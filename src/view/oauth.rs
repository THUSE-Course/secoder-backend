use super::*;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hex::ToHex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use crate::db::get_user;
use crate::security::hash_password;

#[derive(Deserialize)]
pub(super) struct OAuthAuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct OAuthAuthorizeForm {
    txn: Option<String>,
    id: Option<String>,
    password: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct OAuthTokenRequest {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

#[derive(Serialize)]
pub(super) struct OAuthTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    scope: Option<String>,
}

#[derive(Serialize)]
pub(super) struct OAuthUserInfoResponse {
    sub: String,
    email: String,
    name: String,
}

fn oauth_config(
    state: &AppState,
) -> Result<&crate::config::OAuthProviderConfig, AppError> {
    Ok(&state.config.oauth)
}

fn build_redirect(
    redirect_uri: &str,
    code: &str,
    state: Option<&str>,
) -> Result<Url, AppError> {
    let mut url = Url::parse(redirect_uri)
        .map_err(|_| AppError::bad_request("invalid redirect_uri"))?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("code", code);
        if let Some(state) = state {
            pairs.append_pair("state", state);
        }
    }
    Ok(url)
}

fn parse_basic_client(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?;
    let value = value.to_str().ok()?;
    let (scheme, encoded) = value.split_once(' ')?;
    if scheme != "Basic" {
        return None;
    }
    let decoded = STANDARD.decode(encoded).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let mut parts = decoded.splitn(2, ':');
    let client_id = parts.next()?.to_string();
    let client_secret = parts.next()?.to_string();
    Some((client_id, client_secret))
}

fn build_txn_id(
    state: Option<&str>,
    redirect_uri: &str,
    client_id: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(state.unwrap_or_default().as_bytes());
    hasher.update(b"|");
    hasher.update(redirect_uri.as_bytes());
    hasher.update(b"|");
    hasher.update(client_id.as_bytes());
    hasher.finalize().encode_hex()
}

pub(super) async fn oauth_authorize_get(
    State(state): State<AppState>,
    Query(query): Query<OAuthAuthorizeQuery>,
) -> Result<Redirect, AppError> {
    let config = oauth_config(&state)?;
    let response_type = query
        .response_type
        .ok_or_else(|| AppError::bad_request("missing response_type"))?;
    let client_id = query
        .client_id
        .ok_or_else(|| AppError::bad_request("missing client_id"))?;
    let redirect_uri = query
        .redirect_uri
        .ok_or_else(|| AppError::bad_request("missing redirect_uri"))?;
    if response_type != "code" {
        return Err(AppError::bad_request("unsupported response_type"));
    }
    if client_id != config.client_id {
        return Err(AppError::bad_request("invalid client_id"));
    }
    if config.redirect_uri != redirect_uri {
        return Err(AppError::bad_request("invalid redirect_uri"));
    }

    let frontend = Url::parse(&state.config.frontend)
        .map_err(|_| AppError::bad_request("invalid frontend url"))?;
    let txn = build_txn_id(query.state.as_deref(), &redirect_uri, &client_id);
    let now = now_timestamp()?;
    {
        let mut store = match state.oauth_store.lock() {
            Ok(store) => store,
            Err(_) => {
                return Err(AppError::internal("oauth store lock poisoned"));
            }
        };
        store.prune(now);
        store.txns.insert(
            txn.clone(),
            OAuthTxn {
                client_id,
                redirect_uri,
                scope: query.scope.clone(),
                state: query.state.clone(),
                response_type,
                code: None,
                expires_at: now + config.code_ttl_secs,
            },
        );
    }

    let mut redirect = frontend;
    {
        let mut pairs = redirect.query_pairs_mut();
        pairs.append_pair("txn", &txn);
    }
    Ok(Redirect::to(redirect.as_str()))
}

pub(super) async fn oauth_authorize_post(
    State(state): State<AppState>,
    axum::extract::Form(form): axum::extract::Form<OAuthAuthorizeForm>,
) -> Result<axum::response::Response, AppError> {
    let config = oauth_config(&state)?;
    let txn = form
        .txn
        .ok_or_else(|| AppError::bad_request("missing txn"))?;
    let id = form.id.ok_or_else(|| AppError::bad_request("missing id"))?;
    let password = form
        .password
        .ok_or_else(|| AppError::bad_request("missing password"))?;

    let (client_id, redirect_uri, scope, _txn_state) = {
        let mut store = match state.oauth_store.lock() {
            Ok(store) => store,
            Err(_) => {
                return Err(AppError::internal("oauth store lock poisoned"));
            }
        };
        let now = now_timestamp()?;
        store.prune(now);
        let entry = store
            .txns
            .get_mut(&txn)
            .ok_or_else(|| AppError::unauthorized("invalid or expired txn"))?;
        if entry.expires_at <= now {
            return Err(AppError::unauthorized("txn expired"));
        }
        if entry.response_type != "code" {
            return Err(AppError::bad_request("unsupported response_type"));
        }
        if entry.client_id != config.client_id {
            return Err(AppError::bad_request("invalid client_id"));
        }
        if entry.redirect_uri != config.redirect_uri {
            return Err(AppError::bad_request("invalid redirect_uri"));
        }
        (
            entry.client_id.clone(),
            entry.redirect_uri.clone(),
            entry.scope.clone(),
            entry.state.clone(),
        )
    };

    let db = &state.db;
    let user = get_user(db, &id)
        .await?
        .ok_or_else(|| AppError::unauthorized("invalid credentials"))?;
    let hash = hash_password(&user.password_salt, &password);
    if user.password_hash != hash {
        return Err(AppError::unauthorized("invalid credentials"));
    }

    let now = now_timestamp()?;
    let code = Uuid::new_v4().to_string();
    {
        let mut store = match state.oauth_store.lock() {
            Ok(store) => store,
            Err(_) => {
                return Err(AppError::internal("oauth store lock poisoned"));
            }
        };
        store.prune(now);
        store.codes.insert(
            code.clone(),
            AuthCode {
                user_id: id.clone(),
                client_id: client_id.clone(),
                redirect_uri: redirect_uri.clone(),
                scope: scope.clone(),
                expires_at: now + config.code_ttl_secs,
            },
        );
        if let Some(entry) = store.txns.get_mut(&txn) {
            entry.code = Some(code.clone());
        }
    }

    Ok(Redirect::to(&format!("/txn/{}", txn)).into_response())
}

pub(super) async fn oauth_txn(
    State(state): State<AppState>,
    Path(txn): Path<String>,
) -> Result<axum::response::Response, AppError> {
    let now = now_timestamp()?;
    let (redirect_uri, code, txn_state) = {
        let mut store = match state.oauth_store.lock() {
            Ok(store) => store,
            Err(_) => {
                return Err(AppError::internal("oauth store lock poisoned"));
            }
        };
        store.prune(now);
        let entry = store
            .txns
            .remove(&txn)
            .ok_or_else(|| AppError::unauthorized("invalid or expired txn"))?;
        if entry.expires_at <= now {
            return Err(AppError::unauthorized("txn expired"));
        }
        let code = entry
            .code
            .ok_or_else(|| AppError::unauthorized("txn not authorized"))?;
        (entry.redirect_uri, code, entry.state)
    };

    let redirect = build_redirect(&redirect_uri, &code, txn_state.as_deref())?;
    Ok(Redirect::to(redirect.as_str()).into_response())
}

pub(super) async fn oauth_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<OAuthTokenRequest>,
) -> Result<Json<OAuthTokenResponse>, AppError> {
    let config = oauth_config(&state)?;
    let basic = parse_basic_client(&headers);

    let grant_type = payload
        .grant_type
        .ok_or_else(|| AppError::bad_request("missing grant_type"))?;
    let code = payload
        .code
        .ok_or_else(|| AppError::bad_request("missing code"))?;
    let redirect_uri = payload
        .redirect_uri
        .ok_or_else(|| AppError::bad_request("missing redirect_uri"))?;
    let client_id = payload
        .client_id
        .or_else(|| basic.as_ref().map(|pair| pair.0.clone()))
        .ok_or_else(|| AppError::bad_request("missing client_id"))?;
    let client_secret = payload
        .client_secret
        .or_else(|| basic.as_ref().map(|pair| pair.1.clone()))
        .ok_or_else(|| AppError::bad_request("missing client_secret"))?;

    if grant_type != "authorization_code" {
        return Err(AppError::bad_request("unsupported grant_type"));
    }
    if client_id != config.client_id {
        return Err(AppError::bad_request("invalid client_id"));
    }
    if client_secret != config.client_secret {
        return Err(AppError::bad_request("invalid client_secret"));
    }

    let now = now_timestamp()?;
    let (user_id, scope) = {
        let mut store = match state.oauth_store.lock() {
            Ok(store) => store,
            Err(_) => {
                return Err(AppError::internal("oauth store lock poisoned"));
            }
        };
        store.prune(now);
        let entry = store
            .codes
            .remove(&code)
            .ok_or_else(|| AppError::unauthorized("invalid or expired code"))?;
        if entry.expires_at <= now {
            return Err(AppError::unauthorized("code expired"));
        }
        if entry.redirect_uri != redirect_uri {
            return Err(AppError::bad_request("redirect_uri mismatch"));
        }
        if entry.client_id != client_id {
            return Err(AppError::bad_request("invalid client_id"));
        }
        (entry.user_id, entry.scope)
    };

    let access_token = Uuid::new_v4().to_string();
    let expires_in = config.token_ttl_secs;
    {
        let mut store = match state.oauth_store.lock() {
            Ok(store) => store,
            Err(_) => {
                return Err(AppError::internal("oauth store lock poisoned"));
            }
        };
        store.prune(now);
        store.tokens.insert(
            access_token.clone(),
            AccessToken {
                user_id,
                expires_at: now + expires_in,
            },
        );
    }

    Ok(Json(OAuthTokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        scope,
    }))
}

pub(super) async fn oauth_userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<OAuthUserInfoResponse>, AppError> {
    let _config = oauth_config(&state)?;
    let token = extract_bearer(&headers)?;
    let now = now_timestamp()?;
    let user_id = {
        let mut store = match state.oauth_store.lock() {
            Ok(store) => store,
            Err(_) => {
                return Err(AppError::internal("oauth store lock poisoned"));
            }
        };
        store.prune(now);
        let entry = store.tokens.get(&token).ok_or_else(|| {
            AppError::unauthorized("invalid or expired token")
        })?;
        if entry.expires_at <= now {
            return Err(AppError::unauthorized("token expired"));
        }
        entry.user_id.clone()
    };

    let db = &state.db;
    let user = get_user(db, &user_id)
        .await?
        .ok_or_else(|| AppError::not_found("user not found"))?;

    Ok(Json(OAuthUserInfoResponse {
        sub: user.id,
        email: user.email,
        name: user.name,
    }))
}
