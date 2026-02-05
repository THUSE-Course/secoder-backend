use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Redirect},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hex::ToHex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{Level, event};
use url::Url;
use uuid::Uuid;

use super::*;
use crate::{db::get_user, security::hash_password};

fn bad_request(msg: &str) -> AppError {
    AppError::adhoc(StatusCode::BAD_REQUEST, anyhow::anyhow!(msg.to_string()))
}

fn unauthorized(msg: &str) -> AppError {
    AppError::adhoc(StatusCode::UNAUTHORIZED, anyhow::anyhow!(msg.to_string()))
}

fn not_found(msg: &str) -> AppError {
    AppError::adhoc(StatusCode::NOT_FOUND, anyhow::anyhow!(msg.to_string()))
}

fn internal(msg: &str) -> AppError {
    AppError::adhoc(
        StatusCode::INTERNAL_SERVER_ERROR,
        anyhow::anyhow!(msg.to_string()),
    )
}

#[derive(Clone)]
pub(super) struct OAuthClaims {
    user_id: String,
}

#[derive(Deserialize)]
pub(super) struct OAuthAuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct OAuthAuthorizeForm {
    txn: String,
    id: String,
    password: String,
}

#[derive(Deserialize)]
pub(super) struct OAuthTokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: String,
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

fn now_timestamp() -> Result<u64, AppError> {
    Ok(jsonwebtoken::get_current_timestamp())
}

fn extract_bearer(headers: &HeaderMap) -> Result<String, AppError> {
    if let Some(Ok(Some((_, token)))) = headers
        .get(axum::http::header::AUTHORIZATION)
        .map(|v| v.to_str().map(|v| v.split_once(' ')))
    {
        Ok(token.to_string())
    } else {
        Err(unauthorized("authorization required"))
    }
}

fn with_store<T>(
    state: &AppState,
    f: impl FnOnce(&mut OAuthStore) -> Result<T, AppError>,
) -> Result<T, AppError> {
    let mut store = match state.oauth_store.lock() {
        Ok(store) => store,
        Err(_) => return Err(internal("oauth store lock poisoned")),
    };
    f(&mut store)
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
        .map_err(|_| bad_request("invalid redirect_uri"))?;
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

fn require_basic(
    headers: &HeaderMap,
    payload: &OAuthTokenRequest,
) -> Result<(String, String), AppError> {
    let basic = parse_basic_client(headers);
    let client_id = payload
        .client_id
        .clone()
        .or_else(|| basic.as_ref().map(|pair| pair.0.clone()))
        .ok_or_else(|| bad_request("missing client_id"))?;
    let client_secret = payload
        .client_secret
        .clone()
        .or_else(|| basic.as_ref().map(|pair| pair.1.clone()))
        .ok_or_else(|| bad_request("missing client_secret"))?;
    Ok((client_id, client_secret))
}

pub(super) async fn oauth_middleware(
    State(state): State<AppState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Result<axum::response::Response, AppError> {
    let token = extract_bearer(req.headers())?;
    let now = now_timestamp()?;
    let user_id = with_store(&state, |store| {
        store.prune(now);
        let entry = store
            .tokens
            .get(&token)
            .ok_or_else(|| unauthorized("invalid or expired token"))?;
        if entry.expires_at <= now {
            return Err(unauthorized("token expired"));
        }
        Ok(entry.user_id.clone())
    })?;
    req.extensions_mut().insert(OAuthClaims { user_id });
    Ok(next.run(req).await)
}

pub(super) async fn oauth_authorize_get(
    State(state): State<AppState>,
    Query(query): Query<OAuthAuthorizeQuery>,
) -> Result<Redirect, AppError> {
    let config = oauth_config(&state)?;
    let response_type = query.response_type;
    let client_id = query.client_id;
    let redirect_uri = query.redirect_uri;
    if response_type != "code" {
        return Err(bad_request("unsupported response_type"));
    }
    if client_id != config.client_id {
        return Err(bad_request("invalid client_id"));
    }
    if config.redirect_uri != redirect_uri {
        return Err(bad_request("invalid redirect_uri"));
    }

    let frontend = Url::parse(&state.config.frontend)
        .map_err(|_| bad_request("invalid frontend url"))?;
    let txn = build_txn_id(query.state.as_deref(), &redirect_uri, &client_id);
    let now = now_timestamp()?;
    with_store(&state, |store| {
        store.prune(now);
        let before = store.txns.len();
        let existed = store.txns.contains_key(&txn);
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
        let after = store.txns.len();
        event!(
            Level::INFO,
            action = "insert_txn",
            txn = %txn,
            existed,
            before,
            after,
            expires_at = now + config.code_ttl_secs,
            "oauth txn updated"
        );
        Ok(())
    })?;

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
    let txn = form.txn;
    let id = form.id;
    let password = form.password;

    let now = now_timestamp()?;
    let (client_id, redirect_uri, scope, _txn_state) =
        with_store(&state, |store| {
            store.prune(now);
            let entry = store
                .txns
                .get_mut(&txn)
                .ok_or_else(|| unauthorized("invalid or expired txn"))?;
            if entry.expires_at <= now {
                return Err(unauthorized("txn expired"));
            }
            if entry.response_type != "code" {
                return Err(bad_request("unsupported response_type"));
            }
            if entry.client_id != config.client_id {
                return Err(bad_request("invalid client_id"));
            }
            if entry.redirect_uri != config.redirect_uri {
                return Err(bad_request("invalid redirect_uri"));
            }
            Ok((
                entry.client_id.clone(),
                entry.redirect_uri.clone(),
                entry.scope.clone(),
                entry.state.clone(),
            ))
        })?;

    let db = &state.db;
    let user = get_user(db, &id)
        .await?
        .ok_or_else(|| unauthorized("invalid credentials"))?;
    let hash = hash_password(&user.password_salt, &password);
    if user.password_hash != hash {
        return Err(unauthorized("invalid credentials"));
    }

    let now = now_timestamp()?;
    let code = Uuid::new_v4().to_string();
    with_store(&state, |store| {
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
        let had_code = store.txns.get(&txn).and_then(|entry| entry.code.as_ref()).is_some();
        if let Some(entry) = store.txns.get_mut(&txn) {
            entry.code = Some(code.clone());
            event!(
                Level::INFO,
                action = "set_txn_code",
                txn = %txn,
                had_code,
                "oauth txn updated"
            );
        } else {
            event!(
                Level::INFO,
                action = "set_txn_code_missing",
                txn = %txn,
                "oauth txn missing while setting code"
            );
        }
        Ok(())
    })?;

    Ok(Redirect::to(&format!("/txn/{}", txn)).into_response())
}

pub(super) async fn oauth_txn(
    State(state): State<AppState>,
    Path(txn): Path<String>,
) -> Result<axum::response::Response, AppError> {
    let now = now_timestamp()?;
    let (redirect_uri, code, txn_state) = with_store(&state, |store| {
        store.prune(now);
        let before = store.txns.len();
        let entry = match store.txns.remove(&txn) {
            Some(entry) => {
                let after = store.txns.len();
                event!(
                    Level::INFO,
                    action = "remove_txn",
                    txn = %txn,
                    before,
                    after,
                    expires_at = entry.expires_at,
                    has_code = entry.code.is_some(),
                    "oauth txn updated"
                );
                entry
            }
            None => {
                event!(
                    Level::INFO,
                    action = "remove_txn_missing",
                    txn = %txn,
                    before,
                    "oauth txn missing on remove"
                );
                return Err(unauthorized("invalid or expired txn"));
            }
        };
        if entry.expires_at <= now {
            return Err(unauthorized("txn expired"));
        }
        let code = entry
            .code
            .ok_or_else(|| unauthorized("txn not authorized"))?;
        Ok((entry.redirect_uri, code, entry.state))
    })?;

    let redirect = build_redirect(&redirect_uri, &code, txn_state.as_deref())?;
    Ok(Redirect::to(redirect.as_str()).into_response())
}

pub(super) async fn oauth_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<OAuthTokenRequest>,
) -> Result<Json<OAuthTokenResponse>, AppError> {
    let config = oauth_config(&state)?;
    let grant_type = payload.grant_type.clone();
    let code = payload.code.clone();
    let redirect_uri = payload.redirect_uri.clone();
    let (client_id, client_secret) = require_basic(&headers, &payload)?;

    if grant_type != "authorization_code" {
        return Err(bad_request("unsupported grant_type"));
    }
    if client_id != config.client_id {
        return Err(bad_request("invalid client_id"));
    }
    if client_secret != config.client_secret {
        return Err(bad_request("invalid client_secret"));
    }

    let now = now_timestamp()?;
    let (user_id, scope) = with_store(&state, |store| {
        store.prune(now);
        let entry = store
            .codes
            .remove(&code)
            .ok_or_else(|| unauthorized("invalid or expired code"))?;
        if entry.expires_at <= now {
            return Err(unauthorized("code expired"));
        }
        if entry.redirect_uri != redirect_uri {
            return Err(bad_request("redirect_uri mismatch"));
        }
        if entry.client_id != client_id {
            return Err(bad_request("invalid client_id"));
        }
        Ok((entry.user_id, entry.scope))
    })?;

    let access_token = Uuid::new_v4().to_string();
    let expires_in = config.token_ttl_secs;
    with_store(&state, |store| {
        store.prune(now);
        store.tokens.insert(
            access_token.clone(),
            AccessToken {
                user_id,
                expires_at: now + expires_in,
            },
        );
        Ok(())
    })?;

    Ok(Json(OAuthTokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in,
        scope,
    }))
}

pub(super) async fn oauth_userinfo(
    State(state): State<AppState>,
    Extension(claims): Extension<OAuthClaims>,
) -> Result<Json<OAuthUserInfoResponse>, AppError> {
    let _config = oauth_config(&state)?;
    let user_id = claims.user_id;

    let db = &state.db;
    let user = get_user(db, &user_id)
        .await?
        .ok_or_else(|| not_found("user not found"))?;

    Ok(Json(OAuthUserInfoResponse {
        sub: user.id,
        email: user.email,
        name: user.name,
    }))
}
