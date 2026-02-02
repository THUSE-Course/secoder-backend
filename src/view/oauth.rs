use super::*;
use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
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
    student_id: Option<String>,
    password: Option<String>,
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
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
    if !state.config.oauth.enabled {
        return Err(AppError::bad_request("oauth not enabled"));
    }
    Ok(&state.config.oauth)
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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

fn login_form_html(
    client_id: &str,
    redirect_uri: &str,
    response_type: &str,
    scope: Option<&str>,
    state: Option<&str>,
    msg: Option<&str>,
) -> Html<String> {
    let scope = match scope {
        Some(scope) => format!(
            r#"<input type=\"hidden\" name=\"scope\" value=\"{}\">"#,
            escape_html(scope)
        ),
        None => String::new(),
    };
    let state = match state {
        Some(state) => format!(
            r#"<input type=\"hidden\" name=\"state\" value=\"{}\">"#,
            escape_html(state)
        ),
        None => String::new(),
    };
    let msg = match msg {
        Some(msg) => {
            format!(r#"<p style=\"color:#b00020;\">{}</p>"#, escape_html(msg))
        }
        None => String::new(),
    };
    Html(format!(
        r#"<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>Authorize GitLab</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; }}
    form {{ max-width: 420px; }}
    label {{ display: block; margin-top: 1rem; }}
    input {{ width: 100%; padding: 0.5rem; margin-top: 0.25rem; }}
    button {{ margin-top: 1rem; padding: 0.6rem 1rem; }}
  </style>
</head>
<body>
  <h1>Sign in to authorize GitLab</h1>
  {msg}
  <form method=\"post\" action=\"/oauth/authorize\">
    <input type=\"hidden\" name=\"client_id\" value=\"{client_id}\">
    <input type=\"hidden\" name=\"redirect_uri\" value=\"{redirect_uri}\">
    <input type=\"hidden\" name=\"response_type\" value=\"{response_type}\">
    {scope}
    {state}
    <label for=\"student_id\">Student ID</label>
    <input type=\"text\" name=\"student_id\" required>
    <label for=\"password\">Password</label>
    <input type=\"password\" name=\"password\" required>
    <button type=\"submit\">Authorize</button>
  </form>
</body>
</html>"#,
        client_id = escape_html(client_id),
        redirect_uri = escape_html(redirect_uri),
        response_type = escape_html(response_type),
        scope = scope,
        state = state,
        msg = msg,
    ))
}

pub(super) async fn oauth_authorize_get(
    State(state): State<AppState>,
    Query(query): Query<OAuthAuthorizeQuery>,
) -> Result<Html<String>, AppError> {
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
    if !config.redirect_uris.iter().any(|uri| uri == &redirect_uri) {
        return Err(AppError::bad_request("invalid redirect_uri"));
    }
    Ok(login_form_html(
        &client_id,
        &redirect_uri,
        &response_type,
        query.scope.as_deref(),
        query.state.as_deref(),
        None,
    ))
}

pub(super) async fn oauth_authorize_post(
    State(state): State<AppState>,
    axum::extract::Form(form): axum::extract::Form<OAuthAuthorizeForm>,
) -> Result<axum::response::Response, AppError> {
    let config = oauth_config(&state)?;
    let response_type = form
        .response_type
        .ok_or_else(|| AppError::bad_request("missing response_type"))?;
    let client_id = form
        .client_id
        .ok_or_else(|| AppError::bad_request("missing client_id"))?;
    let redirect_uri = form
        .redirect_uri
        .ok_or_else(|| AppError::bad_request("missing redirect_uri"))?;
    let student_id = form
        .student_id
        .ok_or_else(|| AppError::bad_request("missing student_id"))?;
    let password = form
        .password
        .ok_or_else(|| AppError::bad_request("missing password"))?;

    if response_type != "code" {
        return Err(AppError::bad_request("unsupported response_type"));
    }
    if client_id != config.client_id {
        return Err(AppError::bad_request("invalid client_id"));
    }
    if !config.redirect_uris.iter().any(|uri| uri == &redirect_uri) {
        return Err(AppError::bad_request("invalid redirect_uri"));
    }

    let db = &state.db;
    let user = get_user(db, &student_id)
        .await?
        .ok_or_else(|| AppError::unauthorized("invalid credentials"))?;
    let hash = hash_password(&user.password_salt, &password);
    if user.password_hash != hash {
        return Ok(login_form_html(
            &client_id,
            &redirect_uri,
            &response_type,
            form.scope.as_deref(),
            form.state.as_deref(),
            Some("invalid credentials"),
        )
        .into_response());
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
                user_id: student_id.clone(),
                client_id: client_id.clone(),
                redirect_uri: redirect_uri.clone(),
                scope: form.scope.clone(),
                expires_at: now + config.code_ttl_secs,
            },
        );
    }

    let redirect = build_redirect(&redirect_uri, &code, form.state.as_deref())?;
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
        sub: user.student_id,
        email: user.email,
        name: user.name,
    }))
}
