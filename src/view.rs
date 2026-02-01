use crate::config::Config;
use crate::db::{get_user, group_members};
use crate::error::AppError;
use crate::kubernetes::{group_acl, group_ns, user_ns};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jsonwebtoken::{
    DecodingKey, EncodingKey, Header, Validation, decode, encode,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower_http::cors::CorsLayer;
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Connection>>,
    pub config: Config,
    pub(crate) oauth_store: Arc<Mutex<OAuthStore>>,
}

#[derive(Default)]
pub(crate) struct OAuthStore {
    codes: HashMap<String, AuthCode>,
    tokens: HashMap<String, AccessToken>,
}

struct AuthCode {
    user_id: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    expires_at: u64,
}

struct AccessToken {
    user_id: String,
    expires_at: u64,
}

impl OAuthStore {
    fn prune(&mut self, now: u64) {
        self.codes.retain(|_, code| code.expires_at > now);
        self.tokens.retain(|_, token| token.expires_at > now);
    }
}

pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/register", post(register))
        .route("/login", post(login))
        .route(
            "/oauth/authorize",
            get(oauth_authorize_get).post(oauth_authorize_post),
        )
        .route("/oauth/token", post(oauth_token))
        .route("/oauth/userinfo", get(oauth_userinfo))
        .route("/user", get(get_user_info))
        .route("/recover_password", post(recover_password))
        .route("/recover_password/confirm", post(recover_password_confirm))
        .route("/admin/group_assign", post(admin_group_assign))
        .route("/group/join", post(join_group))
        .route("/group/join/accept", post(accept_join_request))
        .route("/group/join/reject", post(reject_join_request))
        .route("/group/invite", post(invite_user))
        .route("/group/invite/accept", post(accept_invitation))
        .route("/group/invite/reject", post(reject_invitation))
        .route("/group/create", post(create_group))
        .route("/users", get(list_users))
        .route("/groups", get(list_groups))
        .route("/debug/users", get(debug_users))
        .with_state(state)
        .layer(CorsLayer::permissive())
}

#[derive(Serialize)]
struct GroupResponse {
    name: String,
    code_name: String,
    leader: String,
    members: Vec<String>,
}

#[derive(Serialize)]
struct GroupSummaryResponse {
    name: String,
    code_name: String,
    leader: LeaderSummary,
    members: Vec<MemberSummary>,
}

#[derive(Serialize)]
struct LeaderSummary {
    student_id: String,
    name: String,
}

#[derive(Serialize)]
struct MemberSummary {
    student_id: String,
    name: String,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    student_id: String,
    exp: usize,
}

#[derive(Deserialize)]
struct OAuthAuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
}

#[derive(Deserialize)]
struct OAuthAuthorizeForm {
    student_id: Option<String>,
    password: Option<String>,
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
}

#[derive(Deserialize)]
struct OAuthTokenRequest {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

#[derive(Serialize)]
struct OAuthTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    scope: Option<String>,
}

#[derive(Serialize)]
struct OAuthUserInfoResponse {
    sub: String,
    email: String,
    name: String,
}

fn with_conn<T>(
    state: &AppState,
    f: impl FnOnce(&Connection) -> Result<T, AppError>,
) -> Result<T, AppError> {
    let conn = match state.db.lock() {
        Ok(conn) => conn,
        Err(_) => return Err(AppError::internal("database lock poisoned")),
    };
    f(&conn)
}

fn extract_bearer(headers: &HeaderMap) -> Result<String, AppError> {
    let value = match headers.get(axum::http::header::AUTHORIZATION) {
        Some(value) => value,
        None => return Err(AppError::unauthorized("authorization required")),
    };
    let value = match value.to_str() {
        Ok(value) => value,
        Err(_) => return Err(AppError::unauthorized("authorization required")),
    };
    let mut parts = value.splitn(2, ' ');
    match (parts.next(), parts.next()) {
        (Some("Bearer"), Some(token)) => Ok(token.to_string()),
        _ => Err(AppError::unauthorized("authorization required")),
    }
}

fn verify_token(token: &str, secret: &str) -> Result<String, AppError> {
    let validation = Validation::default();
    let token_data = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    ) {
        Ok(data) => data,
        Err(_) => return Err(AppError::unauthorized("invalid token")),
    };
    Ok(token_data.claims.student_id)
}

fn generate_token(student_id: &str, secret: &str) -> Result<String, AppError> {
    let exp = SystemTime::now()
        .checked_add(Duration::from_secs(24 * 60 * 60))
        .ok_or_else(|| AppError::internal("failed to build token"))?
        .duration_since(UNIX_EPOCH)?
        .as_secs() as usize;
    let claims = Claims {
        student_id: student_id.to_string(),
        exp,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;
    Ok(token)
}

fn oauth_config(
    state: &AppState,
) -> Result<&crate::config::OAuthProviderConfig, AppError> {
    if !state.config.oauth.enabled {
        return Err(AppError::not_found("oauth provider is disabled"));
    }
    if state.config.oauth.client_id.trim().is_empty()
        || state.config.oauth.client_secret.trim().is_empty()
        || state.config.oauth.redirect_uris.is_empty()
    {
        return Err(AppError::internal("oauth provider misconfigured"));
    }
    Ok(&state.config.oauth)
}

fn now_timestamp() -> Result<u64, AppError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn build_redirect(
    redirect_uri: &str,
    code: &str,
    state: Option<&str>,
) -> Result<String, AppError> {
    let mut url = Url::parse(redirect_uri)
        .map_err(|_| AppError::bad_request("invalid redirect_uri"))?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("code", code);
        if let Some(state) = state {
            pairs.append_pair("state", state);
        }
    }
    Ok(url.to_string())
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
    let mut split = decoded.splitn(2, ':');
    Some((split.next()?.to_string(), split.next()?.to_string()))
}

fn login_form_html(
    client_id: &str,
    redirect_uri: &str,
    response_type: &str,
    scope: Option<&str>,
    state: Option<&str>,
    error: Option<&str>,
) -> Html<String> {
    let mut extra = String::new();
    if let Some(scope) = scope {
        extra.push_str(&format!(
            r#"<input type="hidden" name="scope" value="{}">"#,
            escape_html(scope)
        ));
    }
    if let Some(state) = state {
        extra.push_str(&format!(
            r#"<input type="hidden" name="state" value="{}">"#,
            escape_html(state)
        ));
    }
    let error_html = error
        .map(|msg| {
            format!(r#"<p style="color:#b00020;">{}</p>"#, escape_html(msg))
        })
        .unwrap_or_default();

    Html(format!(
        r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Authorize GitLab</title>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; }}
    form {{ max-width: 420px; }}
    label {{ display: block; margin: 0.75rem 0 0.25rem; }}
    input {{ width: 100%; padding: 0.5rem; }}
    button {{ margin-top: 1rem; padding: 0.6rem 1rem; }}
  </style>
</head>
<body>
  <h1>Sign in to authorize GitLab</h1>
  {error_html}
  <form method="post" action="/oauth/authorize">
    <input type="hidden" name="client_id" value="{client_id}">
    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
    <input type="hidden" name="response_type" value="{response_type}">
    {extra}
    <label for="student_id">Student ID</label>
    <input id="student_id" name="student_id" autocomplete="username" required>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Authorize</button>
  </form>
</body>
</html>"#,
        client_id = escape_html(client_id),
        redirect_uri = escape_html(redirect_uri),
        response_type = escape_html(response_type),
        extra = extra,
        error_html = error_html,
    ))
}

async fn health_check() -> Json<serde_json::Value> {
    Json(json!({"status": "ok", "message": "backend is running"}))
}

#[derive(Deserialize)]
struct RegisterRequest {
    student_id: Option<String>,
    email: Option<String>,
    name: Option<String>,
}

async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let student_id = payload.student_id.ok_or_else(|| {
        AppError::bad_request("missing required field: student_id")
    })?;
    let email = payload.email.ok_or_else(|| {
        AppError::bad_request("missing required field: email")
    })?;
    let name = payload
        .name
        .unwrap_or_else(|| format!("user {}", student_id));

    with_conn(&state, |conn| {
        let existing = get_user(conn, &student_id)?;
        if existing.is_some() {
            return Err(AppError::bad_request("user already exists"));
        }
        Ok(())
    })?;

    user_ns(&state.config.kubernetes, &student_id).await?;

    let password = student_id.clone();
    with_conn(&state, |conn| {
        conn.execute(
            "INSERT INTO users (student_id, name, email, password_hash, group_code_name) \
             VALUES (?, ?, ?, ?, NULL)",
            params![student_id, name, email, password],
        )?;
        Ok(())
    })?;

    Ok(Json(
        json!({"msg": "registration successful", "ver": "1.0"}),
    ))
}

#[derive(Deserialize)]
struct LoginRequest {
    student_id: Option<String>,
    password: Option<String>,
}

async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let student_id = payload.student_id.ok_or_else(|| {
        AppError::bad_request("missing student_id or password")
    })?;
    let password = payload.password.ok_or_else(|| {
        AppError::bad_request("missing student_id or password")
    })?;

    let user = with_conn(&state, |conn| get_user(conn, &student_id))?
        .ok_or_else(|| AppError::unauthorized("invalid credentials"))?;
    if user.password_hash != password {
        return Err(AppError::unauthorized("invalid credentials"));
    }
    let token = generate_token(&student_id, &state.config.jwt_secret)?;
    Ok(Json(json!({"token": token, "msg": "login successful"})))
}

async fn oauth_authorize_get(
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

async fn oauth_authorize_post(
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

    let user = with_conn(&state, |conn| get_user(conn, &student_id))?
        .ok_or_else(|| AppError::unauthorized("invalid credentials"))?;
    if user.password_hash != password {
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
                user_id: student_id,
                client_id: client_id.clone(),
                redirect_uri: redirect_uri.clone(),
                scope: form.scope.clone(),
                expires_at: now + config.code_ttl_secs,
            },
        );
    }
    let redirect = build_redirect(&redirect_uri, &code, form.state.as_deref())?;
    Ok(Redirect::to(&redirect).into_response())
}

async fn oauth_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Form(payload): axum::extract::Form<OAuthTokenRequest>,
) -> Result<Json<OAuthTokenResponse>, AppError> {
    let config = oauth_config(&state)?;
    let basic = parse_basic_client(&headers);
    let client_id = payload
        .client_id
        .or_else(|| basic.as_ref().map(|(id, _)| id.clone()))
        .ok_or_else(|| AppError::bad_request("missing client_id"))?;
    let client_secret = payload
        .client_secret
        .or_else(|| basic.as_ref().map(|(_, secret)| secret.clone()))
        .ok_or_else(|| AppError::bad_request("missing client_secret"))?;
    let grant_type = payload
        .grant_type
        .ok_or_else(|| AppError::bad_request("missing grant_type"))?;
    let code = payload
        .code
        .ok_or_else(|| AppError::bad_request("missing code"))?;
    let redirect_uri = payload
        .redirect_uri
        .ok_or_else(|| AppError::bad_request("missing redirect_uri"))?;

    if grant_type != "authorization_code" {
        return Err(AppError::bad_request("unsupported grant_type"));
    }
    if client_id != config.client_id || client_secret != config.client_secret {
        return Err(AppError::unauthorized("invalid client credentials"));
    }
    if !config.redirect_uris.iter().any(|uri| uri == &redirect_uri) {
        return Err(AppError::bad_request("invalid redirect_uri"));
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
        if entry.redirect_uri != redirect_uri || entry.client_id != client_id {
            return Err(AppError::unauthorized("invalid authorization code"));
        }
        if entry.expires_at <= now {
            return Err(AppError::unauthorized("authorization code expired"));
        }
        (entry.user_id, entry.scope)
    };

    let access_token = Uuid::new_v4().to_string();
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
                expires_at: now + config.token_ttl_secs,
            },
        );
    }

    Ok(Json(OAuthTokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: config.token_ttl_secs,
        scope,
    }))
}

async fn oauth_userinfo(
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

    let user = with_conn(&state, |conn| get_user(conn, &user_id))?
        .ok_or_else(|| AppError::not_found("user not found"))?;

    Ok(Json(OAuthUserInfoResponse {
        sub: user.student_id,
        email: user.email,
        name: user.name,
    }))
}

async fn get_user_info(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let token = extract_bearer(&headers)?;
    let student_id = verify_token(&token, &state.config.jwt_secret)?;
    let user = with_conn(&state, |conn| get_user(conn, &student_id))?
        .ok_or_else(|| AppError::not_found("user not found"))?;

    Ok(Json(json!({
        "student_id": user.student_id,
        "name": user.name,
        "email": user.email,
        "group": user.group_code_name
    })))
}

#[derive(Deserialize)]
struct RecoverPasswordRequest {
    student_id: Option<String>,
    email: Option<String>,
}

async fn recover_password(
    State(state): State<AppState>,
    Json(payload): Json<RecoverPasswordRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let student_id = payload
        .student_id
        .ok_or_else(|| AppError::bad_request("missing student_id or email"))?;
    let email = payload
        .email
        .ok_or_else(|| AppError::bad_request("missing student_id or email"))?;

    let user = with_conn(&state, |conn| get_user(conn, &student_id))?
        .ok_or_else(|| AppError::not_found("user not found"))?;
    if user.email != email {
        return Err(AppError::bad_request("email does not match"));
    }

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let reset_token = format!("reset_token_for_{}_{}", student_id, timestamp);

    Ok(Json(json!({
        "msg": "reset link sent to email",
        "reset_token": reset_token,
        "ver": "1.0"
    })))
}

#[derive(Deserialize)]
struct RecoverPasswordConfirmRequest {
    token: Option<String>,
    #[serde(rename = "newPassword")]
    new_password: Option<String>,
}

async fn recover_password_confirm(
    State(state): State<AppState>,
    Json(payload): Json<RecoverPasswordConfirmRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let token = payload
        .token
        .ok_or_else(|| AppError::bad_request("missing token or newPassword"))?;
    let new_password = payload
        .new_password
        .ok_or_else(|| AppError::bad_request("missing token or newPassword"))?;

    if !token.starts_with("reset_token_for_") {
        return Err(AppError::bad_request("invalid reset token"));
    }
    let parts: Vec<&str> = token.split('_').collect();
    if parts.len() < 5 {
        return Err(AppError::bad_request("invalid reset token"));
    }
    let student_id = parts[3];

    with_conn(&state, |conn| {
        let user = get_user(conn, student_id)?;
        if user.is_none() {
            return Err(AppError::not_found("user not found"));
        }
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE student_id = ?",
            params![new_password, student_id],
        )?;
        Ok(())
    })?;

    Ok(Json(
        json!({"msg": "password reset successful", "ver": "1.0"}),
    ))
}

#[derive(Deserialize)]
struct GroupAssignRequest {
    group_code_name: Option<String>,
    student_id: Option<String>,
}

async fn admin_group_assign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<GroupAssignRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let token = extract_bearer(&headers)?;
    let _admin_id = verify_token(&token, &state.config.jwt_secret)?;
    let group_code_name = payload.group_code_name.ok_or_else(|| {
        AppError::bad_request(
            "missing required fields: group_code_name, student_id",
        )
    })?;
    let student_id = payload.student_id.ok_or_else(|| {
        AppError::bad_request(
            "missing required fields: group_code_name, student_id",
        )
    })?;

    let group = with_conn(&state, |conn| {
        let group_row = conn
            .query_row(
                "SELECT name, code_name, leader_id FROM groups WHERE code_name = ?",
                params![group_code_name],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let (name, code_name, leader_id) = match group_row {
            Some(row) => row,
            None => return Err(AppError::not_found("group not found")),
        };

        let user = get_user(conn, &student_id)?;
        if user.is_none() {
            return Err(AppError::not_found("user not found"));
        }
        let group_value = user.unwrap().group_code_name;
        if group_value.is_some() {
            return Err(AppError::bad_request("user already in a group"));
        }

        conn.execute(
            "INSERT OR IGNORE INTO group_members (group_code_name, student_id) VALUES (?, ?)",
            params![code_name, student_id],
        )?;
        conn.execute(
            "UPDATE users SET group_code_name = ? WHERE student_id = ?",
            params![code_name, student_id],
        )?;

        let members = group_members(conn, &code_name)?;
        Ok(GroupResponse {
            name,
            code_name,
            leader: leader_id,
            members,
        })
    })?;

    group_acl(&state.config.kubernetes, &group_code_name, &student_id).await?;

    Ok(Json(json!({
        "msg": "user assigned to group successfully",
        "group": group
    })))
}

#[derive(Deserialize)]
struct JoinGroupRequest {
    group_code_name: Option<String>,
}

async fn join_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<JoinGroupRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let token = extract_bearer(&headers)?;
    let student_id = verify_token(&token, &state.config.jwt_secret)?;
    let group_code_name = payload.group_code_name.ok_or_else(|| {
        AppError::bad_request("missing required field: group_code_name")
    })?;

    let join_token = with_conn(&state, |conn| {
        let group_exists = conn
            .query_row(
                "SELECT 1 FROM groups WHERE code_name = ?",
                params![group_code_name],
                |_| Ok(()),
            )
            .optional()?;
        if group_exists.is_none() {
            return Err(AppError::not_found("group not found"));
        }

        let user = get_user(conn, &student_id)?;
        let user = user.ok_or_else(|| AppError::not_found("user not found"))?;
        if user.group_code_name.is_some() {
            return Err(AppError::bad_request("user already in a group"));
        }

        let pending: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM join_requests WHERE requester_id = ? AND typ = 'join'",
                params![student_id],
                |row| row.get(0),
            )?;
        if pending >= 5 {
            return Err(AppError::bad_request(
                "user has too many pending join requests",
            ));
        }

        let token = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO join_requests (token, group_code_name, requester_id, typ) VALUES (?, ?, ?, 'join')",
            params![token, group_code_name, student_id],
        )?;
        Ok(token)
    })?;

    Ok(Json(json!({
        "msg": "join request sent successfully",
        "join_token": join_token
    })))
}

#[derive(Deserialize)]
struct TokenRequest {
    token: Option<String>,
}

async fn accept_join_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let auth_token = extract_bearer(&headers)?;
    let leader_id = verify_token(&auth_token, &state.config.jwt_secret)?;
    let join_token = payload.token.ok_or_else(|| {
        AppError::bad_request("missing required field: token")
    })?;

    let (group, group_code_name, invitee_id) = with_conn(&state, |conn| {
        let join_request = conn
            .query_row(
                "SELECT group_code_name, requester_id, typ FROM join_requests WHERE token = ?",
                params![join_token],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let (group_code_name, requester_id, typ) = match join_request {
            Some(row) => row,
            None => {
                return Err(AppError::bad_request(
                    "invalid join request token",
                ));
            }
        };
        if typ != "join" {
            return Err(AppError::bad_request("invalid join request token"));
        }

        let group_row = conn
            .query_row(
                "SELECT name, code_name, leader_id FROM groups WHERE code_name = ?",
                params![group_code_name],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let (name, code_name, leader) = match group_row {
            Some(row) => row,
            None => return Err(AppError::not_found("group no longer exists")),
        };
        if leader != leader_id {
            return Err(AppError::forbidden(
                "only group leader can accept join requests",
            ));
        }

        let requester = get_user(conn, &requester_id)?;
        let requester = requester
            .ok_or_else(|| AppError::not_found("requester not found"))?;
        if requester.group_code_name.is_some() {
            return Err(AppError::bad_request("requester already in a group"));
        }

        conn.execute(
            "INSERT OR IGNORE INTO group_members (group_code_name, student_id) VALUES (?, ?)",
            params![code_name, requester_id],
        )?;
        conn.execute(
            "UPDATE users SET group_code_name = ? WHERE student_id = ?",
            params![code_name, requester_id],
        )?;
        conn.execute(
            "DELETE FROM join_requests WHERE token = ?",
            params![join_token],
        )?;

        let members = group_members(conn, &code_name)?;
        Ok((
            GroupResponse {
                name,
                code_name: code_name.clone(),
                leader,
                members,
            },
            code_name,
            requester_id,
        ))
    })?;

    group_acl(&state.config.kubernetes, &group_code_name, &invitee_id).await?;

    Ok(Json(json!({
        "msg": "join request accepted successfully",
        "group": group
    })))
}

async fn reject_join_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let auth_token = extract_bearer(&headers)?;
    let leader_id = verify_token(&auth_token, &state.config.jwt_secret)?;
    let join_token = payload.token.ok_or_else(|| {
        AppError::bad_request("missing required field: token")
    })?;

    with_conn(&state, |conn| {
        let join_request = conn
            .query_row(
                "SELECT group_code_name, typ FROM join_requests WHERE token = ?",
                params![join_token],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let (group_code_name, typ) = match join_request {
            Some(row) => row,
            None => {
                return Err(AppError::bad_request(
                    "invalid join request token",
                ));
            }
        };
        if typ != "join" {
            return Err(AppError::bad_request("invalid join request token"));
        }

        let group_leader = conn
            .query_row(
                "SELECT leader_id FROM groups WHERE code_name = ?",
                params![group_code_name],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let group_leader = match group_leader {
            Some(leader) => leader,
            None => return Err(AppError::not_found("group no longer exists")),
        };
        if group_leader != leader_id {
            return Err(AppError::forbidden(
                "only group leader can reject join requests",
            ));
        }

        conn.execute(
            "DELETE FROM join_requests WHERE token = ?",
            params![join_token],
        )?;
        Ok(())
    })?;

    Ok(Json(json!({"msg": "join request rejected successfully"})))
}

#[derive(Deserialize)]
struct InviteRequest {
    group_code_name: Option<String>,
    invitee_student_id: Option<String>,
}

async fn invite_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<InviteRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let auth_token = extract_bearer(&headers)?;
    let student_id = verify_token(&auth_token, &state.config.jwt_secret)?;
    let group_code_name = payload.group_code_name.ok_or_else(|| {
        AppError::bad_request(
            "missing required fields: group_code_name, invitee_student_id",
        )
    })?;
    let invitee_student_id = payload.invitee_student_id.ok_or_else(|| {
        AppError::bad_request(
            "missing required fields: group_code_name, invitee_student_id",
        )
    })?;

    let invitation_token = with_conn(&state, |conn| {
        let group_row = conn
            .query_row(
                "SELECT leader_id FROM groups WHERE code_name = ?",
                params![group_code_name],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let leader = match group_row {
            Some(leader) => leader,
            None => return Err(AppError::not_found("group not found")),
        };
        if leader != student_id {
            return Err(AppError::forbidden(
                "only group leader can invite users",
            ));
        }

        let invitee = get_user(conn, &invitee_student_id)?;
        let invitee =
            invitee.ok_or_else(|| AppError::not_found("invitee not found"))?;
        if invitee.group_code_name.is_some() {
            return Err(AppError::bad_request("invitee already in a group"));
        }

        let pending: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM invitations WHERE invitee_id = ? AND typ = 'invite'",
                params![invitee_student_id],
                |row| row.get(0),
            )?;
        if pending >= 5 {
            return Err(AppError::bad_request(
                "invitee has too many pending invitations",
            ));
        }

        let token = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO invitations (token, group_code_name, inviter_id, invitee_id, typ) \
             VALUES (?, ?, ?, ?, 'invite')",
            params![token, group_code_name, student_id, invitee_student_id],
        )?;
        Ok(token)
    })?;

    Ok(Json(json!({
        "msg": "invitation sent successfully",
        "invitation_token": invitation_token
    })))
}

async fn accept_invitation(
    State(state): State<AppState>,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let token = payload.token.ok_or_else(|| {
        AppError::bad_request("missing required field: token")
    })?;

    let (group, group_code_name, invitee_id) = with_conn(&state, |conn| {
        let invite = conn
            .query_row(
                "SELECT group_code_name, invitee_id, typ FROM invitations WHERE token = ?",
                params![token],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let (group_code_name, invitee_id, typ) = match invite {
            Some(row) => row,
            None => {
                return Err(AppError::bad_request("invalid invitation token"));
            }
        };
        if typ != "invite" {
            return Err(AppError::bad_request("invalid invitation token"));
        }

        let group_row = conn
            .query_row(
                "SELECT name, code_name, leader_id FROM groups WHERE code_name = ?",
                params![group_code_name],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let (name, code_name, leader) = match group_row {
            Some(row) => row,
            None => return Err(AppError::not_found("group no longer exists")),
        };

        let invitee = get_user(conn, &invitee_id)?;
        let invitee =
            invitee.ok_or_else(|| AppError::not_found("user not found"))?;
        if invitee.group_code_name.is_some() {
            return Err(AppError::bad_request("user already in a group"));
        }

        conn.execute(
            "INSERT OR IGNORE INTO group_members (group_code_name, student_id) VALUES (?, ?)",
            params![code_name, invitee_id],
        )?;
        conn.execute(
            "UPDATE users SET group_code_name = ? WHERE student_id = ?",
            params![code_name, invitee_id],
        )?;
        conn.execute(
            "DELETE FROM invitations WHERE token = ?",
            params![token],
        )?;

        let members = group_members(conn, &code_name)?;
        Ok((
            GroupResponse {
                name,
                code_name: code_name.clone(),
                leader,
                members,
            },
            code_name,
            invitee_id,
        ))
    })?;

    group_acl(&state.config.kubernetes, &group_code_name, &invitee_id).await?;

    Ok(Json(json!({
        "msg": "invitation accepted successfully",
        "group": group
    })))
}

async fn reject_invitation(
    State(state): State<AppState>,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let token = payload.token.ok_or_else(|| {
        AppError::bad_request("missing required field: token")
    })?;

    with_conn(&state, |conn| {
        let invitation = conn
            .query_row(
                "SELECT typ FROM invitations WHERE token = ?",
                params![token],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let typ = match invitation {
            Some(typ) => typ,
            None => {
                return Err(AppError::bad_request("invalid invitation token"));
            }
        };
        if typ != "invite" {
            return Err(AppError::bad_request("invalid invitation token"));
        }
        conn.execute(
            "DELETE FROM invitations WHERE token = ?",
            params![token],
        )?;
        Ok(())
    })?;

    Ok(Json(json!({"msg": "invitation rejected successfully"})))
}

#[derive(Deserialize)]
struct CreateGroupRequest {
    name: Option<String>,
    code_name: Option<String>,
}

async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateGroupRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let token = extract_bearer(&headers)?;
    let student_id = verify_token(&token, &state.config.jwt_secret)?;
    let name = payload.name.ok_or_else(|| {
        AppError::bad_request("missing required fields: name, code_name")
    })?;
    let code_name = payload.code_name.ok_or_else(|| {
        AppError::bad_request("missing required fields: name, code_name")
    })?;
    let response_name = name.clone();
    let response_code_name = code_name.clone();

    with_conn(&state, |conn| {
        let user = get_user(conn, &student_id)?;
        let user = user.ok_or_else(|| AppError::not_found("user not found"))?;
        if user.group_code_name.is_some() {
            return Err(AppError::bad_request("user already in a group"));
        }

        let existing = conn
            .query_row(
                "SELECT 1 FROM groups WHERE code_name = ?",
                params![code_name],
                |_| Ok(()),
            )
            .optional()?;
        if existing.is_some() {
            return Err(AppError::bad_request(
                "group code name already exists",
            ));
        }
        Ok(())
    })?;

    group_ns(&state.config.kubernetes, &code_name, &student_id).await?;

    with_conn(&state, |conn| {
        conn.execute(
            "INSERT INTO groups (code_name, name, leader_id) VALUES (?, ?, ?)",
            params![code_name, name, student_id],
        )?;
        conn.execute(
            "INSERT INTO group_members (group_code_name, student_id) VALUES (?, ?)",
            params![code_name, student_id],
        )?;
        conn.execute(
            "UPDATE users SET group_code_name = ? WHERE student_id = ?",
            params![code_name, student_id],
        )?;
        Ok(())
    })?;

    Ok(Json(json!({
        "msg": "group created successfully",
        "group": {
            "name": response_name,
            "code_name": response_code_name,
            "leader": student_id
        }
    })))
}

#[derive(Deserialize)]
struct Pagination {
    page: Option<u32>,
    page_size: Option<u32>,
}

async fn list_users(
    State(state): State<AppState>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<serde_json::Value>, AppError> {
    let page = pagination.page.unwrap_or(1);
    let page_size = pagination.page_size.unwrap_or(20);
    let offset = (page.saturating_sub(1) * page_size) as i64;
    let limit = page_size as i64;

    let users = with_conn(&state, |conn| {
        let mut stmt = conn.prepare(
            "SELECT student_id, name, group_code_name FROM users ORDER BY student_id LIMIT ? OFFSET ?",
        )?;
        let rows = stmt.query_map(params![limit, offset], |row| {
            Ok(json!({
                "student_id": row.get::<_, String>(0)?,
                "name": row.get::<_, String>(1)?,
                "group": row.get::<_, Option<String>>(2)?,
            }))
        })?;
        let mut list = Vec::new();
        for row in rows {
            list.push(row?);
        }
        Ok(list)
    })?;

    Ok(Json(json!({
        "page": page,
        "page_size": page_size,
        "users": users
    })))
}

async fn list_groups(
    State(state): State<AppState>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<serde_json::Value>, AppError> {
    let page = pagination.page.unwrap_or(1);
    let page_size = pagination.page_size.unwrap_or(20);
    let offset = (page.saturating_sub(1) * page_size) as i64;
    let limit = page_size as i64;

    let groups = with_conn(&state, |conn| {
        let mut stmt = conn.prepare(
            "SELECT code_name, name, leader_id FROM groups ORDER BY code_name LIMIT ? OFFSET ?",
        )?;
        let rows = stmt.query_map(params![limit, offset], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;

        let mut list = Vec::new();
        for row in rows {
            let (code_name, name, leader_id) = row?;

            let leader_name = conn
                .query_row(
                    "SELECT name FROM users WHERE student_id = ?",
                    params![leader_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .unwrap_or_else(|| format!("user {}", leader_id));

            let mut member_stmt = conn.prepare(
                "SELECT student_id FROM group_members WHERE group_code_name = ? ORDER BY student_id",
            )?;
            let member_rows = member_stmt
                .query_map(params![code_name], |row| row.get::<_, String>(0))?;
            let mut members = Vec::new();
            for member_row in member_rows {
                let member_id = member_row?;
                let member_name = conn
                    .query_row(
                        "SELECT name FROM users WHERE student_id = ?",
                        params![member_id],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?
                    .unwrap_or_else(|| format!("user {}", member_id));
                members.push(MemberSummary {
                    student_id: member_id,
                    name: member_name,
                });
            }

            list.push(GroupSummaryResponse {
                name,
                code_name,
                leader: LeaderSummary {
                    student_id: leader_id,
                    name: leader_name,
                },
                members,
            });
        }
        Ok(list)
    })?;

    Ok(Json(json!({
        "page": page,
        "page_size": page_size,
        "groups": groups
    })))
}

async fn debug_users(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let payload = with_conn(&state, |conn| {
        let mut users = BTreeMap::new();
        let mut stmt = conn.prepare(
            "SELECT student_id, name, email, group_code_name FROM users ORDER BY student_id",
        )?;
        let rows = stmt.query_map(params![], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?;
        for row in rows {
            let (student_id, name, email, group_code_name) = row?;
            users.insert(
                student_id,
                json!({
                    "name": name,
                    "email": email,
                    "password_hash": "***",
                    "group": group_code_name
                }),
            );
        }

        let mut groups = BTreeMap::new();
        let mut group_stmt = conn.prepare(
            "SELECT code_name, name, leader_id FROM groups ORDER BY code_name",
        )?;
        let group_rows = group_stmt.query_map(params![], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        for row in group_rows {
            let (code_name, name, leader_id) = row?;
            let members = group_members(conn, &code_name)?;
            groups.insert(
                code_name.clone(),
                json!({
                    "name": name,
                    "code_name": code_name,
                    "leader": leader_id,
                    "members": members
                }),
            );
        }

        let mut invitations = BTreeMap::new();
        let mut invite_stmt = conn.prepare(
            "SELECT token, group_code_name, inviter_id, invitee_id, typ FROM invitations ORDER BY token",
        )?;
        let invite_rows = invite_stmt.query_map(params![], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        for row in invite_rows {
            let (token, group_code_name, inviter_id, invitee_id, typ) = row?;
            invitations.insert(
                token,
                json!({
                    "group_code_name": group_code_name,
                    "inviter_id": inviter_id,
                    "invitee_id": invitee_id,
                    "type": typ
                }),
            );
        }

        let mut join_requests = BTreeMap::new();
        let mut join_stmt = conn.prepare(
            "SELECT token, group_code_name, requester_id, typ FROM join_requests ORDER BY token",
        )?;
        let join_rows = join_stmt.query_map(params![], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        for row in join_rows {
            let (token, group_code_name, requester_id, typ) = row?;
            join_requests.insert(
                token,
                json!({
                    "group_code_name": group_code_name,
                    "requester_id": requester_id,
                    "type": typ
                }),
            );
        }

        Ok(json!({
            "users": users,
            "groups": groups,
            "invitations": invitations,
            "join_requests": join_requests
        }))
    })?;

    Ok(Json(payload))
}
