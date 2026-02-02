use crate::config::Config;
use crate::error::AppError;
use crate::metrics;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, header::CONTENT_TYPE},
    response::IntoResponse,
    routing::{get, post},
};
use jsonwebtoken::{
    DecodingKey, EncodingKey, Header, Validation, decode, encode,
};
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower_http::{cors::CorsLayer, normalize_path::NormalizePathLayer};

mod auth;
mod groups;
mod health;
mod oauth;
mod users;

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub config: Config,
    pub users: std::sync::Arc<HashMap<String, String>>,
    pub(crate) oauth_store: Arc<Mutex<OAuthStore>>,
}

impl AppState {
    pub fn new(
        db: DatabaseConnection,
        config: Config,
        users: HashMap<String, String>,
    ) -> Self {
        Self {
            db,
            config,
            users: Arc::new(users),
            oauth_store: Arc::new(Mutex::new(Default::default())),
        }
    }
}

#[derive(Default)]
pub(crate) struct OAuthStore {
    pub(crate) codes: HashMap<String, AuthCode>,
    pub(crate) tokens: HashMap<String, AccessToken>,
}

pub(crate) struct AuthCode {
    pub(crate) user_id: String,
    pub(crate) client_id: String,
    pub(crate) redirect_uri: String,
    pub(crate) scope: Option<String>,
    pub(crate) expires_at: u64,
}

pub(crate) struct AccessToken {
    pub(crate) user_id: String,
    pub(crate) expires_at: u64,
}

impl OAuthStore {
    pub(crate) fn prune(&mut self, now: u64) {
        self.codes.retain(|_, code| code.expires_at > now);
        self.tokens.retain(|_, token| token.expires_at > now);
    }
}

pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health::health_check))
        .route("/register", post(auth::register))
        .route("/login", post(auth::login))
        .route(
            "/oauth/authorize",
            get(oauth::oauth_authorize_get).post(oauth::oauth_authorize_post),
        )
        .route("/oauth/token", post(oauth::oauth_token))
        .route("/oauth/userinfo", get(oauth::oauth_userinfo))
        .route("/user", get(users::get_user_info))
        .route("/user/edit", post(users::edit_user_info))
        .route("/metrics", get(metrics_handler))
        .route("/recover_password", post(auth::recover_password))
        .route(
            "/recover_password/confirm",
            post(auth::recover_password_confirm),
        )
        .route("/admin/group_assign", post(groups::admin_group_assign))
        .route("/group/join", post(groups::join_group))
        .route("/group/join/accept", post(groups::accept_join_request))
        .route("/group/join/reject", post(groups::reject_join_request))
        .route("/group/invite", post(groups::invite_user))
        .route("/group/invite/accept", post(groups::accept_invitation))
        .route("/group/invite/reject", post(groups::reject_invitation))
        .route("/group/create", post(groups::create_group))
        .route("/users", get(users::list_users))
        .route("/groups", get(groups::list_groups))
        .with_state(state)
        .layer(NormalizePathLayer::trim_trailing_slash())
        .layer(CorsLayer::permissive())
}

async fn metrics_handler(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let body = metrics::render_metrics(&state.db).await?;
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "text/plain; version=0.0.4".parse().unwrap());
    Ok((headers, body))
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Claims {
    pub(crate) student_id: String,
    pub(crate) exp: usize,
}

#[derive(Deserialize)]
pub(crate) struct Pagination {
    pub(crate) page: Option<u32>,
    pub(crate) page_size: Option<u32>,
}

pub(crate) fn extract_bearer(headers: &HeaderMap) -> Result<String, AppError> {
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

pub(crate) fn verify_token(
    token: &str,
    secret: &str,
) -> Result<String, AppError> {
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

pub(crate) fn generate_token(
    student_id: &str,
    secret: &str,
) -> Result<String, AppError> {
    let exp = SystemTime::now()
        .checked_add(Duration::from_secs(24 * 60 * 60))
        .ok_or_else(|| AppError::internal("failed to build token"))?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::internal("failed to build token"))?
        .as_secs() as usize;
    let claims = Claims {
        student_id: student_id.to_string(),
        exp,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| AppError::internal("failed to build token"))
}

pub(crate) fn now_timestamp() -> Result<u64, AppError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub(crate) fn ok_status() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "message": "service is healthy"
    }))
}
