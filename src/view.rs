use crate::config::Config;
use crate::error::AppError;
use crate::metrics;
use axum::{
    Router,
    extract::State,
    http::{HeaderMap, header::CONTENT_TYPE},
    middleware,
    response::IntoResponse,
    routing::{get, post},
};
use jsonwebtoken::{
    DecodingKey, EncodingKey, Header, Validation, decode, encode,
};
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower_http::{cors::CorsLayer, normalize_path::NormalizePathLayer};

mod auth;
mod groups;
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
    let protected = Router::new()
        .route("/user", get(users::get_user_info))
        .route("/user/edit", post(users::edit_user_info))
        .route("/admin/group_assign", post(groups::admin_group_assign))
        .route("/admin/imperson", post(auth::admin_impersonate))
        .route("/group/invite", post(groups::invite_user))
        .route("/group/invite/accept", post(groups::accept_invitation))
        .route("/group/invite/reject", post(groups::reject_invitation))
        .route("/user/invite/list", get(groups::list_user_invitations))
        .route("/group/invite/list", get(groups::list_group_invitations))
        .route("/group/create", post(groups::create_group))
        .route("/group/edit", post(groups::edit_group))
        .route("/group/delete", post(groups::delete_group))
        .route("/users", get(users::list_users))
        .route("/groups", get(groups::list_groups))
        .layer(middleware::from_fn(auth_middleware));

    Router::new()
        .route("/register", post(auth::register))
        .route("/login", post(auth::login))
        .route(
            "/oauth2/v1/authorize",
            get(oauth::oauth_authorize_get).post(oauth::oauth_authorize_post),
        )
        .route("/oauth2/v1/token", post(oauth::oauth_token))
        .route("/oauth2/v1/userinfo", get(oauth::oauth_userinfo))
        .merge(protected)
        .with_state(state)
        .layer(NormalizePathLayer::trim_trailing_slash())
        .layer(CorsLayer::permissive())
}

pub fn build_metrics_app(state: AppState) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
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

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Claims {
    pub(crate) id: String,
    pub(crate) imperson: bool,
    pub(crate) exp: usize,
}

static JWT_SECRET: OnceLock<String> = OnceLock::new();

pub(crate) fn set_jwt_secret(secret: String) {
    let _ = JWT_SECRET.set(secret);
}

impl TryFrom<String> for Claims {
    type Error = AppError;

    fn try_from(token: String) -> Result<Self, Self::Error> {
        let secret = JWT_SECRET
            .get()
            .ok_or_else(|| AppError::internal("jwt secret not initialized"))?;
        let validation = Validation::default();
        let token_data = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .map_err(|_| AppError::unauthorized("invalid token"))?;
        let claims = token_data.claims;
        let now = now_timestamp()? as usize;
        if claims.exp <= now {
            return Err(AppError::unauthorized("token expired"));
        }
        Ok(claims)
    }
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

pub(crate) fn generate_token(
    id: &str,
    secret: &str,
) -> Result<String, AppError> {
    let exp = SystemTime::now()
        .checked_add(Duration::from_secs(24 * 60 * 60))
        .ok_or_else(|| AppError::internal("failed to build token"))?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::internal("failed to build token"))?
        .as_secs() as usize;
    let claims = Claims {
        id: id.to_string(),
        imperson: false,
        exp,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| AppError::internal("failed to build token"))
}

pub(crate) fn generate_token_with_impersonation(
    id: &str,
    secret: &str,
    imperson: bool,
) -> Result<String, AppError> {
    let exp = SystemTime::now()
        .checked_add(Duration::from_secs(24 * 60 * 60))
        .ok_or_else(|| AppError::internal("failed to build token"))?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::internal("failed to build token"))?
        .as_secs() as usize;
    let claims = Claims {
        id: id.to_string(),
        imperson,
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

async fn auth_middleware(
    mut req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Result<axum::response::Response, AppError> {
    let token = extract_bearer(req.headers())?;
    let claims = Claims::try_from(token)?;
    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}
