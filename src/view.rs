use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    middleware,
    response::IntoResponse,
    routing::{get, post},
};
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use tower_http::{cors::CorsLayer, normalize_path::NormalizePathLayer};

use crate::{config::Config, error::AppError, metrics};

mod auth;
mod groups;
mod oauth;
mod users;

pub static JWT_SECRET: OnceLock<String> = OnceLock::new();
pub static JWT_TTL: OnceLock<u64> = OnceLock::new();

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub config: Config,
    pub users: std::sync::Arc<HashMap<String, String>>,
    pub oauth_store: Arc<Mutex<OAuthStore>>,
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
pub struct OAuthStore {
    codes: HashMap<String, AuthCode>,
    tokens: HashMap<String, AccessToken>,
    txns: HashMap<String, OAuthTxn>,
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

struct OAuthTxn {
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    response_type: String,
    code: Option<String>,
    expires_at: u64,
}

impl OAuthStore {
    pub(crate) fn prune(&mut self, now: u64) {
        self.codes.retain(|_, code| code.expires_at > now);
        self.tokens.retain(|_, token| token.expires_at > now);
        self.txns.retain(|_, txn| txn.expires_at > now);
    }
}

pub fn build_app(state: AppState) -> Router {
    let oauth_protected = Router::new()
        .route("/oauth2/v1/userinfo", get(oauth::oauth_userinfo))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            oauth::oauth_middleware,
        ));
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
        .route("/txn/{id}", get(oauth::oauth_txn))
        .merge(oauth_protected)
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
struct Claims {
    id: String,
    imperson: bool,
    exp: u64,
}

impl TryFrom<&str> for Claims {
    type Error = AppError;

    fn try_from(token: &str) -> Result<Self, Self::Error> {
        use jsonwebtoken::{DecodingKey, Validation, decode};
        let secret = JWT_SECRET.get().unwrap();
        let validation = Validation::default();
        let claims = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .map_err(|e| AppError::adhoc(StatusCode::UNAUTHORIZED, e))?
        .claims;
        let now = jsonwebtoken::get_current_timestamp();
        if claims.exp <= now {
            return Err(AppError::adhoc(
                StatusCode::UNAUTHORIZED,
                anyhow::anyhow!("token expired at {}", claims.exp),
            ));
        }
        Ok(claims)
    }
}

#[derive(Deserialize)]
pub(super) struct Pagination {
    pub(super) page: Option<u32>,
    pub(super) page_size: Option<u32>,
}

impl<S> From<(S, bool)> for Claims
where
    S: Into<String>,
{
    fn from(value: (S, bool)) -> Self {
        Claims {
            id: value.0.into(),
            imperson: value.1,
            exp: jsonwebtoken::get_current_timestamp() + JWT_TTL.get().unwrap(),
        }
    }
}

impl TryFrom<&Claims> for String {
    type Error = AppError;
    fn try_from(value: &Claims) -> Result<Self, Self::Error> {
        use jsonwebtoken::{EncodingKey, Header};
        Ok(jsonwebtoken::encode(
            &Header::default(),
            value,
            &EncodingKey::from_secret(JWT_SECRET.get().unwrap().as_bytes()),
        )?)
    }
}

async fn auth_middleware(
    mut req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Result<axum::response::Response, AppError> {
    let cliams = if let Some(Ok(Some((_, token)))) = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .map(|v| v.to_str().map(|v| v.split_once(' ')))
    {
        Claims::try_from(token)?
    } else {
        return Err(AppError::adhoc(
            StatusCode::UNAUTHORIZED,
            anyhow::anyhow!("authorization required"),
        ));
    };
    req.extensions_mut().insert(cliams);
    Ok(next.run(req).await)
}
