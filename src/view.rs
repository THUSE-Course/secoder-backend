use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};

use axum::{
    Json, Router,
    extract::{Extension, Query, State},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    middleware,
    response::IntoResponse,
    routing::{get, post},
};
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use tower_http::{cors::CorsLayer, normalize_path::NormalizePathLayer};

use super::{config::Config, error::AppError, metrics};
use kube::Client;

mod auth;
mod group;
mod rbac;
mod user;

pub static JWT_SECRET: OnceLock<String> = OnceLock::new();
pub static JWT_TTL: OnceLock<u64> = OnceLock::new();

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub config: Config,
    pub users: std::sync::Arc<HashMap<String, String>>,
    pub kube: Client,
}

impl AppState {
    pub fn new(
        db: DatabaseConnection,
        config: Config,
        users: HashMap<String, String>,
        kube: Client,
    ) -> Self {
        Self {
            db,
            config,
            users: Arc::new(users),
            kube,
        }
    }
}

pub fn route(state: AppState) -> Router {
    let protected = Router::new()
        .route("/user", get(user::get_user_info))
        .route("/user/edit", post(user::edit_user_info))
        .route("/admin/group_assign", post(group::admin_group_assign))
        .route("/admin/imperson", post(auth::admin_impersonate))
        .route("/group/invite", post(group::invite_user))
        .route("/group/invite/accept", post(group::accept_invitation))
        .route("/group/invite/reject", post(group::reject_invitation))
        .route("/user/invite/list", get(group::list_user_invitations))
        .route("/group/invite/list", get(group::list_group_invitations))
        .route("/group/create", post(group::create_group))
        .route("/group/edit", post(group::edit_group))
        .route("/group/delete", post(group::delete_group))
        .route("/rbac", get(rbac::get_token))
        .route("/users", get(user::list_users))
        .route("/groups", get(group::list_groups))
        .layer(middleware::from_fn(auth_middleware));

    Router::new()
        .route("/register", post(auth::register))
        .route("/login", post(auth::login))
        .merge(protected)
        .with_state(state)
        .layer(NormalizePathLayer::trim_trailing_slash())
        .layer(CorsLayer::permissive())
}

pub fn metric(state: AppState) -> Router {
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
    email: String,
    name: String,
    imperson: bool,
    exp: u64,
    // client my require iat field
    // https://github.com/omniauth/omniauth-jwt
    iat: u64,
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
struct Pagination {
    page: Option<u32>,
    page_size: Option<u32>,
}

impl<S1, S2, S3> From<(S1, S2, S3, bool)> for Claims
where
    S1: Into<String>,
    S2: Into<String>,
    S3: Into<String>,
{
    fn from(value: (S1, S2, S3, bool)) -> Self {
        let iat = jsonwebtoken::get_current_timestamp();
        Claims {
            id: value.0.into(),
            email: value.1.into(),
            name: value.2.into(),
            imperson: value.3,
            iat,
            exp: iat + JWT_TTL.get().unwrap(),
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
    let cliams = if let Some(Ok(Some((b, token)))) = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .map(|v| v.to_str().map(|v| v.split_once(' ')))
        && b == "Bearer"
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
