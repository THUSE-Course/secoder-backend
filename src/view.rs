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
use kube::Client;
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder,
};
use serde::{Deserialize, Serialize};
use tower_http::{cors::CorsLayer, normalize_path::NormalizePathLayer};

use super::{config::Config, error::AppError, metrics};
use crate::db;
use crate::entity::member;

mod admin;
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
    pub webhook_token: String,
}

impl AppState {
    pub fn new(
        db: DatabaseConnection,
        config: Config,
        users: HashMap<String, String>,
        kube: Client,
        webhook_token: String,
    ) -> Self {
        Self {
            db,
            config,
            users: Arc::new(users),
            kube,
            webhook_token,
        }
    }
}

pub fn route(state: AppState) -> Router {
    let protected = Router::new()
        .route("/admin/readonly", post(admin::update_readonly))
        .route("/admin/impersonate", post(admin::impersonate))
        .route("/sync", get(sync))
        .route("/user", get(user::get_user_info))
        .route("/user/edit", post(user::edit_user_info))
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
        .route("/AGENTS.md", get(agents_md))
        .route("/status", get(status))
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

async fn agents_md() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/markdown; charset=utf-8")],
        include_str!("../docs/AGENTS.md"),
    )
}

#[derive(Serialize)]
pub struct WebhookPayload {
    users: Vec<String>,
    groups: HashMap<String, Vec<String>>,
}

pub fn dispatch_webhook(
    config: &Config,
    webhook_token: &str,
    payload: WebhookPayload,
) {
    if config.webhook.url.is_empty() {
        return;
    }
    let url = config.webhook.url.clone();
    let token = webhook_token.to_string();
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let resp = client
            .post(url)
            .bearer_auth(token)
            .json(&payload)
            .send()
            .await;
        if let Err(err) = resp {
            tracing::warn!("failed to send webhook: {err}");
        }
    });
}

pub async fn load_group_members(
    db: &DatabaseConnection,
    group_code_name: &str,
) -> Result<Vec<String>, AppError> {
    let members = member::Entity::find()
        .filter(member::Column::GroupCodeName.eq(group_code_name))
        .order_by_asc(member::Column::Id)
        .all(db)
        .await?
        .into_iter()
        .map(|member| member.id)
        .collect::<Vec<_>>();
    Ok(members)
}

async fn sync(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<StatusCode, AppError> {
    let db = &state.db;
    let user = crate::db::get_user(db, &claims.id).await?.ok_or_else(|| {
        AppError::adhoc(
            StatusCode::NOT_FOUND,
            anyhow::anyhow!("user {} not found", &claims.id),
        )
    })?;
    let mut groups = HashMap::new();
    if let Some(code_name) = user.group_code_name.clone() {
        let members = load_group_members(db, &code_name).await?;
        groups.insert(code_name, members);
    }
    dispatch_webhook(
        &state.config,
        &state.webhook_token,
        WebhookPayload {
            users: vec![user.id],
            groups,
        },
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn metrics_handler(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    let body = metrics::render_metrics(&state.db).await?;
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "text/plain; version=0.0.4".parse().unwrap());
    Ok((headers, body))
}

#[derive(Serialize)]
struct StatusResponse {
    readonly: bool,
}

async fn status(
    State(state): State<AppState>,
) -> Result<Json<StatusResponse>, AppError> {
    let readonly = db::is_readonly(&state.db).await?;
    Ok(Json(StatusResponse { readonly }))
}

pub async fn ensure_not_readonly(
    db: &DatabaseConnection,
) -> Result<(), AppError> {
    if db::is_readonly(db).await? {
        return Err(AppError::adhoc(
            StatusCode::FORBIDDEN,
            anyhow::anyhow!("backend is readonly"),
        ));
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
struct Claims {
    id: String,
    email: String,
    name: String,
    // indicate this user is root
    sudo: bool,
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
            sudo: value.3,
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
