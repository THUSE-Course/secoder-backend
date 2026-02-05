use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
};
use sea_orm::{EntityTrait, Set};
use serde::Deserialize;

use super::*;

use crate::db::get_user;
use crate::entity::user;
use crate::kubernetes::user_ns;
use crate::security::{generate_salt, hash_password};

#[derive(Deserialize)]
pub struct RegisterRequest {
    id: String,
    email: String,
    name: String,
    password: String,
}

fn invalid_cred() -> AppError {
    AppError::adhoc(
        StatusCode::UNAUTHORIZED,
        anyhow::anyhow!("invalid credentials"),
    )
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<StatusCode, AppError> {
    let unauthorized = |e: &str| {
        AppError::adhoc(
            StatusCode::UNAUTHORIZED,
            anyhow::anyhow!(e.to_string()),
        )
    };
    let expected = state
        .users
        .get(&payload.id)
        .ok_or(unauthorized("user is not in predefined list"))?;
    if expected != &payload.password {
        return Err(invalid_cred());
    }
    let db = &state.db;
    let existing = get_user(db, &payload.id).await?;
    if existing.is_some() {
        return Err(invalid_cred());
    }
    user_ns(&payload.id).await?;
    let salt = generate_salt();
    let hash = hash_password(&salt, expected);
    let user = user::ActiveModel {
        id: Set(payload.id),
        name: Set(payload.name),
        email: Set(payload.email),
        password_hash: Set(hash),
        password_salt: Set(salt),
        group_code_name: Set(None),
    };
    user::Entity::insert(user).exec(db).await?;
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
pub struct LoginRequest {
    id: String,
    password: String,
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<String, AppError> {
    if payload.id == state.config.admin {
        if payload.password != state.config.password {
            return Err(invalid_cred());
        }
        let token = Claims::from((&payload.id, false));
        Ok({ &token }.try_into()?)
    } else {
        let db = &state.db;
        let user = get_user(db, &payload.id).await?.ok_or(invalid_cred())?;
        let hash = hash_password(&user.password_salt, &payload.password);
        if user.password_hash != hash {
            return Err(invalid_cred());
        }
        let token = Claims::from((&payload.id, false));
        Ok({ &token }.try_into()?)
    }
}

#[derive(Deserialize)]
pub struct ImpersonateRequest {
    id: String,
}

pub async fn admin_impersonate(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<ImpersonateRequest>,
) -> Result<String, AppError> {
    if claims.imperson || claims.id != state.config.admin {
        return Err(AppError::adhoc(
            StatusCode::FORBIDDEN,
            anyhow::anyhow!("admin privileges required"),
        ));
    }
    let db = &state.db;
    let user = get_user(db, &payload.id).await?;
    if user.is_none() {
        return Err(AppError::adhoc(
            StatusCode::NOT_FOUND,
            anyhow::anyhow!("user {} not found", payload.id),
        ));
    }

    let token = Claims::from((&payload.id, true));
    { &token }.try_into()
}
