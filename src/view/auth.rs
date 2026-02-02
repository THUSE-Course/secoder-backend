use super::*;
use axum::Json;
use axum::extract::{Extension, State};
use sea_orm::{EntityTrait, Set};
use serde::{Deserialize, Serialize};

use crate::db::get_user;
use crate::entity::user;
use crate::kubernetes::user_ns;
use crate::security::{generate_salt, hash_password};

#[derive(Deserialize)]
pub(super) struct RegisterRequest {
    id: Option<String>,
    email: Option<String>,
    name: Option<String>,
    password: Option<String>,
}

#[derive(Serialize)]
pub(super) struct RegisterResponse {
    msg: String,
    ver: String,
}

pub(super) async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
    let id = payload
        .id
        .ok_or_else(|| AppError::bad_request("missing required field: id"))?;
    let email = payload.email.ok_or_else(|| {
        AppError::bad_request("missing required field: email")
    })?;
    let name = payload
        .name
        .ok_or_else(|| AppError::bad_request("missing required field: name"))?;
    let password = payload.password.ok_or_else(|| {
        AppError::bad_request("missing required field: password")
    })?;

    let expected = state.users.get(&id).ok_or_else(|| {
        AppError::unauthorized("user is not in predefined list")
    })?;
    if expected != &password {
        return Err(AppError::unauthorized("invalid credentials"));
    }

    let db = &state.db;
    let existing = get_user(db, &id).await?;
    if existing.is_some() {
        return Err(AppError::bad_request("user already exists"));
    }

    user_ns(&id).await?;

    let salt = generate_salt();
    let hash = hash_password(&salt, expected);
    let user = user::ActiveModel {
        id: Set(id.clone()),
        name: Set(name),
        email: Set(email),
        password_hash: Set(hash),
        password_salt: Set(salt),
        group_code_name: Set(None),
    };
    user::Entity::insert(user).exec(db).await?;

    Ok(Json(RegisterResponse {
        msg: "registration successful".to_string(),
        ver: "1.0".to_string(),
    }))
}

#[derive(Deserialize)]
pub(super) struct LoginRequest {
    id: Option<String>,
    password: Option<String>,
}

#[derive(Serialize)]
pub(super) struct LoginResponse {
    token: String,
    msg: String,
}

pub(super) async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let id = payload
        .id
        .ok_or_else(|| AppError::bad_request("missing id or password"))?;
    let password = payload
        .password
        .ok_or_else(|| AppError::bad_request("missing id or password"))?;

    if id == state.config.admin {
        if password != state.config.password {
            return Err(AppError::unauthorized("invalid credentials"));
        }
        let token =
            generate_token_with_impersonation(&id, &state.config.jwt, false)?;
        return Ok(Json(LoginResponse {
            token,
            msg: "login successful".to_string(),
        }));
    }

    let db = &state.db;
    let user = get_user(db, &id)
        .await?
        .ok_or_else(|| AppError::unauthorized("invalid credentials"))?;
    let hash = hash_password(&user.password_salt, &password);
    if user.password_hash != hash {
        return Err(AppError::unauthorized("invalid credentials"));
    }
    let token = generate_token(&id, &state.config.jwt)?;
    Ok(Json(LoginResponse {
        token,
        msg: "login successful".to_string(),
    }))
}

#[derive(Deserialize)]
pub(super) struct ImpersonateRequest {
    id: Option<String>,
}

#[derive(Serialize)]
pub(super) struct ImpersonateResponse {
    token: String,
    msg: String,
}

pub(super) async fn admin_impersonate(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<ImpersonateRequest>,
) -> Result<Json<ImpersonateResponse>, AppError> {
    if claims.imperson || claims.id != state.config.admin {
        return Err(AppError::forbidden("admin privileges required"));
    }
    let target_id = payload
        .id
        .ok_or_else(|| AppError::bad_request("missing required field: id"))?;

    let db = &state.db;
    let user = get_user(db, &target_id).await?;
    if user.is_none() {
        return Err(AppError::not_found("user not found"));
    }

    let token =
        generate_token_with_impersonation(&target_id, &state.config.jwt, true)?;
    Ok(Json(ImpersonateResponse {
        token,
        msg: "impersonation successful".to_string(),
    }))
}
