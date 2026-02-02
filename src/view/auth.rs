use super::*;
use axum::Json;
use axum::extract::State;
use sea_orm::{EntityTrait, Set};
use serde::{Deserialize, Serialize};

use crate::db::get_user;
use crate::entity::user;
use crate::kubernetes::user_ns;
use crate::security::{generate_salt, hash_password};

#[derive(Deserialize)]
pub(super) struct RegisterRequest {
    student_id: Option<String>,
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
    let student_id = payload.student_id.ok_or_else(|| {
        AppError::bad_request("missing required field: student_id")
    })?;
    let email = payload.email.ok_or_else(|| {
        AppError::bad_request("missing required field: email")
    })?;
    let name = payload
        .name
        .ok_or_else(|| AppError::bad_request("missing required field: name"))?;
    let password = payload.password.ok_or_else(|| {
        AppError::bad_request("missing required field: password")
    })?;

    let expected = state.users.get(&student_id).ok_or_else(|| {
        AppError::unauthorized("user is not in predefined list")
    })?;
    if expected != &password {
        return Err(AppError::unauthorized("invalid credentials"));
    }

    let db = &state.db;
    let existing = get_user(db, &student_id).await?;
    if existing.is_some() {
        return Err(AppError::bad_request("user already exists"));
    }

    user_ns(&student_id).await?;

    let salt = generate_salt();
    let hash = hash_password(&salt, expected);
    let user = user::ActiveModel {
        student_id: Set(student_id.clone()),
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
    student_id: Option<String>,
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
    let student_id = payload.student_id.ok_or_else(|| {
        AppError::bad_request("missing student_id or password")
    })?;
    let password = payload.password.ok_or_else(|| {
        AppError::bad_request("missing student_id or password")
    })?;

    let db = &state.db;
    let user = get_user(db, &student_id)
        .await?
        .ok_or_else(|| AppError::unauthorized("invalid credentials"))?;
    let hash = hash_password(&user.password_salt, &password);
    if user.password_hash != hash {
        return Err(AppError::unauthorized("invalid credentials"));
    }
    let token = generate_token(&student_id, &state.config.jwt)?;
    Ok(Json(LoginResponse {
        token,
        msg: "login successful".to_string(),
    }))
}
