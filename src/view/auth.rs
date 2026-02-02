use std::time::{SystemTime, UNIX_EPOCH};

use super::*;
use axum::Json;
use axum::extract::State;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use serde::Deserialize;
use serde_json::json;

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

pub(super) async fn register(
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

    user_ns(&state.config.kubernetes, &student_id).await?;

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

    Ok(Json(
        json!({"msg": "registration successful", "ver": "1.0"}),
    ))
}

#[derive(Deserialize)]
pub(super) struct LoginRequest {
    student_id: Option<String>,
    password: Option<String>,
}

pub(super) async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
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
    Ok(Json(json!({"token": token, "msg": "login successful"})))
}

#[derive(Deserialize)]
pub(super) struct RecoverPasswordRequest {
    student_id: Option<String>,
    email: Option<String>,
}

pub(super) async fn recover_password(
    State(state): State<AppState>,
    Json(payload): Json<RecoverPasswordRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let student_id = payload
        .student_id
        .ok_or_else(|| AppError::bad_request("missing student_id or email"))?;
    let email = payload
        .email
        .ok_or_else(|| AppError::bad_request("missing student_id or email"))?;

    let db = &state.db;
    let user = get_user(db, &student_id)
        .await?
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
pub(super) struct RecoverPasswordConfirmRequest {
    token: Option<String>,
    #[serde(rename = "newPassword")]
    new_password: Option<String>,
}

pub(super) async fn recover_password_confirm(
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

    let db = &state.db;
    let user = get_user(db, student_id).await?;
    if user.is_none() {
        return Err(AppError::not_found("user not found"));
    }
    let mut model: user::ActiveModel =
        user::Entity::find_by_id(student_id.to_string())
            .one(db)
            .await?
            .ok_or_else(|| AppError::not_found("user not found"))?
            .into();
    let salt = generate_salt();
    let hash = hash_password(&salt, &new_password);
    model.password_hash = Set(hash);
    model.password_salt = Set(salt);
    model.update(db).await?;

    Ok(Json(
        json!({"msg": "password reset successful", "ver": "1.0"}),
    ))
}
