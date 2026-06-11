use sea_orm::{EntityTrait, Set};

use super::*;

use crate::{
    db::get_user,
    entity::user,
    kubernetes::user_ns,
    security::{hash_password, verify_password},
};

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
    super::ensure_not_readonly(&state.db).await?;
    let unauthorized = |e: &str| {
        AppError::adhoc(
            StatusCode::UNAUTHORIZED,
            anyhow::anyhow!(e.to_string()),
        )
    };
    let expected = state
        .users
        .password_for(&payload.id)
        .ok_or(unauthorized("user is not in predefined list"))?;
    if expected != payload.password {
        return Err(invalid_cred());
    }
    let db = &state.db;
    let existing = get_user(db, &payload.id).await?;
    if existing.is_some() {
        return Err(invalid_cred());
    }
    user_ns(&state.kube, &payload.id, &state.config.rbac).await?;
    let hash = hash_password(&expected)?;
    let user = user::ActiveModel {
        id: Set(payload.id),
        name: Set(payload.name),
        email: Set(payload.email),
        sudo: Set(false),
        password_hash: Set(hash),
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
    if state.users.is_banned(&payload.id) {
        return Err(invalid_cred());
    }
    let db = &state.db;
    let user = get_user(db, &payload.id).await?.ok_or(invalid_cred())?;
    if !verify_password(&user.password_hash, &payload.password)? {
        return Err(invalid_cred());
    }
    let token = Claims::from((&payload.id, user.email, user.name, user.sudo));
    { &token }.try_into()
}
