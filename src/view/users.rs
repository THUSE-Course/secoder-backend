use super::*;
use crate::db::get_user;
use crate::entity::user;
use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
};
use sea_orm::{ActiveModelTrait, EntityTrait, QueryOrder, QuerySelect, Set};
use serde::Serialize;

pub(super) async fn get_user_info(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<UserInfoResponse>, AppError> {
    let token = extract_bearer(&headers)?;
    let id = verify_token(&token, &state.config.jwt)?;
    let db = &state.db;
    let user = get_user(db, &id)
        .await?
        .ok_or_else(|| AppError::not_found("user not found"))?;

    Ok(Json(UserInfoResponse {
        id: user.id,
        name: user.name,
        email: user.email,
        group: user.group_code_name,
    }))
}

pub(super) async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(pagination): Query<Pagination>,
) -> Result<Json<UserListResponse>, AppError> {
    let token = extract_bearer(&headers)?;
    let _id = verify_token(&token, &state.config.jwt)?;
    let page = pagination.page.unwrap_or(1);
    let page_size = pagination.page_size.unwrap_or(20);
    let offset = (page.saturating_sub(1) * page_size) as u64;
    let limit = page_size as u64;

    let db = &state.db;
    let rows = user::Entity::find()
        .order_by_asc(user::Column::Id)
        .offset(offset)
        .limit(limit)
        .all(db)
        .await?;
    let users = rows
        .into_iter()
        .map(|row| UserSummary {
            id: row.id,
            name: row.name,
            group: row.group_code_name,
        })
        .collect::<Vec<_>>();

    Ok(Json(UserListResponse {
        page,
        page_size,
        users,
    }))
}

#[derive(serde::Deserialize)]
pub(super) struct EditUserRequest {
    email: Option<String>,
    name: Option<String>,
    password: Option<String>,
}

pub(super) async fn edit_user_info(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<EditUserRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    let token = extract_bearer(&headers)?;
    let id = verify_token(&token, &state.config.jwt)?;

    if payload.email.is_none()
        && payload.name.is_none()
        && payload.password.is_none()
    {
        return Err(AppError::bad_request(
            "missing required fields: email, name, or password",
        ));
    }

    let db = &state.db;
    let mut model: user::ActiveModel = user::Entity::find_by_id(id.clone())
        .one(db)
        .await?
        .ok_or_else(|| AppError::not_found("user not found"))?
        .into();

    if let Some(email) = payload.email {
        model.email = Set(email);
    }
    if let Some(name) = payload.name {
        model.name = Set(name);
    }
    if let Some(password) = payload.password {
        let salt = crate::security::generate_salt();
        let hash = crate::security::hash_password(&salt, &password);
        model.password_salt = Set(salt);
        model.password_hash = Set(hash);
    }

    model.update(db).await?;

    Ok(Json(MessageResponse {
        msg: "user updated".to_string(),
    }))
}

#[derive(Serialize)]
pub(super) struct UserInfoResponse {
    id: String,
    name: String,
    email: String,
    group: Option<String>,
}

#[derive(Serialize)]
pub(super) struct UserSummary {
    id: String,
    name: String,
    group: Option<String>,
}

#[derive(Serialize)]
pub(super) struct UserListResponse {
    page: u32,
    page_size: u32,
    users: Vec<UserSummary>,
}

#[derive(Serialize)]
pub(super) struct MessageResponse {
    msg: String,
}
