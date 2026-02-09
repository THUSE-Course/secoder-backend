use sea_orm::{ActiveModelTrait, EntityTrait, QueryOrder, QuerySelect, Set};

use super::*;
use crate::db::get_user;
use crate::entity::user;

pub async fn get_user_info(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<UserInfoResponse>, AppError> {
    let db = &state.db;
    let user = get_user(db, &claims.id).await?.ok_or_else(|| {
        AppError::adhoc(
            StatusCode::NOT_FOUND,
            anyhow::anyhow!("user not found"),
        )
    })?;

    Ok(Json(UserInfoResponse {
        id: user.id,
        name: user.name,
        email: user.email,
        sudo: user.sudo,
        group: user.group_code_name,
    }))
}

pub async fn list_users(
    State(state): State<AppState>,
    Extension(_claims): Extension<Claims>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<UserListResponse>, AppError> {
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
            email: row.email,
            sudo: row.sudo,
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
pub struct EditUserRequest {
    email: Option<String>,
    name: Option<String>,
    password: Option<String>,
}

pub async fn edit_user_info(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<EditUserRequest>,
) -> Result<(), AppError> {
    super::ensure_not_readonly(&state.db).await?;
    if payload.email.is_none()
        && payload.name.is_none()
        && payload.password.is_none()
    {
        return Err(AppError::adhoc(
            StatusCode::BAD_REQUEST,
            anyhow::anyhow!(
                "missing required fields: email, name, or password"
            ),
        ));
    }

    let db = &state.db;
    let mut model: user::ActiveModel =
        user::Entity::find_by_id(claims.id.clone())
            .one(db)
            .await?
            .ok_or_else(|| {
                AppError::adhoc(
                    StatusCode::NOT_FOUND,
                    anyhow::anyhow!("user not found"),
                )
            })?
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

    Ok(())
}

#[derive(Serialize)]
pub struct UserInfoResponse {
    id: String,
    name: String,
    email: String,
    sudo: bool,
    group: Option<String>,
}

#[derive(Serialize)]
pub struct UserSummary {
    id: String,
    name: String,
    email: String,
    sudo: bool,
    group: Option<String>,
}

#[derive(Serialize)]
pub struct UserListResponse {
    page: u32,
    page_size: u32,
    users: Vec<UserSummary>,
}
