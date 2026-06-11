use std::collections::BTreeMap;

use sea_orm::{ActiveModelTrait, EntityTrait, QueryOrder, Set};

use super::*;
use crate::entity::{admin, user};

fn forbidden() -> AppError {
    AppError::adhoc(StatusCode::FORBIDDEN, anyhow::anyhow!("sudo required"))
}

fn bad_request(msg: &str) -> AppError {
    AppError::adhoc(StatusCode::BAD_REQUEST, anyhow::anyhow!(msg.to_string()))
}

#[derive(Deserialize)]
pub struct UpdateReadonlyRequest {
    readonly: bool,
}

pub async fn update_readonly(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<UpdateReadonlyRequest>,
) -> Result<StatusCode, AppError> {
    if !claims.sudo {
        return Err(forbidden());
    }

    let db = &state.db;
    let existing = admin::Entity::find_by_id(1).one(db).await?;
    let model = match existing {
        Some(row) => {
            let mut model: admin::ActiveModel = row.into();
            model.readonly = Set(payload.readonly);
            model
        }
        None => admin::ActiveModel {
            id: Set(1),
            readonly: Set(payload.readonly),
        },
    };
    model.save(db).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct ImpersonateRequest {
    id: String,
}

pub async fn impersonate(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<ImpersonateRequest>,
) -> Result<String, AppError> {
    if !claims.sudo {
        return Err(forbidden());
    }
    if state.users.is_banned(&payload.id) {
        return Err(AppError::adhoc(
            StatusCode::FORBIDDEN,
            anyhow::anyhow!("user is banned"),
        ));
    }
    let db = &state.db;
    let user = user::Entity::find_by_id(&payload.id).one(db).await?.ok_or(
        AppError::adhoc(
            StatusCode::NOT_FOUND,
            anyhow::anyhow!("user {} not found", payload.id),
        ),
    )?;
    let token = Claims::from((&user.id, user.email, user.name, user.sudo));
    { &token }.try_into()
}

#[derive(Serialize)]
pub struct AdminUserAccessResponse {
    page: u32,
    page_size: u32,
    total: u64,
    users: Vec<AdminUserAccessSummary>,
}

#[derive(Serialize)]
pub struct AdminUserAccessSummary {
    id: String,
    banned: bool,
    registered: bool,
    name: Option<String>,
    email: Option<String>,
    sudo: bool,
    group: Option<String>,
}

#[derive(Deserialize)]
pub struct AddUserAccessRequest {
    id: String,
    password: String,
}

#[derive(Deserialize)]
pub struct BanUserAccessRequest {
    id: String,
}

#[derive(Deserialize)]
pub struct UnbanUserAccessRequest {
    id: String,
}

pub async fn list_user_access(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<AdminUserAccessResponse>, AppError> {
    if !claims.sudo {
        return Err(forbidden());
    }

    let page = pagination.page.unwrap_or(1).max(1);
    let page_size = pagination.page_size.unwrap_or(20).max(1);
    let offset = (page.saturating_sub(1) * page_size) as usize;
    let limit = page_size as usize;
    let mut users_by_id = BTreeMap::new();

    // TODO(online-upgrade): this endpoint temporarily returns the union of the
    // allowlist and registered DB users so accounts missing from legacy
    // users.json remain visible after a live upgrade. Once production
    // users.json has been normalized by the new admin controls, this can go
    // back to listing only access-store entries.
    for entry in state.users.list() {
        users_by_id.insert(
            entry.id.clone(),
            AdminUserAccessSummary {
                id: entry.id,
                banned: entry.banned,
                registered: false,
                name: None,
                email: None,
                sudo: false,
                group: None,
            },
        );
    }

    let registered_rows = user::Entity::find()
        .order_by_asc(user::Column::Id)
        .all(&state.db)
        .await?;
    for row in registered_rows {
        users_by_id
            .entry(row.id.clone())
            .and_modify(|summary| {
                summary.registered = true;
                summary.name = Some(row.name.clone());
                summary.email = Some(row.email.clone());
                summary.sudo = row.sudo;
                summary.group = row.group_code_name.clone();
            })
            .or_insert(AdminUserAccessSummary {
                id: row.id,
                banned: false,
                registered: true,
                name: Some(row.name),
                email: Some(row.email),
                sudo: row.sudo,
                group: row.group_code_name,
            });
    }

    let total = users_by_id.len() as u64;
    let users = users_by_id
        .into_values()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();

    Ok(Json(AdminUserAccessResponse {
        page,
        page_size,
        total,
        users,
    }))
}

pub async fn add_user_access(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<AddUserAccessRequest>,
) -> Result<StatusCode, AppError> {
    if !claims.sudo {
        return Err(forbidden());
    }
    super::ensure_not_readonly(&state.db).await?;

    let id = payload.id.trim();
    let password = payload.password.trim();
    if id.is_empty() || password.is_empty() {
        return Err(bad_request("id and password are required"));
    }

    state
        .users
        .add_or_unban(id.to_string(), password.to_string())?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn ban_user_access(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<BanUserAccessRequest>,
) -> Result<StatusCode, AppError> {
    if !claims.sudo {
        return Err(forbidden());
    }
    super::ensure_not_readonly(&state.db).await?;

    let id = payload.id.trim();
    if id.is_empty() {
        return Err(bad_request("id is required"));
    }
    if id == claims.id {
        return Err(AppError::adhoc(
            StatusCode::FORBIDDEN,
            anyhow::anyhow!("cannot ban current user"),
        ));
    }

    let registered = user::Entity::find_by_id(id.to_string())
        .one(&state.db)
        .await?;
    if registered.as_ref().map(|user| user.sudo).unwrap_or(false) {
        return Err(AppError::adhoc(
            StatusCode::FORBIDDEN,
            anyhow::anyhow!("cannot ban sudo user"),
        ));
    }
    if registered.is_none() && !state.users.contains(id) {
        return Err(AppError::adhoc(
            StatusCode::NOT_FOUND,
            anyhow::anyhow!("user {} not found", id),
        ));
    }

    state.users.ban(id)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn unban_user_access(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<UnbanUserAccessRequest>,
) -> Result<StatusCode, AppError> {
    if !claims.sudo {
        return Err(forbidden());
    }
    super::ensure_not_readonly(&state.db).await?;

    let id = payload.id.trim();
    if id.is_empty() {
        return Err(bad_request("id is required"));
    }

    let registered = user::Entity::find_by_id(id.to_string())
        .one(&state.db)
        .await?;
    if registered.is_none() && !state.users.contains(id) {
        return Err(AppError::adhoc(
            StatusCode::NOT_FOUND,
            anyhow::anyhow!("user {} not found", id),
        ));
    }

    let updated = state.users.unban(id)?;
    if !updated {
        return Ok(StatusCode::NO_CONTENT);
    }
    Ok(StatusCode::NO_CONTENT)
}
