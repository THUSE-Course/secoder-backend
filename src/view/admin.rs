use sea_orm::{ActiveModelTrait, EntityTrait, Set};

use super::*;
use crate::entity::{admin, user};

fn forbidden() -> AppError {
    AppError::adhoc(StatusCode::FORBIDDEN, anyhow::anyhow!("sudo required"))
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
