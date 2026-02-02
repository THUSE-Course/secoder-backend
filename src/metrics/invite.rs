use crate::entity::invite;
use crate::error::AppError;
use sea_orm::DatabaseConnection;
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};

pub async fn count_pending_invitations(
    db: &DatabaseConnection,
) -> Result<u64, AppError> {
    Ok(invite::Entity::find()
        .filter(invite::Column::Typ.eq("invite"))
        .count(db)
        .await?)
}
