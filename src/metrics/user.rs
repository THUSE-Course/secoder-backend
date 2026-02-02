use crate::entity::user;
use crate::error::AppError;
use sea_orm::DatabaseConnection;
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};

pub async fn count_users(db: &DatabaseConnection) -> Result<u64, AppError> {
    Ok(user::Entity::find().count(db).await?)
}

pub async fn count_ungrouped_users(
    db: &DatabaseConnection,
) -> Result<u64, AppError> {
    Ok(user::Entity::find()
        .filter(user::Column::GroupCodeName.is_null())
        .count(db)
        .await?)
}
