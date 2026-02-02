use crate::entity::group;
use crate::error::AppError;
use sea_orm::DatabaseConnection;
use sea_orm::{EntityTrait, PaginatorTrait};

pub async fn count_groups(db: &DatabaseConnection) -> Result<u64, AppError> {
    Ok(group::Entity::find().count(db).await?)
}
