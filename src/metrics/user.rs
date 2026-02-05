use crate::entity::user;

use super::*;

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
