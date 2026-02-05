use super::*;

use crate::entity::group;

pub async fn count_groups(db: &DatabaseConnection) -> Result<u64, AppError> {
    Ok(group::Entity::find().count(db).await?)
}
