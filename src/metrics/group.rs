use super::*;
use sea_orm::QueryOrder;

use crate::entity::{group, member};

pub async fn count_groups(db: &DatabaseConnection) -> Result<u64, AppError> {
    Ok(group::Entity::find().count(db).await?)
}

pub async fn least_and_most_members(
    db: &DatabaseConnection,
) -> Result<(u8, u8), AppError> {
    let groups = group::Entity::find()
        .order_by_asc(group::Column::CodeName)
        .all(db)
        .await?;
    let mut least: Option<u8> = None;
    let mut most: Option<u8> = None;

    for g in groups {
        let current = member::Entity::find()
            .filter(member::Column::GroupCodeName.eq(&g.code_name))
            .count(db)
            .await? as u8;
        if least.as_ref().is_none_or(|v| current < *v) {
            least = Some(current);
        }
        if most.as_ref().is_none_or(|v| current > *v) {
            most = Some(current);
        }
    }
    Ok((least.unwrap_or_default(), most.unwrap_or_default()))
}
