use super::*;

use crate::entity::invite;

pub async fn count_pending_invitations(
    db: &DatabaseConnection,
) -> Result<u64, AppError> {
    Ok(invite::Entity::find()
        .filter(invite::Column::Typ.eq("invite"))
        .count(db)
        .await?)
}
