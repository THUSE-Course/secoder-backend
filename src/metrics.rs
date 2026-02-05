use super::error::AppError;

use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
};

pub mod group;
pub mod invite;
pub mod user;

pub async fn render_metrics(
    db: &DatabaseConnection,
) -> Result<String, AppError> {
    let users_total = user::count_users(db).await?;
    let users_ungrouped_total = user::count_ungrouped_users(db).await?;
    let groups_total = group::count_groups(db).await?;
    let invitations_pending_total =
        invite::count_pending_invitations(db).await?;

    Ok(format!(
        "# HELP secoder_users_total Total number of users.\n\
# TYPE secoder_users_total gauge\n\
secoder_users_total {users}\n\
# HELP secoder_users_ungrouped_total Total number of users not in a group.\n\
# TYPE secoder_users_ungrouped_total gauge\n\
secoder_users_ungrouped_total {ungrouped}\n\
# HELP secoder_groups_total Total number of groups.\n\
# TYPE secoder_groups_total gauge\n\
secoder_groups_total {groups}\n\
# HELP secoder_invitations_pending_total Total number of pending invitations.\n\
# TYPE secoder_invitations_pending_total gauge\n\
secoder_invitations_pending_total {pending}\n",
        users = users_total,
        ungrouped = users_ungrouped_total,
        groups = groups_total,
        pending = invitations_pending_total
    ))
}
