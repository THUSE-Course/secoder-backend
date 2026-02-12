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
    let (least_group, most_group) = group::least_and_most_members(db).await?;
    let invitations_pending_total =
        invite::count_pending_invitations(db).await?;
    Ok(format!(
        "# HELP secoder_users Total number of users.\n\
# TYPE secoder_users gauge\n\
secoder_users {users}\n\
# HELP secoder_users_ungrouped Total number of users not in a group.\n\
# TYPE secoder_users_ungrouped gauge\n\
secoder_users_ungrouped {ungrouped}\n\
# HELP secoder_groups Total number of groups.\n\
# TYPE secoder_groups gauge\n\
secoder_groups {groups}\n\
# HELP secoder_group_members_least Number of members in the least man-powered group.\n\
# TYPE secoder_group_members_least gauge\n\
secoder_group_members_least {least_group}\n\
# HELP secoder_group_members_most Number of members in the most man-powered group.\n\
# TYPE secoder_group_members_most gauge\n\
secoder_group_members_most {most_group}\n\
# HELP secoder_invitations_pending Total number of pending invitations.\n\
# TYPE secoder_invitations_pending gauge\n\
secoder_invitations_pending {pending}\n",
        users = users_total,
        ungrouped = users_ungrouped_total,
        groups = groups_total,
        least_group = least_group,
        most_group = most_group,
        pending = invitations_pending_total
    ))
}
