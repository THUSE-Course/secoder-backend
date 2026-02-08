use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, Set, TransactionTrait,
    sea_query::{Expr, OnConflict},
};
use uuid::Uuid;

use super::*;
use crate::{
    db::{get_user, group_members},
    entity::{group, invite, member, user},
    kubernetes::{sanitize_k8s_name, update_group_tenant_label},
};

fn bad_request(msg: &str) -> AppError {
    AppError::adhoc(StatusCode::BAD_REQUEST, anyhow::anyhow!(msg.to_string()))
}

fn forbidden(msg: &str) -> AppError {
    AppError::adhoc(StatusCode::FORBIDDEN, anyhow::anyhow!(msg.to_string()))
}

fn not_found(msg: &str) -> AppError {
    AppError::adhoc(StatusCode::NOT_FOUND, anyhow::anyhow!(msg.to_string()))
}

fn ensure_leader_in_members(leader_id: &str, members: &mut Vec<String>) {
    if members.iter().any(|member| member == leader_id) {
        return;
    }
    members.insert(0, leader_id.to_string());
}

#[derive(Serialize)]
struct GroupResponse {
    name: String,
    code_name: String,
    leader: String,
    members: Vec<String>,
}

#[derive(Serialize)]
struct GroupSummaryResponse {
    name: String,
    code_name: String,
    leader: LeaderSummary,
    members: Vec<MemberSummary>,
}

#[derive(Serialize)]
struct LeaderSummary {
    id: String,
    name: String,
}

#[derive(Serialize)]
struct MemberSummary {
    id: String,
    name: String,
}

#[derive(Serialize)]
pub struct InviteUserResponse {
    msg: String,
    invitation_token: String,
}

#[derive(Serialize)]
pub struct AcceptInvitationResponse {
    msg: String,
    group: GroupResponse,
}

#[derive(Serialize)]
pub struct ListInvitationsResponse {
    page: u32,
    page_size: u32,
    invitations: Vec<InvitationSummary>,
}

#[derive(Serialize)]
pub struct ListGroupInvitationsResponse {
    page: u32,
    page_size: u32,
    group_code_name: String,
    invitations: Vec<InvitationSummary>,
}

#[derive(Serialize)]
pub struct CreateGroupResponse {
    msg: String,
    group: CreateGroupInfo,
}

#[derive(Serialize)]
pub struct CreateGroupInfo {
    name: String,
    code_name: String,
    leader: String,
}

#[derive(Serialize)]
pub struct ListGroupsResponse {
    page: u32,
    page_size: u32,
    groups: Vec<GroupSummaryResponse>,
}

#[derive(Deserialize)]
pub struct InviteRequest {
    group_code_name: String,
    invitee_id: String,
}

#[derive(Deserialize)]
pub struct TokenRequest {
    token: String,
}

#[derive(Deserialize)]
pub struct GroupInvitationQuery {
    group_code_name: String,
    page: Option<u32>,
    page_size: Option<u32>,
}

#[derive(Serialize)]
pub struct InvitationSummary {
    token: String,
    group_code_name: String,
    inviter_id: String,
    invitee_id: String,
}

pub async fn invite_user(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<InviteRequest>,
) -> Result<Json<InviteUserResponse>, AppError> {
    super::ensure_not_readonly(&state.db).await?;
    let id = claims.id;
    let group_code_name = payload.group_code_name;
    let invitee_id = payload.invitee_id;

    let db = &state.db;
    let group = group::Entity::find_by_id(group_code_name.clone())
        .one(db)
        .await?;
    let leader = match group {
        Some(group) => group.leader_id,
        None => return Err(not_found("group not found")),
    };
    if leader != id {
        return Err(forbidden("only group leader can invite users"));
    }

    let invitee = get_user(db, &invitee_id).await?;
    let invitee = invitee.ok_or_else(|| not_found("invitee not found"))?;
    if invitee.group_code_name.is_some() {
        return Err(bad_request("invitee already in a group"));
    }

    let pending = invite::Entity::find()
        .filter(invite::Column::InviteeId.eq(&invitee_id))
        .filter(invite::Column::Typ.eq("invite"))
        .count(db)
        .await?;
    if pending >= 5 {
        return Err(bad_request("invitee has too many pending invitations"));
    }

    let invitation_token = Uuid::new_v4().to_string();
    let invite = invite::ActiveModel {
        token: Set(invitation_token.clone()),
        group_code_name: Set(group_code_name.clone()),
        inviter_id: Set(id.clone()),
        invitee_id: Set(invitee_id.clone()),
        typ: Set("invite".to_string()),
    };
    invite::Entity::insert(invite).exec(db).await?;

    Ok(Json(InviteUserResponse {
        msg: "invitation sent successfully".to_string(),
        invitation_token,
    }))
}

pub(super) async fn accept_invitation(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<AcceptInvitationResponse>, AppError> {
    super::ensure_not_readonly(&state.db).await?;
    let id = claims.id;
    let token = payload.token;

    let db = &state.db;
    let invite = invite::Entity::find_by_id(token.clone())
        .one(db)
        .await?
        .ok_or_else(|| bad_request("invalid invitation token"))?;
    if invite.typ != "invite" {
        return Err(bad_request("invalid invitation token"));
    }
    if invite.invitee_id != id {
        return Err(forbidden(
            "only the invited user can accept the invitation",
        ));
    }

    let group_row = group::Entity::find_by_id(invite.group_code_name.clone())
        .one(db)
        .await?
        .ok_or_else(|| not_found("group no longer exists"))?;

    let invitee = get_user(db, &invite.invitee_id).await?;
    let invitee = invitee.ok_or_else(|| not_found("user not found"))?;
    if invitee.group_code_name.is_some() {
        return Err(bad_request("user already in a group"));
    }

    let member = member::ActiveModel {
        group_code_name: Set(group_row.code_name.clone()),
        id: Set(invite.invitee_id.clone()),
    };
    member::Entity::insert(member)
        .on_conflict(
            OnConflict::columns([
                member::Column::GroupCodeName,
                member::Column::Id,
            ])
            .do_nothing()
            .to_owned(),
        )
        .exec(db)
        .await?;

    let mut user_model: user::ActiveModel =
        user::Entity::find_by_id(invite.invitee_id.clone())
            .one(db)
            .await?
            .ok_or_else(|| not_found("user not found"))?
            .into();
    user_model.group_code_name = Set(Some(group_row.code_name.clone()));
    user_model.update(db).await?;

    invite::Entity::delete_by_id(token.clone()).exec(db).await?;

    let members = group_members(db, &group_row.code_name).await?;
    let mut label_members = members.clone();
    ensure_leader_in_members(&group_row.leader_id, &mut label_members);
    update_group_tenant_label(
        &state.kube,
        &group_row.code_name,
        &state.config.rbac,
        &label_members,
    )
    .await?;
    let group = GroupResponse {
        name: group_row.name,
        code_name: group_row.code_name.clone(),
        leader: group_row.leader_id,
        members,
    };
    let _invitee_id = invite.invitee_id;

    Ok(Json(AcceptInvitationResponse {
        msg: "invitation accepted successfully".to_string(),
        group,
    }))
}

pub async fn reject_invitation(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<TokenRequest>,
) -> Result<StatusCode, AppError> {
    super::ensure_not_readonly(&state.db).await?;
    let id = claims.id;
    let token = payload.token;

    let db = &state.db;
    let invitation = invite::Entity::find_by_id(token.clone())
        .one(db)
        .await?
        .ok_or_else(|| bad_request("invalid invitation token"))?;
    if invitation.typ != "invite" {
        return Err(bad_request("invalid invitation token"));
    }
    if invitation.invitee_id != id {
        return Err(forbidden(
            "only the invited user can reject the invitation",
        ));
    }
    invite::Entity::delete_by_id(token.clone()).exec(db).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_user_invitations(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<ListInvitationsResponse>, AppError> {
    let id = claims.id;
    let page = pagination.page.unwrap_or(1);
    let page_size = pagination.page_size.unwrap_or(20);
    let offset = (page.saturating_sub(1) * page_size) as u64;
    let limit = page_size as u64;

    let db = &state.db;
    let rows = invite::Entity::find()
        .filter(invite::Column::InviteeId.eq(&id))
        .filter(invite::Column::Typ.eq("invite"))
        .order_by_asc(invite::Column::GroupCodeName)
        .order_by_asc(invite::Column::InviterId)
        .offset(offset)
        .limit(limit)
        .all(db)
        .await?;

    let invitations = rows
        .into_iter()
        .map(|row| InvitationSummary {
            token: row.token,
            group_code_name: row.group_code_name,
            inviter_id: row.inviter_id,
            invitee_id: row.invitee_id,
        })
        .collect::<Vec<_>>();

    Ok(Json(ListInvitationsResponse {
        page,
        page_size,
        invitations,
    }))
}

pub async fn list_group_invitations(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(query): Query<GroupInvitationQuery>,
) -> Result<Json<ListGroupInvitationsResponse>, AppError> {
    let leader_id = claims.id;
    let group_code_name = query.group_code_name;
    let page = query.page.unwrap_or(1);
    let page_size = query.page_size.unwrap_or(20);
    let offset = (page.saturating_sub(1) * page_size) as u64;
    let limit = page_size as u64;

    let db = &state.db;
    let group_row = group::Entity::find_by_id(group_code_name.clone())
        .one(db)
        .await?
        .ok_or_else(|| not_found("group not found"))?;
    if group_row.leader_id != leader_id {
        return Err(forbidden("only group leader can view group invitations"));
    }

    let rows = invite::Entity::find()
        .filter(invite::Column::GroupCodeName.eq(&group_code_name))
        .filter(invite::Column::Typ.eq("invite"))
        .order_by_asc(invite::Column::InviteeId)
        .order_by_asc(invite::Column::Token)
        .offset(offset)
        .limit(limit)
        .all(db)
        .await?;

    let invitations = rows
        .into_iter()
        .map(|row| InvitationSummary {
            token: row.token,
            group_code_name: row.group_code_name,
            inviter_id: row.inviter_id,
            invitee_id: row.invitee_id,
        })
        .collect::<Vec<_>>();

    Ok(Json(ListGroupInvitationsResponse {
        page,
        page_size,
        group_code_name,
        invitations,
    }))
}

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    name: String,
    code_name: String,
}

#[derive(Deserialize)]
pub struct DeleteGroupRequest {
    group_code_name: String,
}

#[derive(Deserialize)]
pub struct EditGroupRequest {
    group_code_name: String,
    name: String,
}

pub async fn create_group(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreateGroupRequest>,
) -> Result<Json<CreateGroupResponse>, AppError> {
    super::ensure_not_readonly(&state.db).await?;
    let id = claims.id;
    let name = payload.name;
    let code_name = sanitize_k8s_name(&payload.code_name);
    let response_name = name.clone();
    let response_code_name = code_name.clone();

    let db = &state.db;
    let user = get_user(db, &id).await?;
    let user = user.ok_or_else(|| not_found("user not found"))?;
    if user.group_code_name.is_some() {
        return Err(bad_request("user already in a group"));
    }

    let existing = group::Entity::find_by_id(code_name.clone()).one(db).await?;
    if existing.is_some() {
        return Err(bad_request("group code name already exists"));
    }

    let group = group::ActiveModel {
        code_name: Set(code_name.clone()),
        name: Set(name.clone()),
        leader_id: Set(id.clone()),
    };
    group::Entity::insert(group).exec(db).await?;

    let member = member::ActiveModel {
        group_code_name: Set(code_name.clone()),
        id: Set(id.clone()),
    };
    member::Entity::insert(member)
        .on_conflict(
            OnConflict::columns([
                member::Column::GroupCodeName,
                member::Column::Id,
            ])
            .do_nothing()
            .to_owned(),
        )
        .exec(db)
        .await?;

    let mut user_model: user::ActiveModel =
        user::Entity::find_by_id(id.clone())
            .one(db)
            .await?
            .ok_or_else(|| not_found("user not found"))?
            .into();
    user_model.group_code_name = Set(Some(code_name.clone()));
    user_model.update(db).await?;

    update_group_tenant_label(
        &state.kube,
        &code_name,
        &state.config.rbac,
        std::slice::from_ref(&id),
    )
    .await?;

    Ok(Json(CreateGroupResponse {
        msg: "group created successfully".to_string(),
        group: CreateGroupInfo {
            name: response_name,
            code_name: response_code_name,
            leader: id,
        },
    }))
}

pub async fn delete_group(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<DeleteGroupRequest>,
) -> Result<StatusCode, AppError> {
    super::ensure_not_readonly(&state.db).await?;
    let leader_id = claims.id;
    let group_code_name = payload.group_code_name;

    let db = &state.db;
    let group_row = group::Entity::find_by_id(group_code_name.clone())
        .one(db)
        .await?
        .ok_or_else(|| not_found("group not found"))?;
    if group_row.leader_id != leader_id {
        return Err(forbidden("only group leader can delete the group"));
    }
    let txn = db.begin().await?;
    member::Entity::delete_many()
        .filter(member::Column::GroupCodeName.eq(&group_code_name))
        .exec(&txn)
        .await?;
    user::Entity::update_many()
        .col_expr(user::Column::GroupCodeName, Expr::value(None::<String>))
        .filter(user::Column::GroupCodeName.eq(&group_code_name))
        .exec(&txn)
        .await?;
    invite::Entity::delete_many()
        .filter(invite::Column::GroupCodeName.eq(&group_code_name))
        .filter(invite::Column::Typ.eq("invite"))
        .exec(&txn)
        .await?;
    group::Entity::delete_by_id(group_code_name.clone())
        .exec(&txn)
        .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn edit_group(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<EditGroupRequest>,
) -> Result<(), AppError> {
    super::ensure_not_readonly(&state.db).await?;
    let leader_id = claims.id;
    let group_code_name = payload.group_code_name;
    let name = payload.name;

    let db = &state.db;
    let group_row = group::Entity::find_by_id(group_code_name.clone())
        .one(db)
        .await?
        .ok_or_else(|| not_found("group not found"))?;
    if group_row.leader_id != leader_id {
        return Err(forbidden("only group leader can edit the group"));
    }
    let mut model: group::ActiveModel = group_row.into();
    model.name = Set(name.clone());
    model.update(db).await?;

    Ok(())
}

pub async fn list_groups(
    State(state): State<AppState>,
    Extension(_claims): Extension<Claims>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<ListGroupsResponse>, AppError> {
    let page = pagination.page.unwrap_or(1);
    let page_size = pagination.page_size.unwrap_or(20);
    let offset = (page.saturating_sub(1) * page_size) as u64;
    let limit = page_size as u64;

    let db = &state.db;
    let rows = group::Entity::find()
        .order_by_asc(group::Column::CodeName)
        .offset(offset)
        .limit(limit)
        .all(db)
        .await?;

    let mut groups = Vec::new();
    for row in rows {
        let leader_name = user::Entity::find_by_id(row.leader_id.clone())
            .one(db)
            .await?
            .map(|leader| leader.name)
            .unwrap_or_else(|| format!("user {}", row.leader_id));

        let member_rows = member::Entity::find()
            .filter(member::Column::GroupCodeName.eq(row.code_name.clone()))
            .order_by_asc(member::Column::Id)
            .all(db)
            .await?;
        let mut members = Vec::new();
        for member in member_rows {
            let member_name = user::Entity::find_by_id(member.id.clone())
                .one(db)
                .await?
                .map(|user| user.name)
                .unwrap_or_else(|| format!("user {}", member.id));
            members.push(MemberSummary {
                id: member.id,
                name: member_name,
            });
        }

        groups.push(GroupSummaryResponse {
            name: row.name,
            code_name: row.code_name,
            leader: LeaderSummary {
                id: row.leader_id,
                name: leader_name,
            },
            members,
        });
    }

    Ok(Json(ListGroupsResponse {
        page,
        page_size,
        groups,
    }))
}
