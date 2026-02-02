use super::*;
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::{get_user, group_members};
use crate::entity::{group, invite, member as member_entity, user};
use crate::kubernetes::group_ns;
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, Set, TransactionTrait,
};

#[derive(Serialize)]
pub(super) struct GroupResponse {
    name: String,
    code_name: String,
    leader: String,
    members: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct GroupSummaryResponse {
    name: String,
    code_name: String,
    leader: LeaderSummary,
    members: Vec<MemberSummary>,
}

#[derive(Serialize)]
pub(super) struct LeaderSummary {
    student_id: String,
    name: String,
}

#[derive(Serialize)]
pub(super) struct MemberSummary {
    student_id: String,
    name: String,
}

#[derive(Serialize)]
pub(super) struct AdminGroupAssignResponse {
    msg: String,
    group: GroupResponse,
}

#[derive(Serialize)]
pub(super) struct InviteUserResponse {
    msg: String,
    invitation_token: String,
}

#[derive(Serialize)]
pub(super) struct AcceptInvitationResponse {
    msg: String,
    group: GroupResponse,
}

#[derive(Serialize)]
pub(super) struct ListInvitationsResponse {
    page: u32,
    page_size: u32,
    invitations: Vec<InvitationSummary>,
}

#[derive(Serialize)]
pub(super) struct ListGroupInvitationsResponse {
    page: u32,
    page_size: u32,
    group_code_name: String,
    invitations: Vec<InvitationSummary>,
}

#[derive(Serialize)]
pub(super) struct CreateGroupResponse {
    msg: String,
    group: CreateGroupInfo,
}

#[derive(Serialize)]
pub(super) struct CreateGroupInfo {
    name: String,
    code_name: String,
    leader: String,
}

#[derive(Serialize)]
pub(super) struct ListGroupsResponse {
    page: u32,
    page_size: u32,
    groups: Vec<GroupSummaryResponse>,
}

#[derive(Deserialize)]
pub(super) struct GroupAssignRequest {
    group_code_name: Option<String>,
    student_id: Option<String>,
}

pub(super) async fn admin_group_assign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<GroupAssignRequest>,
) -> Result<Json<AdminGroupAssignResponse>, AppError> {
    let token = extract_bearer(&headers)?;
    let admin_id = verify_token(&token, &state.config.jwt)?;
    let group_code_name = payload.group_code_name.ok_or_else(|| {
        AppError::bad_request(
            "missing required fields: group_code_name, student_id",
        )
    })?;
    let student_id = payload.student_id.ok_or_else(|| {
        AppError::bad_request(
            "missing required fields: group_code_name, student_id",
        )
    })?;

    let db = &state.db;
    let group_row = group::Entity::find_by_id(group_code_name.clone())
        .one(db)
        .await?;
    let group_row =
        group_row.ok_or_else(|| AppError::not_found("group not found"))?;
    if group_row.leader_id != admin_id {
        return Err(AppError::forbidden(
            "only group leader can assign members",
        ));
    }

    let user = get_user(db, &student_id).await?;
    if user.is_none() {
        return Err(AppError::not_found("user not found"));
    }
    let group_value = user.unwrap().group_code_name;
    if group_value.is_some() {
        return Err(AppError::bad_request("user already in a group"));
    }

    let member = member_entity::ActiveModel {
        group_code_name: Set(group_row.code_name.clone()),
        student_id: Set(student_id.clone()),
    };
    member_entity::Entity::insert(member)
        .on_conflict(
            OnConflict::columns([
                member_entity::Column::GroupCodeName,
                member_entity::Column::StudentId,
            ])
            .do_nothing()
            .to_owned(),
        )
        .exec(db)
        .await?;

    let mut user_model: user::ActiveModel =
        user::Entity::find_by_id(student_id.clone())
            .one(db)
            .await?
            .ok_or_else(|| AppError::not_found("user not found"))?
            .into();
    user_model.group_code_name = Set(Some(group_row.code_name.clone()));
    user_model.update(db).await?;

    let members = group_members(db, &group_row.code_name).await?;
    let group = GroupResponse {
        name: group_row.name,
        code_name: group_row.code_name,
        leader: group_row.leader_id,
        members,
    };

    Ok(Json(AdminGroupAssignResponse {
        msg: "user assigned to group successfully".to_string(),
        group,
    }))
}

#[derive(Deserialize)]
pub(super) struct InviteRequest {
    group_code_name: Option<String>,
    invitee_student_id: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct TokenRequest {
    token: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct GroupInvitationQuery {
    group_code_name: Option<String>,
    page: Option<u32>,
    page_size: Option<u32>,
}

#[derive(Serialize)]
pub(super) struct InvitationSummary {
    token: String,
    group_code_name: String,
    inviter_id: String,
    invitee_id: String,
}

pub(super) async fn invite_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<InviteRequest>,
) -> Result<Json<InviteUserResponse>, AppError> {
    let auth_token = extract_bearer(&headers)?;
    let student_id = verify_token(&auth_token, &state.config.jwt)?;
    let group_code_name = payload.group_code_name.ok_or_else(|| {
        AppError::bad_request(
            "missing required fields: group_code_name, invitee_student_id",
        )
    })?;
    let invitee_student_id = payload.invitee_student_id.ok_or_else(|| {
        AppError::bad_request(
            "missing required fields: group_code_name, invitee_student_id",
        )
    })?;

    let db = &state.db;
    let group = group::Entity::find_by_id(group_code_name.clone())
        .one(db)
        .await?;
    let leader = match group {
        Some(group) => group.leader_id,
        None => return Err(AppError::not_found("group not found")),
    };
    if leader != student_id {
        return Err(AppError::forbidden("only group leader can invite users"));
    }

    let invitee = get_user(db, &invitee_student_id).await?;
    let invitee =
        invitee.ok_or_else(|| AppError::not_found("invitee not found"))?;
    if invitee.group_code_name.is_some() {
        return Err(AppError::bad_request("invitee already in a group"));
    }

    let pending = invite::Entity::find()
        .filter(invite::Column::InviteeId.eq(&invitee_student_id))
        .filter(invite::Column::Typ.eq("invite"))
        .count(db)
        .await?;
    if pending >= 5 {
        return Err(AppError::bad_request(
            "invitee has too many pending invitations",
        ));
    }

    let invitation_token = Uuid::new_v4().to_string();
    let invite = invite::ActiveModel {
        token: Set(invitation_token.clone()),
        group_code_name: Set(group_code_name.clone()),
        inviter_id: Set(student_id.clone()),
        invitee_id: Set(invitee_student_id.clone()),
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
    headers: HeaderMap,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<AcceptInvitationResponse>, AppError> {
    let auth_token = extract_bearer(&headers)?;
    let student_id = verify_token(&auth_token, &state.config.jwt)?;
    let token = payload.token.ok_or_else(|| {
        AppError::bad_request("missing required field: token")
    })?;

    let db = &state.db;
    let invite = invite::Entity::find_by_id(token.clone())
        .one(db)
        .await?
        .ok_or_else(|| AppError::bad_request("invalid invitation token"))?;
    if invite.typ != "invite" {
        return Err(AppError::bad_request("invalid invitation token"));
    }
    if invite.invitee_id != student_id {
        return Err(AppError::forbidden(
            "only the invited user can accept the invitation",
        ));
    }

    let group_row = group::Entity::find_by_id(invite.group_code_name.clone())
        .one(db)
        .await?
        .ok_or_else(|| AppError::not_found("group no longer exists"))?;

    let invitee = get_user(db, &invite.invitee_id).await?;
    let invitee =
        invitee.ok_or_else(|| AppError::not_found("user not found"))?;
    if invitee.group_code_name.is_some() {
        return Err(AppError::bad_request("user already in a group"));
    }

    let member = member_entity::ActiveModel {
        group_code_name: Set(group_row.code_name.clone()),
        student_id: Set(invite.invitee_id.clone()),
    };
    member_entity::Entity::insert(member)
        .on_conflict(
            OnConflict::columns([
                member_entity::Column::GroupCodeName,
                member_entity::Column::StudentId,
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
            .ok_or_else(|| AppError::not_found("user not found"))?
            .into();
    user_model.group_code_name = Set(Some(group_row.code_name.clone()));
    user_model.update(db).await?;

    invite::Entity::delete_by_id(token.clone()).exec(db).await?;

    let members = group_members(db, &group_row.code_name).await?;
    let group = GroupResponse {
        name: group_row.name,
        code_name: group_row.code_name.clone(),
        leader: group_row.leader_id,
        members,
    };
    let _group_code_name = group_row.code_name;
    let _invitee_id = invite.invitee_id;

    Ok(Json(AcceptInvitationResponse {
        msg: "invitation accepted successfully".to_string(),
        group,
    }))
}

pub(super) async fn reject_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<TokenRequest>,
) -> Result<StatusCode, AppError> {
    let auth_token = extract_bearer(&headers)?;
    let student_id = verify_token(&auth_token, &state.config.jwt)?;
    let token = payload.token.ok_or_else(|| {
        AppError::bad_request("missing required field: token")
    })?;

    let db = &state.db;
    let invitation =
        invite::Entity::find_by_id(token.clone())
            .one(db)
            .await?
            .ok_or_else(|| AppError::bad_request("invalid invitation token"))?;
    if invitation.typ != "invite" {
        return Err(AppError::bad_request("invalid invitation token"));
    }
    if invitation.invitee_id != student_id {
        return Err(AppError::forbidden(
            "only the invited user can reject the invitation",
        ));
    }
    invite::Entity::delete_by_id(token.clone()).exec(db).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn list_user_invitations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(pagination): Query<Pagination>,
) -> Result<Json<ListInvitationsResponse>, AppError> {
    let token = extract_bearer(&headers)?;
    let student_id = verify_token(&token, &state.config.jwt)?;
    let page = pagination.page.unwrap_or(1);
    let page_size = pagination.page_size.unwrap_or(20);
    let offset = (page.saturating_sub(1) * page_size) as u64;
    let limit = page_size as u64;

    let db = &state.db;
    let rows = invite::Entity::find()
        .filter(invite::Column::InviteeId.eq(&student_id))
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

pub(super) async fn list_group_invitations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<GroupInvitationQuery>,
) -> Result<Json<ListGroupInvitationsResponse>, AppError> {
    let token = extract_bearer(&headers)?;
    let leader_id = verify_token(&token, &state.config.jwt)?;
    let group_code_name = query.group_code_name.ok_or_else(|| {
        AppError::bad_request("missing required field: group_code_name")
    })?;
    let page = query.page.unwrap_or(1);
    let page_size = query.page_size.unwrap_or(20);
    let offset = (page.saturating_sub(1) * page_size) as u64;
    let limit = page_size as u64;

    let db = &state.db;
    let group_row = group::Entity::find_by_id(group_code_name.clone())
        .one(db)
        .await?
        .ok_or_else(|| AppError::not_found("group not found"))?;
    if group_row.leader_id != leader_id {
        return Err(AppError::forbidden(
            "only group leader can view group invitations",
        ));
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
pub(super) struct CreateGroupRequest {
    name: Option<String>,
    code_name: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct DeleteGroupRequest {
    group_code_name: Option<String>,
}

fn validate_group_code_name(value: &str) -> Result<(), AppError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return Err(AppError::bad_request(
            "group code name must be 1-63 characters",
        ));
    }
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_alnum(bytes[0]) || !is_alnum(bytes[bytes.len() - 1]) {
        return Err(AppError::bad_request(
            "group code name must start and end with a lowercase letter or digit",
        ));
    }
    for &b in bytes {
        if is_alnum(b) || b == b'-' {
            continue;
        }
        return Err(AppError::bad_request(
            "group code name must contain only lowercase letters, digits, or '-'",
        ));
    }
    Ok(())
}

pub(super) async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateGroupRequest>,
) -> Result<Json<CreateGroupResponse>, AppError> {
    let token = extract_bearer(&headers)?;
    let student_id = verify_token(&token, &state.config.jwt)?;
    let name = payload.name.ok_or_else(|| {
        AppError::bad_request("missing required fields: name, code_name")
    })?;
    let code_name = payload.code_name.ok_or_else(|| {
        AppError::bad_request("missing required fields: name, code_name")
    })?;
    validate_group_code_name(&code_name)?;
    let response_name = name.clone();
    let response_code_name = code_name.clone();

    let db = &state.db;
    let user = get_user(db, &student_id).await?;
    let user = user.ok_or_else(|| AppError::not_found("user not found"))?;
    if user.group_code_name.is_some() {
        return Err(AppError::bad_request("user already in a group"));
    }

    let existing = group::Entity::find_by_id(code_name.clone()).one(db).await?;
    if existing.is_some() {
        return Err(AppError::bad_request("group code name already exists"));
    }

    group_ns(&code_name).await?;

    let group = group::ActiveModel {
        code_name: Set(code_name.clone()),
        name: Set(name.clone()),
        leader_id: Set(student_id.clone()),
    };
    group::Entity::insert(group).exec(db).await?;

    let member = member_entity::ActiveModel {
        group_code_name: Set(code_name.clone()),
        student_id: Set(student_id.clone()),
    };
    member_entity::Entity::insert(member)
        .on_conflict(
            OnConflict::columns([
                member_entity::Column::GroupCodeName,
                member_entity::Column::StudentId,
            ])
            .do_nothing()
            .to_owned(),
        )
        .exec(db)
        .await?;

    let mut user_model: user::ActiveModel =
        user::Entity::find_by_id(student_id.clone())
            .one(db)
            .await?
            .ok_or_else(|| AppError::not_found("user not found"))?
            .into();
    user_model.group_code_name = Set(Some(code_name.clone()));
    user_model.update(db).await?;

    Ok(Json(CreateGroupResponse {
        msg: "group created successfully".to_string(),
        group: CreateGroupInfo {
            name: response_name,
            code_name: response_code_name,
            leader: student_id,
        },
    }))
}

pub(super) async fn delete_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<DeleteGroupRequest>,
) -> Result<StatusCode, AppError> {
    let token = extract_bearer(&headers)?;
    let leader_id = verify_token(&token, &state.config.jwt)?;
    let group_code_name = payload.group_code_name.ok_or_else(|| {
        AppError::bad_request("missing required field: group_code_name")
    })?;

    let db = &state.db;
    let group_row = group::Entity::find_by_id(group_code_name.clone())
        .one(db)
        .await?
        .ok_or_else(|| AppError::not_found("group not found"))?;
    if group_row.leader_id != leader_id {
        return Err(AppError::forbidden(
            "only group leader can delete the group",
        ));
    }

    let txn = db.begin().await?;
    member_entity::Entity::delete_many()
        .filter(member_entity::Column::GroupCodeName.eq(&group_code_name))
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

pub(super) async fn list_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(pagination): Query<Pagination>,
) -> Result<Json<ListGroupsResponse>, AppError> {
    let token = extract_bearer(&headers)?;
    let _student_id = verify_token(&token, &state.config.jwt)?;
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

        let member_rows = member_entity::Entity::find()
            .filter(
                member_entity::Column::GroupCodeName.eq(row.code_name.clone()),
            )
            .order_by_asc(member_entity::Column::StudentId)
            .all(db)
            .await?;
        let mut members = Vec::new();
        for member in member_rows {
            let member_name =
                user::Entity::find_by_id(member.student_id.clone())
                    .one(db)
                    .await?
                    .map(|user| user.name)
                    .unwrap_or_else(|| format!("user {}", member.student_id));
            members.push(MemberSummary {
                student_id: member.student_id,
                name: member_name,
            });
        }

        groups.push(GroupSummaryResponse {
            name: row.name,
            code_name: row.code_name,
            leader: LeaderSummary {
                student_id: row.leader_id,
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
