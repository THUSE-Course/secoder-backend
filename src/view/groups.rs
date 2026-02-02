use super::*;
use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::db::{get_user, group_members};
use crate::entity::{group, invite, join, member as member_entity, user};
use crate::kubernetes::{group_acl, group_ns};
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, Set,
};

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
    student_id: String,
    name: String,
}

#[derive(Serialize)]
struct MemberSummary {
    student_id: String,
    name: String,
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
) -> Result<Json<serde_json::Value>, AppError> {
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

    group_acl(&state.config.kubernetes, &group_code_name, &student_id).await?;

    Ok(Json(json!({
        "msg": "user assigned to group successfully",
        "group": group
    })))
}

#[derive(Deserialize)]
pub(super) struct JoinGroupRequest {
    group_code_name: Option<String>,
}

pub(super) async fn join_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<JoinGroupRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let token = extract_bearer(&headers)?;
    let student_id = verify_token(&token, &state.config.jwt)?;
    let group_code_name = payload.group_code_name.ok_or_else(|| {
        AppError::bad_request("missing required field: group_code_name")
    })?;

    let db = &state.db;
    let group_exists = group::Entity::find_by_id(group_code_name.clone())
        .one(db)
        .await?;
    if group_exists.is_none() {
        return Err(AppError::not_found("group not found"));
    }

    let user = get_user(db, &student_id).await?;
    let user = user.ok_or_else(|| AppError::not_found("user not found"))?;
    if user.group_code_name.is_some() {
        return Err(AppError::bad_request("user already in a group"));
    }

    let pending = join::Entity::find()
        .filter(join::Column::RequesterId.eq(&student_id))
        .filter(join::Column::Typ.eq("join"))
        .count(db)
        .await?;
    if pending >= 5 {
        return Err(AppError::bad_request(
            "user has too many pending join requests",
        ));
    }

    let join_token = Uuid::new_v4().to_string();
    let request = join::ActiveModel {
        token: Set(join_token.clone()),
        group_code_name: Set(group_code_name.clone()),
        requester_id: Set(student_id.clone()),
        typ: Set("join".to_string()),
    };
    join::Entity::insert(request).exec(db).await?;

    Ok(Json(json!({
        "msg": "join request sent successfully",
        "join_token": join_token
    })))
}

#[derive(Deserialize)]
pub(super) struct TokenRequest {
    token: Option<String>,
}

pub(super) async fn accept_join_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let auth_token = extract_bearer(&headers)?;
    let leader_id = verify_token(&auth_token, &state.config.jwt)?;
    let join_token = payload.token.ok_or_else(|| {
        AppError::bad_request("missing required field: token")
    })?;

    let db = &state.db;
    let join_request = join::Entity::find_by_id(join_token.clone())
        .one(db)
        .await?
        .ok_or_else(|| AppError::bad_request("invalid join request token"))?;
    if join_request.typ != "join" {
        return Err(AppError::bad_request("invalid join request token"));
    }

    let group_row =
        group::Entity::find_by_id(join_request.group_code_name.clone())
            .one(db)
            .await?
            .ok_or_else(|| AppError::not_found("group no longer exists"))?;
    if group_row.leader_id != leader_id {
        return Err(AppError::forbidden(
            "only group leader can accept join requests",
        ));
    }

    let requester = get_user(db, &join_request.requester_id).await?;
    let requester =
        requester.ok_or_else(|| AppError::not_found("requester not found"))?;
    if requester.group_code_name.is_some() {
        return Err(AppError::bad_request("requester already in a group"));
    }

    let member = member_entity::ActiveModel {
        group_code_name: Set(group_row.code_name.clone()),
        student_id: Set(join_request.requester_id.clone()),
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
        user::Entity::find_by_id(join_request.requester_id.clone())
            .one(db)
            .await?
            .ok_or_else(|| AppError::not_found("user not found"))?
            .into();
    user_model.group_code_name = Set(Some(group_row.code_name.clone()));
    user_model.update(db).await?;

    join::Entity::delete_by_id(join_token.clone())
        .exec(db)
        .await?;

    let members = group_members(db, &group_row.code_name).await?;
    let group = GroupResponse {
        name: group_row.name,
        code_name: group_row.code_name.clone(),
        leader: group_row.leader_id,
        members,
    };
    let group_code_name = group_row.code_name;
    let invitee_id = join_request.requester_id;

    group_acl(&state.config.kubernetes, &group_code_name, &invitee_id).await?;

    Ok(Json(json!({
        "msg": "join request accepted successfully",
        "group": group
    })))
}

pub(super) async fn reject_join_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let auth_token = extract_bearer(&headers)?;
    let leader_id = verify_token(&auth_token, &state.config.jwt)?;
    let join_token = payload.token.ok_or_else(|| {
        AppError::bad_request("missing required field: token")
    })?;

    let db = &state.db;
    let join_request = join::Entity::find_by_id(join_token.clone())
        .one(db)
        .await?
        .ok_or_else(|| AppError::bad_request("invalid join request token"))?;
    if join_request.typ != "join" {
        return Err(AppError::bad_request("invalid join request token"));
    }

    let group = group::Entity::find_by_id(join_request.group_code_name.clone())
        .one(db)
        .await?
        .ok_or_else(|| AppError::not_found("group no longer exists"))?;
    if group.leader_id != leader_id {
        return Err(AppError::forbidden(
            "only group leader can reject join requests",
        ));
    }

    join::Entity::delete_by_id(join_token.clone())
        .exec(db)
        .await?;

    Ok(Json(json!({"msg": "join request rejected successfully"})))
}

#[derive(Deserialize)]
pub(super) struct InviteRequest {
    group_code_name: Option<String>,
    invitee_student_id: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct GroupInvitationQuery {
    group_code_name: Option<String>,
    page: Option<u32>,
    page_size: Option<u32>,
}

#[derive(Serialize)]
struct InvitationSummary {
    token: String,
    group_code_name: String,
    inviter_id: String,
    invitee_id: String,
}

pub(super) async fn invite_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<InviteRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
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

    Ok(Json(json!({
        "msg": "invitation sent successfully",
        "invitation_token": invitation_token
    })))
}

pub(super) async fn accept_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
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
    let group_code_name = group_row.code_name;
    let invitee_id = invite.invitee_id;

    group_acl(&state.config.kubernetes, &group_code_name, &invitee_id).await?;

    Ok(Json(json!({
        "msg": "invitation accepted successfully",
        "group": group
    })))
}

pub(super) async fn reject_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
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

    Ok(Json(json!({"msg": "invitation rejected successfully"})))
}

pub(super) async fn list_user_invitations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(pagination): Query<Pagination>,
) -> Result<Json<serde_json::Value>, AppError> {
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

    Ok(Json(json!({
        "page": page,
        "page_size": page_size,
        "invitations": invitations
    })))
}

pub(super) async fn list_group_invitations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<GroupInvitationQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
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

    Ok(Json(json!({
        "page": page,
        "page_size": page_size,
        "group_code_name": group_code_name,
        "invitations": invitations
    })))
}

#[derive(Deserialize)]
pub(super) struct CreateGroupRequest {
    name: Option<String>,
    code_name: Option<String>,
}

pub(super) async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateGroupRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let token = extract_bearer(&headers)?;
    let student_id = verify_token(&token, &state.config.jwt)?;
    let name = payload.name.ok_or_else(|| {
        AppError::bad_request("missing required fields: name, code_name")
    })?;
    let code_name = payload.code_name.ok_or_else(|| {
        AppError::bad_request("missing required fields: name, code_name")
    })?;
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

    group_ns(&state.config.kubernetes, &code_name, &student_id).await?;

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

    Ok(Json(json!({
        "msg": "group created successfully",
        "group": {
            "name": response_name,
            "code_name": response_code_name,
            "leader": student_id
        }
    })))
}

pub(super) async fn list_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(pagination): Query<Pagination>,
) -> Result<Json<serde_json::Value>, AppError> {
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

    Ok(Json(json!({
        "page": page,
        "page_size": page_size,
        "groups": groups
    })))
}
