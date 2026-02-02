use super::*;
use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
};
use serde_json::json;
use std::collections::BTreeMap;

use crate::db::{get_user, group_members};
use crate::entity::{group, invite, join, user};
use sea_orm::{EntityTrait, QueryOrder, QuerySelect};

pub(super) async fn get_user_info(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let token = extract_bearer(&headers)?;
    let student_id = verify_token(&token, &state.config.jwt)?;
    let db = &state.db;
    let user = get_user(db, &student_id)
        .await?
        .ok_or_else(|| AppError::not_found("user not found"))?;

    Ok(Json(json!({
        "student_id": user.student_id,
        "name": user.name,
        "email": user.email,
        "group": user.group_code_name
    })))
}

pub(super) async fn list_users(
    State(state): State<AppState>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<serde_json::Value>, AppError> {
    let page = pagination.page.unwrap_or(1);
    let page_size = pagination.page_size.unwrap_or(20);
    let offset = (page.saturating_sub(1) * page_size) as u64;
    let limit = page_size as u64;

    let db = &state.db;
    let rows = user::Entity::find()
        .order_by_asc(user::Column::StudentId)
        .offset(offset)
        .limit(limit)
        .all(db)
        .await?;
    let users = rows
        .into_iter()
        .map(|row| {
            json!({
                "student_id": row.student_id,
                "name": row.name,
                "group": row.group_code_name,
            })
        })
        .collect::<Vec<_>>();

    Ok(Json(json!({
        "page": page,
        "page_size": page_size,
        "users": users
    })))
}

pub(super) async fn debug_users(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = &state.db;
    let mut users_map = BTreeMap::new();
    for user in user::Entity::find()
        .order_by_asc(user::Column::StudentId)
        .all(db)
        .await?
    {
        users_map.insert(
            user.student_id,
            json!({
                "name": user.name,
                "email": user.email,
                "password_hash": "***",
                "group": user.group_code_name
            }),
        );
    }

    let mut groups_map = BTreeMap::new();
    for group in group::Entity::find()
        .order_by_asc(group::Column::CodeName)
        .all(db)
        .await?
    {
        let members = group_members(db, &group.code_name).await?;
        groups_map.insert(
            group.code_name.clone(),
            json!({
                "name": group.name,
                "code_name": group.code_name,
                "leader": group.leader_id,
                "members": members
            }),
        );
    }

    let mut invitations_map = BTreeMap::new();
    for invite in invite::Entity::find()
        .order_by_asc(invite::Column::Token)
        .all(db)
        .await?
    {
        invitations_map.insert(
            invite.token,
            json!({
                "group_code_name": invite.group_code_name,
                "inviter_id": invite.inviter_id,
                "invitee_id": invite.invitee_id,
                "type": invite.typ
            }),
        );
    }

    let mut join_requests_map = BTreeMap::new();
    for request in join::Entity::find()
        .order_by_asc(join::Column::Token)
        .all(db)
        .await?
    {
        join_requests_map.insert(
            request.token,
            json!({
                "group_code_name": request.group_code_name,
                "requester_id": request.requester_id,
                "type": request.typ
            }),
        );
    }

    let payload = json!({
        "users": users_map,
        "groups": groups_map,
        "invitations": invitations_map,
        "join_requests": join_requests_map
    });

    Ok(Json(payload))
}
