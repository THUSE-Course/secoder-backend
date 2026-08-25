use std::collections::{BTreeMap, BTreeSet};

use axum::response::{IntoResponse, Response};
use csv::{ReaderBuilder, StringRecord, Trim};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    QueryOrder, Set, TransactionTrait, sea_query::OnConflict,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::*;
use crate::{
    db::group_members,
    entity::{group, invite, member, user, user_access},
    kubernetes::{sanitize_k8s_name, update_group_tenant_label},
};

#[derive(Deserialize)]
pub struct RosterRequest {
    csv: String,
}

#[derive(Deserialize)]
pub struct ApplyRosterRequest {
    csv: String,
    preview_token: String,
}

#[derive(Clone, Debug)]
struct ParsedGroup {
    row: usize,
    code_name: String,
    display_name: String,
    leader: String,
    members: Vec<(usize, String)>,
}

#[derive(Debug, Default)]
struct ParsedRoster {
    groups: Vec<ParsedGroup>,
    ungrouped: Vec<(usize, usize, String)>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RosterValidationError {
    row: Option<usize>,
    column: Option<String>,
    message: String,
}

impl RosterValidationError {
    fn file(message: impl Into<String>) -> Self {
        Self {
            row: None,
            column: None,
            message: message.into(),
        }
    }

    fn cell(
        row: usize,
        column: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            row: Some(row),
            column: Some(column.into()),
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CreatedGroupChange {
    code_name: String,
    display_name: String,
    leader: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RenamedGroupChange {
    code_name: String,
    from: String,
    to: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct LeaderChange {
    code_name: String,
    from: String,
    to: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct StudentGroupChange {
    id: String,
    from_group: Option<String>,
    to_group: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RosterChanges {
    created_groups: Vec<CreatedGroupChange>,
    renamed_groups: Vec<RenamedGroupChange>,
    leader_changes: Vec<LeaderChange>,
    student_changes: Vec<StudentGroupChange>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RosterSummary {
    groups_created: usize,
    groups_renamed: usize,
    leaders_changed: usize,
    students_changed: usize,
    students_ungrouped: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct RosterPreviewResponse {
    valid: bool,
    errors: Vec<RosterValidationError>,
    preview_token: Option<String>,
    summary: Option<RosterSummary>,
    changes: Option<RosterChanges>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReconciliationWarning {
    group_code_name: String,
    message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApplyRosterResponse {
    applied: bool,
    summary: RosterSummary,
    reconciliation_warnings: Vec<ReconciliationWarning>,
}

#[derive(Clone, Debug, Serialize)]
struct UserState {
    id: String,
    sudo: bool,
    banned: bool,
    group_code_name: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct GroupState {
    code_name: String,
    name: String,
    leader_id: String,
    members: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct InvitationState {
    token: String,
    group_code_name: String,
    inviter_id: String,
    invitee_id: String,
}

#[derive(Clone, Debug, Serialize)]
struct RosterState {
    users: BTreeMap<String, UserState>,
    groups: BTreeMap<String, GroupState>,
    invitations: Vec<InvitationState>,
}

#[derive(Clone, Debug)]
struct DesiredGroup {
    code_name: String,
    display_name: String,
    leader: String,
    active_members: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct RosterPlan {
    desired_groups: BTreeMap<String, DesiredGroup>,
    assignments: BTreeMap<String, Option<String>>,
    summary: RosterSummary,
    changes: RosterChanges,
    preview_token: String,
}

pub async fn preview(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<RosterRequest>,
) -> Result<Json<RosterPreviewResponse>, AppError> {
    require_sudo(&claims)?;
    let roster_state = load_roster_state(&state.db).await?;
    match build_plan(&payload.csv, &roster_state) {
        Ok(plan) => Ok(Json(valid_preview(&plan))),
        Err(errors) => Ok(Json(invalid_preview(errors))),
    }
}

pub async fn apply(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<ApplyRosterRequest>,
) -> Result<Response, AppError> {
    require_sudo(&claims)?;
    super::ensure_not_readonly(&state.db).await?;

    let txn = state.db.begin().await?;
    let roster_state = load_roster_state(&txn).await?;
    let plan = match build_plan(&payload.csv, &roster_state) {
        Ok(plan) => plan,
        Err(errors) => {
            txn.rollback().await?;
            return Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(invalid_preview(errors)),
            )
                .into_response());
        }
    };
    if payload.preview_token != plan.preview_token {
        txn.rollback().await?;
        return Err(AppError::adhoc(
            StatusCode::CONFLICT,
            anyhow::anyhow!(
                "roster data changed after preview; preview the CSV again"
            ),
        ));
    }

    apply_database_plan(&txn, &plan).await?;
    txn.commit().await?;

    let mut reconciliation_warnings = Vec::new();
    for desired in plan.desired_groups.values() {
        let mut members = group_members(&state.db, &desired.code_name).await?;
        if !members.iter().any(|id| id == &desired.leader) {
            members.insert(0, desired.leader.clone());
        }
        if let Err(err) = update_group_tenant_label(
            &state.kube,
            &desired.code_name,
            &state.config.rbac,
            &members,
        )
        .await
        {
            reconciliation_warnings.push(ReconciliationWarning {
                group_code_name: desired.code_name.clone(),
                message: err.to_string(),
            });
        }
    }

    Ok(Json(ApplyRosterResponse {
        applied: true,
        summary: plan.summary,
        reconciliation_warnings,
    })
    .into_response())
}

fn require_sudo(claims: &Claims) -> Result<(), AppError> {
    if claims.sudo {
        return Ok(());
    }
    Err(AppError::adhoc(
        StatusCode::FORBIDDEN,
        anyhow::anyhow!("sudo required"),
    ))
}

fn valid_preview(plan: &RosterPlan) -> RosterPreviewResponse {
    RosterPreviewResponse {
        valid: true,
        errors: Vec::new(),
        preview_token: Some(plan.preview_token.clone()),
        summary: Some(plan.summary.clone()),
        changes: Some(plan.changes.clone()),
    }
}

fn invalid_preview(
    errors: Vec<RosterValidationError>,
) -> RosterPreviewResponse {
    RosterPreviewResponse {
        valid: false,
        errors,
        preview_token: None,
        summary: None,
        changes: None,
    }
}

async fn load_roster_state<C>(db: &C) -> Result<RosterState, AppError>
where
    C: ConnectionTrait,
{
    let banned = user_access::Entity::find()
        .order_by_asc(user_access::Column::Id)
        .all(db)
        .await?
        .into_iter()
        .filter(|row| row.banned)
        .map(|row| row.id)
        .collect::<BTreeSet<_>>();

    let users = user::Entity::find()
        .order_by_asc(user::Column::Id)
        .all(db)
        .await?
        .into_iter()
        .map(|row| {
            let id = row.id.clone();
            (
                id.clone(),
                UserState {
                    id: id.clone(),
                    sudo: row.sudo,
                    banned: banned.contains(&id),
                    group_code_name: row.group_code_name,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut members_by_group = BTreeMap::<String, Vec<String>>::new();
    for row in member::Entity::find()
        .order_by_asc(member::Column::GroupCodeName)
        .order_by_asc(member::Column::Id)
        .all(db)
        .await?
    {
        members_by_group
            .entry(row.group_code_name)
            .or_default()
            .push(row.id);
    }

    let groups = group::Entity::find()
        .order_by_asc(group::Column::CodeName)
        .all(db)
        .await?
        .into_iter()
        .map(|row| {
            let code_name = row.code_name.clone();
            (
                code_name.clone(),
                GroupState {
                    code_name: code_name.clone(),
                    name: row.name,
                    leader_id: row.leader_id,
                    members: members_by_group
                        .remove(&code_name)
                        .unwrap_or_default(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    let invitations = invite::Entity::find()
        .filter(invite::Column::Typ.eq("invite"))
        .order_by_asc(invite::Column::Token)
        .all(db)
        .await?
        .into_iter()
        .map(|row| InvitationState {
            token: row.token,
            group_code_name: row.group_code_name,
            inviter_id: row.inviter_id,
            invitee_id: row.invitee_id,
        })
        .collect();

    Ok(RosterState {
        users,
        groups,
        invitations,
    })
}

fn build_plan(
    csv_text: &str,
    state: &RosterState,
) -> Result<RosterPlan, Vec<RosterValidationError>> {
    let parsed = parse_csv(csv_text)?;
    let mut errors = Vec::new();
    let eligible = state
        .users
        .values()
        .filter(|user| !user.sudo && !user.banned)
        .map(|user| user.id.clone())
        .collect::<BTreeSet<_>>();
    let mut desired_groups = BTreeMap::new();
    let mut assignments = BTreeMap::<String, Option<String>>::new();

    for parsed_group in parsed.groups {
        if desired_groups.contains_key(&parsed_group.code_name) {
            errors.push(RosterValidationError::cell(
                parsed_group.row,
                "CodeName",
                format!(
                    "group {} appears more than once",
                    parsed_group.code_name
                ),
            ));
            continue;
        }
        if sanitize_k8s_name(&parsed_group.code_name) != parsed_group.code_name
        {
            errors.push(RosterValidationError::cell(
                parsed_group.row,
                "CodeName",
                "CodeName must be a canonical RFC 1035 name",
            ));
        }
        validate_student(
            &parsed_group.leader,
            parsed_group.row,
            "Leader",
            state,
            &eligible,
            &mut errors,
        );

        let mut active_members = BTreeSet::new();
        record_assignment(
            &parsed_group.leader,
            Some(&parsed_group.code_name),
            parsed_group.row,
            "Leader",
            &mut assignments,
            &mut errors,
        );
        active_members.insert(parsed_group.leader.clone());

        for (member_index, member_id) in &parsed_group.members {
            let column = format!("Member{member_index}");
            validate_student(
                member_id,
                parsed_group.row,
                &column,
                state,
                &eligible,
                &mut errors,
            );
            record_assignment(
                member_id,
                Some(&parsed_group.code_name),
                parsed_group.row,
                &column,
                &mut assignments,
                &mut errors,
            );
            active_members.insert(member_id.clone());
        }

        desired_groups.insert(
            parsed_group.code_name.clone(),
            DesiredGroup {
                code_name: parsed_group.code_name,
                display_name: parsed_group.display_name,
                leader: parsed_group.leader,
                active_members,
            },
        );
    }

    for (row, member_index, id) in parsed.ungrouped {
        let column = format!("Member{member_index}");
        validate_student(&id, row, &column, state, &eligible, &mut errors);
        record_assignment(
            &id,
            None,
            row,
            &column,
            &mut assignments,
            &mut errors,
        );
    }

    let assigned = assignments.keys().cloned().collect::<BTreeSet<_>>();
    for id in eligible.difference(&assigned) {
        errors.push(RosterValidationError::file(format!(
            "registered unbanned student {id} is missing from the roster"
        )));
    }
    for code_name in state.groups.keys() {
        if !desired_groups.contains_key(code_name) {
            errors.push(RosterValidationError::file(format!(
                "existing group {code_name} is missing from the roster"
            )));
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    let changes = calculate_changes(state, &desired_groups, &assignments);
    let summary = RosterSummary {
        groups_created: changes.created_groups.len(),
        groups_renamed: changes.renamed_groups.len(),
        leaders_changed: changes.leader_changes.len(),
        students_changed: changes.student_changes.len(),
        students_ungrouped: changes
            .student_changes
            .iter()
            .filter(|change| change.to_group.is_none())
            .count(),
    };
    let preview_token = preview_token(csv_text, state);
    Ok(RosterPlan {
        desired_groups,
        assignments,
        summary,
        changes,
        preview_token,
    })
}

fn parse_csv(
    csv_text: &str,
) -> Result<ParsedRoster, Vec<RosterValidationError>> {
    if csv_text.trim().is_empty() {
        return Err(vec![RosterValidationError::file("CSV file is empty")]);
    }
    let mut reader = ReaderBuilder::new()
        .flexible(true)
        .trim(Trim::All)
        .from_reader(csv_text.as_bytes());
    let headers = reader.headers().map_err(|err| {
        vec![RosterValidationError::file(format!(
            "unable to read CSV header: {err}"
        ))]
    })?;
    validate_headers(headers)?;
    let header_len = headers.len();

    let mut roster = ParsedRoster::default();
    let mut errors = Vec::new();
    let mut ungrouped_seen = false;
    for (record_index, result) in reader.records().enumerate() {
        let row = record_index + 2;
        let record = match result {
            Ok(record) => record,
            Err(err) => {
                errors.push(RosterValidationError::cell(
                    row,
                    "CSV",
                    err.to_string(),
                ));
                continue;
            }
        };
        if record.iter().all(str::is_empty) {
            continue;
        }
        if record.len() > header_len {
            errors.push(RosterValidationError::cell(
                row,
                "CSV",
                format!(
                    "row has {} columns but the header has {header_len}",
                    record.len()
                ),
            ));
            continue;
        }
        let code_name = field(&record, 0);
        let display_name = field(&record, 1);
        let leader = field(&record, 2);
        let members = record
            .iter()
            .skip(3)
            .enumerate()
            .filter_map(|(index, value)| {
                let value = value.trim();
                (!value.is_empty()).then(|| (index + 1, value.to_string()))
            })
            .collect::<Vec<_>>();

        if code_name.is_empty() {
            if !display_name.is_empty() || !leader.is_empty() {
                errors.push(RosterValidationError::cell(
                    row,
                    "CodeName",
                    "the ungrouped row requires empty CodeName, DisplayName, and Leader",
                ));
                continue;
            }
            if ungrouped_seen {
                errors.push(RosterValidationError::cell(
                    row,
                    "CodeName",
                    "only one ungrouped row is allowed",
                ));
                continue;
            }
            ungrouped_seen = true;
            roster.ungrouped = members
                .into_iter()
                .map(|(member_index, id)| (row, member_index, id))
                .collect();
            continue;
        }
        if display_name.is_empty() {
            errors.push(RosterValidationError::cell(
                row,
                "DisplayName",
                "DisplayName is required",
            ));
        }
        if leader.is_empty() {
            errors.push(RosterValidationError::cell(
                row,
                "Leader",
                "Leader is required",
            ));
        }
        roster.groups.push(ParsedGroup {
            row,
            code_name,
            display_name,
            leader,
            members,
        });
    }
    if errors.is_empty() {
        Ok(roster)
    } else {
        Err(errors)
    }
}

fn validate_headers(
    headers: &StringRecord,
) -> Result<(), Vec<RosterValidationError>> {
    if headers.len() < 4 {
        return Err(vec![RosterValidationError::file(
            "CSV header must contain CodeName, DisplayName, Leader, and at least Member1",
        )]);
    }
    for (index, expected) in
        ["CodeName", "DisplayName", "Leader"].iter().enumerate()
    {
        if headers.get(index) != Some(*expected) {
            return Err(vec![RosterValidationError::file(format!(
                "CSV column {} must be named {expected}",
                index + 1
            ))]);
        }
    }
    for index in 3..headers.len() {
        let expected = format!("Member{}", index - 2);
        if headers.get(index) != Some(expected.as_str()) {
            return Err(vec![RosterValidationError::file(format!(
                "CSV column {} must be named {expected}",
                index + 1
            ))]);
        }
    }
    Ok(())
}

fn field(record: &StringRecord, index: usize) -> String {
    record.get(index).unwrap_or_default().trim().to_string()
}

fn validate_student(
    id: &str,
    row: usize,
    column: &str,
    state: &RosterState,
    eligible: &BTreeSet<String>,
    errors: &mut Vec<RosterValidationError>,
) {
    let error = match state.users.get(id) {
        None => Some(format!("user {id} is not registered")),
        Some(user) if user.sudo => {
            Some(format!("sudo user {id} cannot appear in the roster"))
        }
        Some(user) if user.banned => {
            Some(format!("banned user {id} cannot appear in the roster"))
        }
        Some(_) if !eligible.contains(id) => {
            Some(format!("user {id} is not eligible for the roster"))
        }
        Some(_) => None,
    };
    if let Some(message) = error {
        errors.push(RosterValidationError::cell(row, column, message));
    }
}

fn record_assignment(
    id: &str,
    group_code_name: Option<&str>,
    row: usize,
    column: &str,
    assignments: &mut BTreeMap<String, Option<String>>,
    errors: &mut Vec<RosterValidationError>,
) {
    if assignments.contains_key(id) {
        errors.push(RosterValidationError::cell(
            row,
            column,
            format!("student {id} appears more than once"),
        ));
        return;
    }
    assignments.insert(id.to_string(), group_code_name.map(str::to_string));
}

fn calculate_changes(
    state: &RosterState,
    desired_groups: &BTreeMap<String, DesiredGroup>,
    assignments: &BTreeMap<String, Option<String>>,
) -> RosterChanges {
    let mut changes = RosterChanges::default();
    for desired in desired_groups.values() {
        match state.groups.get(&desired.code_name) {
            None => changes.created_groups.push(CreatedGroupChange {
                code_name: desired.code_name.clone(),
                display_name: desired.display_name.clone(),
                leader: desired.leader.clone(),
            }),
            Some(current) => {
                if current.name != desired.display_name {
                    changes.renamed_groups.push(RenamedGroupChange {
                        code_name: desired.code_name.clone(),
                        from: current.name.clone(),
                        to: desired.display_name.clone(),
                    });
                }
                if current.leader_id != desired.leader {
                    changes.leader_changes.push(LeaderChange {
                        code_name: desired.code_name.clone(),
                        from: current.leader_id.clone(),
                        to: desired.leader.clone(),
                    });
                }
            }
        }
    }
    for (id, to_group) in assignments {
        let from_group = state
            .users
            .get(id)
            .and_then(|user| user.group_code_name.clone());
        if from_group != *to_group {
            changes.student_changes.push(StudentGroupChange {
                id: id.clone(),
                from_group,
                to_group: to_group.clone(),
            });
        }
    }
    changes
}

fn preview_token(csv_text: &str, state: &RosterState) -> String {
    let mut digest = Sha256::new();
    digest.update(csv_text.as_bytes());
    digest.update([0]);
    digest.update(
        serde_json::to_vec(state)
            .expect("roster state serialization cannot fail"),
    );
    hex::encode(digest.finalize())
}

async fn apply_database_plan<C>(
    db: &C,
    plan: &RosterPlan,
) -> Result<(), AppError>
where
    C: ConnectionTrait,
{
    for desired in plan.desired_groups.values() {
        match group::Entity::find_by_id(desired.code_name.clone())
            .one(db)
            .await?
        {
            Some(row) => {
                let mut model: group::ActiveModel = row.into();
                model.name = Set(desired.display_name.clone());
                model.leader_id = Set(desired.leader.clone());
                model.update(db).await?;
            }
            None => {
                group::ActiveModel {
                    code_name: Set(desired.code_name.clone()),
                    name: Set(desired.display_name.clone()),
                    leader_id: Set(desired.leader.clone()),
                }
                .insert(db)
                .await?;
            }
        }
    }

    let active_ids = plan.assignments.keys().cloned().collect::<Vec<_>>();
    if !active_ids.is_empty() {
        member::Entity::delete_many()
            .filter(member::Column::Id.is_in(active_ids.clone()))
            .exec(db)
            .await?;
        invite::Entity::delete_many()
            .filter(invite::Column::Typ.eq("invite"))
            .filter(invite::Column::InviteeId.is_in(active_ids))
            .exec(db)
            .await?;
    }

    for desired in plan.desired_groups.values() {
        for id in &desired.active_members {
            member::Entity::insert(member::ActiveModel {
                group_code_name: Set(desired.code_name.clone()),
                id: Set(id.clone()),
            })
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
        }
    }
    for (id, group_code_name) in &plan.assignments {
        let row = user::Entity::find_by_id(id.clone())
            .one(db)
            .await?
            .ok_or_else(|| {
                AppError::adhoc(
                    StatusCode::CONFLICT,
                    anyhow::anyhow!(
                        "user {id} disappeared while applying roster"
                    ),
                )
            })?;
        let mut model: user::ActiveModel = row.into();
        model.group_code_name = Set(group_code_name.clone());
        model.update(db).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{db::init_db, entity::user_access};
    use sea_orm::{Database, DatabaseConnection};

    async fn test_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        init_db(&db).await.unwrap();
        db
    }

    async fn add_user(
        db: &DatabaseConnection,
        id: &str,
        group_code_name: Option<&str>,
        banned: bool,
    ) {
        user::ActiveModel {
            id: Set(id.to_string()),
            name: Set(id.to_string()),
            email: Set(format!("{id}@example.test")),
            sudo: Set(false),
            password_hash: Set("hash".to_string()),
            group_code_name: Set(group_code_name.map(str::to_string)),
        }
        .insert(db)
        .await
        .unwrap();
        user_access::ActiveModel {
            id: Set(id.to_string()),
            password_hash: Set("hash".to_string()),
            banned: Set(banned),
        }
        .insert(db)
        .await
        .unwrap();
    }

    #[test]
    fn parses_group_and_ungrouped_rows() {
        let parsed = parse_csv(
            "CodeName,DisplayName,Leader,Member1,Member2\nteam-a,Team A,alice,bob,\n,,,carol,\n",
        )
        .unwrap();
        assert_eq!(parsed.groups.len(), 1);
        assert_eq!(parsed.groups[0].leader, "alice");
        assert_eq!(parsed.groups[0].members[0].1, "bob");
        assert_eq!(parsed.ungrouped[0].2, "carol");
    }

    #[test]
    fn rejects_non_contiguous_member_headers() {
        let errors = parse_csv(
            "CodeName,DisplayName,Leader,Member2\nteam-a,Team A,alice,bob\n",
        )
        .unwrap_err();
        assert!(errors[0].message.contains("Member1"));
    }

    #[tokio::test]
    async fn validates_and_applies_authoritative_active_roster() {
        let db = test_db().await;
        add_user(&db, "alice", Some("old"), false).await;
        add_user(&db, "bob", Some("old"), false).await;
        add_user(&db, "carol", Some("old"), true).await;
        group::ActiveModel {
            code_name: Set("old".to_string()),
            name: Set("Old".to_string()),
            leader_id: Set("alice".to_string()),
        }
        .insert(&db)
        .await
        .unwrap();
        for id in ["alice", "bob", "carol"] {
            member::ActiveModel {
                group_code_name: Set("old".to_string()),
                id: Set(id.to_string()),
            }
            .insert(&db)
            .await
            .unwrap();
        }

        let csv = "CodeName,DisplayName,Leader,Member1\nold,Renamed,bob,\nnew,New Team,alice,\n";
        let state = load_roster_state(&db).await.unwrap();
        let plan = build_plan(csv, &state).unwrap();
        assert_eq!(plan.summary.groups_created, 1);
        assert_eq!(plan.summary.groups_renamed, 1);
        assert_eq!(plan.summary.leaders_changed, 1);
        apply_database_plan(&db, &plan).await.unwrap();

        let updated_old = group::Entity::find_by_id("old")
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated_old.name, "Renamed");
        assert_eq!(updated_old.leader_id, "bob");
        assert_eq!(
            group_members(&db, "old").await.unwrap(),
            vec!["bob", "carol"]
        );
        assert_eq!(group_members(&db, "new").await.unwrap(), vec!["alice"]);
        assert_eq!(
            user::Entity::find_by_id("carol")
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .group_code_name,
            Some("old".to_string())
        );
    }

    #[tokio::test]
    async fn rejects_missing_active_student_and_existing_group() {
        let db = test_db().await;
        add_user(&db, "alice", None, false).await;
        add_user(&db, "bob", None, false).await;
        group::ActiveModel {
            code_name: Set("old".to_string()),
            name: Set("Old".to_string()),
            leader_id: Set("alice".to_string()),
        }
        .insert(&db)
        .await
        .unwrap();
        let state = load_roster_state(&db).await.unwrap();
        let errors = build_plan(
            "CodeName,DisplayName,Leader,Member1\nnew,New,alice,\n",
            &state,
        )
        .unwrap_err();
        assert!(errors.iter().any(|error| error.message.contains("bob")));
        assert!(errors.iter().any(|error| error.message.contains("old")));
    }

    #[tokio::test]
    async fn apply_clears_active_invitations_and_is_idempotent() {
        let db = test_db().await;
        add_user(&db, "alice", None, false).await;
        add_user(&db, "bob", None, false).await;
        invite::ActiveModel {
            token: Set("active-invite".to_string()),
            group_code_name: Set("team-a".to_string()),
            inviter_id: Set("alice".to_string()),
            invitee_id: Set("bob".to_string()),
            typ: Set("invite".to_string()),
        }
        .insert(&db)
        .await
        .unwrap();

        let csv =
            "CodeName,DisplayName,Leader,Member1\nteam-a,Team A,alice,bob\n";
        let state = load_roster_state(&db).await.unwrap();
        let plan = build_plan(csv, &state).unwrap();
        apply_database_plan(&db, &plan).await.unwrap();
        assert!(
            invite::Entity::find_by_id("active-invite")
                .one(&db)
                .await
                .unwrap()
                .is_none()
        );

        let updated_state = load_roster_state(&db).await.unwrap();
        let retry_plan = build_plan(csv, &updated_state).unwrap();
        assert_eq!(retry_plan.summary.students_changed, 0);
        assert_eq!(retry_plan.summary.groups_created, 0);
        apply_database_plan(&db, &retry_plan).await.unwrap();
        assert_eq!(
            group_members(&db, "team-a").await.unwrap(),
            vec!["alice", "bob"]
        );
    }

    #[tokio::test]
    async fn preview_token_changes_when_roster_state_changes() {
        let db = test_db().await;
        add_user(&db, "alice", None, false).await;
        let csv = "CodeName,DisplayName,Leader,Member1\nteam-a,Team A,alice,\n";
        let before = load_roster_state(&db).await.unwrap();
        let before_token = build_plan(csv, &before).unwrap().preview_token;

        add_user(&db, "bob", None, false).await;
        let after = load_roster_state(&db).await.unwrap();
        let errors = build_plan(csv, &after).unwrap_err();
        assert!(errors.iter().any(|error| error.message.contains("bob")));
        assert_ne!(preview_token(csv, &before), preview_token(csv, &after));
        assert_eq!(before_token, preview_token(csv, &before));
    }
}
