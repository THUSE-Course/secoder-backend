use anyhow::Result;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend, EntityTrait,
    QueryFilter, QueryOrder, Schema, Set, Statement,
};

use super::{
    entity::{admin, group, invite, join, member, user},
    error::AppError,
};

#[derive(Debug)]
pub struct UserRow {
    pub id: String,
    pub name: String,
    pub email: String,
    pub sudo: bool,
    pub password_hash: String,
    pub group_code_name: Option<String>,
}

pub async fn init_db(db: &DatabaseConnection) -> Result<()> {
    let pragma =
        Statement::from_string(DbBackend::Sqlite, "PRAGMA foreign_keys = ON;");
    db.execute(pragma).await?;

    let schema = Schema::new(DbBackend::Sqlite);
    let tables = [
        schema.create_table_from_entity(user::Entity),
        schema.create_table_from_entity(admin::Entity),
        schema.create_table_from_entity(group::Entity),
        schema.create_table_from_entity(member::Entity),
        schema.create_table_from_entity(invite::Entity),
        schema.create_table_from_entity(join::Entity),
    ];
    for mut stmt in tables {
        stmt.if_not_exists();
        let statement = db.get_database_backend().build(&stmt);
        db.execute(statement).await?;
    }
    ensure_admin_row(db).await?;
    ensure_root_user(db).await?;
    Ok(())
}

pub async fn get_user(
    db: &DatabaseConnection,
    id: &str,
) -> Result<Option<UserRow>, AppError> {
    let user = user::Entity::find_by_id(id.to_string()).one(db).await?;
    Ok(user.map(|model| UserRow {
        id: model.id,
        name: model.name,
        email: model.email,
        sudo: model.sudo,
        password_hash: model.password_hash,
        group_code_name: model.group_code_name,
    }))
}

pub async fn is_readonly(db: &DatabaseConnection) -> Result<bool, AppError> {
    let admin = admin::Entity::find_by_id(1).one(db).await?;
    Ok(admin.map(|row| row.readonly).unwrap_or_default())
}

async fn ensure_admin_row(db: &DatabaseConnection) -> Result<()> {
    let existing = admin::Entity::find_by_id(1).one(db).await?;
    if existing.is_some() {
        return Ok(());
    }
    let admin = admin::ActiveModel {
        id: Set(1),
        readonly: Set(false),
    };
    admin::Entity::insert(admin).exec(db).await?;
    Ok(())
}

async fn ensure_root_user(db: &DatabaseConnection) -> Result<()> {
    let existing = user::Entity::find_by_id("root".to_string()).one(db).await?;
    if existing.is_some() {
        return Ok(());
    }
    let hash = super::security::hash_password("root")
        .map_err(|e| anyhow::anyhow!(e))?;
    let root = user::ActiveModel {
        id: Set("root".to_string()),
        name: Set("root".to_string()),
        email: Set("root@localhost".to_string()),
        sudo: Set(true),
        password_hash: Set(hash),
        group_code_name: Set(None),
    };
    user::Entity::insert(root).exec(db).await?;
    Ok(())
}

pub async fn group_members(
    db: &DatabaseConnection,
    code_name: &str,
) -> Result<Vec<String>, AppError> {
    let members = member::Entity::find()
        .filter(member::Column::GroupCodeName.eq(code_name))
        .order_by_asc(member::Column::Id)
        .all(db)
        .await?;
    Ok(members.into_iter().map(|m| m.id).collect())
}
