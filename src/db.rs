use crate::entity::{group, invite, join, member, user};
use crate::error::AppError;
use anyhow::Result;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection,
    DbBackend, EntityTrait, QueryFilter, QueryOrder, Schema, Set, Statement,
};

#[derive(Debug)]
pub struct UserRow {
    pub student_id: String,
    pub name: String,
    pub email: String,
    pub password_hash: String,
    pub password_salt: String,
    pub group_code_name: Option<String>,
}

pub async fn init_db(db: &DatabaseConnection) -> Result<()> {
    let pragma =
        Statement::from_string(DbBackend::Sqlite, "PRAGMA foreign_keys = ON;");
    db.execute(pragma).await?;

    let schema = Schema::new(DbBackend::Sqlite);
    let tables = [
        schema.create_table_from_entity(user::Entity),
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
    ensure_password_salt(db).await?;
    Ok(())
}

pub async fn get_user(
    db: &DatabaseConnection,
    student_id: &str,
) -> Result<Option<UserRow>, AppError> {
    let user = user::Entity::find_by_id(student_id.to_string())
        .one(db)
        .await?;
    Ok(user.map(|model| UserRow {
        student_id: model.student_id,
        name: model.name,
        email: model.email,
        password_hash: model.password_hash,
        password_salt: model.password_salt,
        group_code_name: model.group_code_name,
    }))
}

async fn ensure_password_salt(db: &DatabaseConnection) -> Result<()> {
    let pragma =
        Statement::from_string(DbBackend::Sqlite, "PRAGMA table_info(users);");
    let rows = db.query_all(pragma).await?;
    let mut has_salt = false;
    for row in rows {
        let name: String = row.try_get("", "name")?;
        if name == "password_salt" {
            has_salt = true;
            break;
        }
    }
    if has_salt {
        return Ok(());
    }

    let alter = Statement::from_string(
        DbBackend::Sqlite,
        "ALTER TABLE users ADD COLUMN password_salt varchar NOT NULL DEFAULT '';",
    );
    db.execute(alter).await?;

    let users = user::Entity::find().all(db).await?;
    for user in users {
        let salt = crate::security::generate_salt();
        let hash = crate::security::hash_password(&salt, &user.password_hash);
        let mut model: user::ActiveModel = user.into();
        model.password_salt = Set(salt);
        model.password_hash = Set(hash);
        model.update(db).await?;
    }

    Ok(())
}

pub async fn group_members(
    db: &DatabaseConnection,
    code_name: &str,
) -> Result<Vec<String>, AppError> {
    let members = member::Entity::find()
        .filter(member::Column::GroupCodeName.eq(code_name))
        .order_by_asc(member::Column::StudentId)
        .all(db)
        .await?;
    Ok(members.into_iter().map(|m| m.student_id).collect())
}
