use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::{Context, Result};
use sea_orm::{
    ActiveModelTrait, DatabaseConnection, EntityTrait, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};

use crate::{
    entity::{user, user_access},
    error::AppError,
    security::hash_password,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PredefinedUser {
    pub id: String,
    #[serde(rename = "passwd")]
    pub password: String,
    // TODO(online-upgrade): keep this default while importing legacy users.json
    // files that were written before the banned field existed. Remove with the
    // JSON import path after production has normalized into user_access.
    #[serde(default, skip_serializing_if = "is_false")]
    pub banned: bool,
}

#[derive(Clone, Debug)]
pub struct UserAccessEntry {
    pub id: String,
    pub banned: bool,
}

#[derive(Clone, Debug)]
pub struct RegistrationAccess {
    pub password_hash: String,
}

pub async fn migrate_from_json(
    db: &DatabaseConnection,
    path: impl AsRef<Path>,
) -> Result<()> {
    let json_users = read_users(path.as_ref())?;
    let registered_rows = user::Entity::find()
        .order_by_asc(user::Column::Id)
        .all(db)
        .await?;
    let existing_access_ids = user_access::Entity::find()
        .all(db)
        .await?
        .into_iter()
        .map(|row| row.id)
        .collect::<BTreeSet<_>>();

    let mut pending = BTreeMap::new();
    for row in registered_rows {
        if existing_access_ids.contains(&row.id) {
            continue;
        }
        let banned = json_users
            .get(&row.id)
            .map(|json_user| json_user.banned)
            .unwrap_or(false);
        pending.insert(
            row.id.clone(),
            user_access::ActiveModel {
                id: Set(row.id),
                password_hash: Set(row.password_hash),
                banned: Set(banned),
            },
        );
    }
    for json_user in json_users.into_values() {
        if existing_access_ids.contains(&json_user.id)
            || pending.contains_key(&json_user.id)
        {
            continue;
        }
        pending.insert(
            json_user.id.clone(),
            user_access::ActiveModel {
                id: Set(json_user.id),
                password_hash: Set(hash_password(&json_user.password)
                    .map_err(|e| anyhow::anyhow!(e))?),
                banned: Set(json_user.banned),
            },
        );
    }

    for row in pending.into_values() {
        row.insert(db).await?;
    }
    Ok(())
}

pub async fn registration_access(
    db: &DatabaseConnection,
    id: &str,
) -> Result<Option<RegistrationAccess>, AppError> {
    let access = user_access::Entity::find_by_id(id.to_string())
        .one(db)
        .await?;
    Ok(access
        .filter(|row| !row.banned)
        .map(|row| RegistrationAccess {
            password_hash: row.password_hash,
        }))
}

#[cfg(test)]
async fn verify_registration_password(
    db: &DatabaseConnection,
    id: &str,
    password: &str,
) -> Result<bool, AppError> {
    let Some(access) = registration_access(db, id).await? else {
        return Ok(false);
    };
    Ok(crate::security::verify_password(
        &access.password_hash,
        password,
    )?)
}

pub async fn is_banned(
    db: &DatabaseConnection,
    id: &str,
) -> Result<bool, AppError> {
    let access = user_access::Entity::find_by_id(id.to_string())
        .one(db)
        .await?;
    Ok(access.map(|row| row.banned).unwrap_or(false))
}

pub async fn contains(
    db: &DatabaseConnection,
    id: &str,
) -> Result<bool, AppError> {
    Ok(user_access::Entity::find_by_id(id.to_string())
        .one(db)
        .await?
        .is_some())
}

pub async fn list(
    db: &DatabaseConnection,
) -> Result<Vec<UserAccessEntry>, AppError> {
    let rows = user_access::Entity::find()
        .order_by_asc(user_access::Column::Id)
        .all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| UserAccessEntry {
            id: row.id,
            banned: row.banned,
        })
        .collect())
}

pub async fn add_or_unban(
    db: &DatabaseConnection,
    id: String,
    password: String,
) -> Result<(), AppError> {
    let password_hash =
        hash_password(&password).map_err(|e| anyhow::anyhow!(e))?;
    let existing = user_access::Entity::find_by_id(id.clone()).one(db).await?;
    match existing {
        Some(row) => {
            let mut model: user_access::ActiveModel = row.into();
            model.password_hash = Set(password_hash);
            model.banned = Set(false);
            model.update(db).await?;
        }
        None => user_access::ActiveModel {
            id: Set(id),
            password_hash: Set(password_hash),
            banned: Set(false),
        }
        .insert(db)
        .await
        .map(|_| ())?,
    };
    Ok(())
}

pub async fn ban(db: &DatabaseConnection, id: &str) -> Result<(), AppError> {
    let existing = user_access::Entity::find_by_id(id.to_string())
        .one(db)
        .await?;
    match existing {
        Some(row) => {
            let mut model: user_access::ActiveModel = row.into();
            model.banned = Set(true);
            model.update(db).await?;
        }
        None => {
            let registered =
                user::Entity::find_by_id(id.to_string()).one(db).await?;
            let Some(registered) = registered else {
                return Err(AppError::adhoc(
                    axum::http::StatusCode::NOT_FOUND,
                    anyhow::anyhow!("user {} not found", id),
                ));
            };
            user_access::ActiveModel {
                id: Set(id.to_string()),
                password_hash: Set(registered.password_hash),
                banned: Set(true),
            }
            .insert(db)
            .await
            .map(|_| ())?;
        }
    };
    Ok(())
}

pub async fn unban(
    db: &DatabaseConnection,
    id: &str,
) -> Result<bool, AppError> {
    let Some(row) = user_access::Entity::find_by_id(id.to_string())
        .one(db)
        .await?
    else {
        return Ok(false);
    };
    let mut model: user_access::ActiveModel = row.into();
    model.banned = Set(false);
    model.save(db).await?;
    Ok(true)
}

fn read_users(path: &Path) -> Result<BTreeMap<String, PredefinedUser>> {
    let contents = fs::read_to_string(path).with_context(|| {
        format!("failed to read users file: {}", path.display())
    })?;
    let rows: Vec<PredefinedUser> = serde_json::from_str(&contents)
        .with_context(|| {
            format!("failed to parse users file: {}", path.display())
        })?;
    let mut users = BTreeMap::new();
    for user in rows {
        let id = user.id.clone();
        if users.insert(id.clone(), user).is_some() {
            return Err(anyhow::anyhow!(
                "duplicate user id in users file: {}",
                id
            ));
        }
    }
    Ok(users)
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ConnectionTrait, Database, DbBackend, Schema, Statement};
    use uuid::Uuid;

    async fn test_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute(Statement::from_string(
            DbBackend::Sqlite,
            "PRAGMA foreign_keys = ON;",
        ))
        .await
        .unwrap();
        let schema = Schema::new(DbBackend::Sqlite);
        for mut stmt in [
            schema.create_table_from_entity(user::Entity),
            schema.create_table_from_entity(user_access::Entity),
        ] {
            stmt.if_not_exists();
            let statement = db.get_database_backend().build(&stmt);
            db.execute(statement).await.unwrap();
        }
        db
    }

    fn write_users_json(body: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir()
            .join(format!("secoder-users-test-{}.json", Uuid::new_v4()));
        fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn parses_existing_user_format() {
        let rows: Vec<PredefinedUser> =
            serde_json::from_str(r#"[{"id":"alice","passwd":"secret"}]"#)
                .unwrap();
        assert_eq!(rows[0].id, "alice");
        assert_eq!(rows[0].password, "secret");
        assert!(!rows[0].banned);
    }

    #[test]
    fn parses_banned_user_format() {
        let rows: Vec<PredefinedUser> = serde_json::from_str(
            r#"[{"id":"alice","passwd":"secret","banned":true}]"#,
        )
        .unwrap();
        assert!(rows[0].banned);
    }

    #[tokio::test]
    async fn imports_legacy_json_to_user_access() {
        let db = test_db().await;
        let path = write_users_json(
            r#"[
                {"id":"alice","passwd":"secret"},
                {"id":"bob","passwd":"hidden","banned":true}
            ]"#,
        );

        migrate_from_json(&db, &path).await.unwrap();

        assert!(
            verify_registration_password(&db, "alice", "secret")
                .await
                .unwrap()
        );
        assert!(!is_banned(&db, "alice").await.unwrap());
        assert!(is_banned(&db, "bob").await.unwrap());
        assert!(registration_access(&db, "bob").await.unwrap().is_none());

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn backfills_registered_users_and_preserves_json_ban() {
        let db = test_db().await;
        let password_hash = hash_password("registered-password").unwrap();
        user::Entity::insert(user::ActiveModel {
            id: Set("alice".to_string()),
            name: Set("Alice".to_string()),
            email: Set("alice@example.com".to_string()),
            sudo: Set(false),
            password_hash: Set(password_hash.clone()),
            group_code_name: Set(None),
        })
        .exec(&db)
        .await
        .unwrap();
        let path = write_users_json(
            r#"[{"id":"alice","passwd":"legacy-password","banned":true}]"#,
        );

        migrate_from_json(&db, &path).await.unwrap();

        assert!(is_banned(&db, "alice").await.unwrap());
        let access = user_access::Entity::find_by_id("alice".to_string())
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(access.password_hash, password_hash);

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn add_ban_and_unban_update_database_rows() {
        let db = test_db().await;

        add_or_unban(&db, "alice".to_string(), "secret".to_string())
            .await
            .unwrap();
        assert!(
            verify_registration_password(&db, "alice", "secret")
                .await
                .unwrap()
        );

        ban(&db, "alice").await.unwrap();
        assert!(is_banned(&db, "alice").await.unwrap());
        assert!(registration_access(&db, "alice").await.unwrap().is_none());

        assert!(unban(&db, "alice").await.unwrap());
        assert!(!is_banned(&db, "alice").await.unwrap());
        assert!(
            verify_registration_password(&db, "alice", "secret")
                .await
                .unwrap()
        );
    }
}
