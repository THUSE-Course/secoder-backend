use sea_orm::{
    ActiveModelTrait, DatabaseConnection, EntityTrait, QueryOrder, Set,
};

use crate::{
    entity::{user, user_access},
    error::AppError,
    security::hash_password,
};

#[derive(Clone, Debug)]
pub struct UserAccessEntry {
    pub id: String,
    pub banned: bool,
}

#[derive(Clone, Debug)]
pub struct RegistrationAccess {
    pub password_hash: String,
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

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ConnectionTrait, Database, DbBackend, Schema};

    async fn test_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared("PRAGMA foreign_keys = ON;")
            .await
            .unwrap();
        let schema = Schema::new(DbBackend::Sqlite);
        for mut stmt in [
            schema.create_table_from_entity(user::Entity),
            schema.create_table_from_entity(user_access::Entity),
        ] {
            stmt.if_not_exists();
            db.execute(&stmt).await.unwrap();
        }
        db
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
