use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::RwLock,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PredefinedUser {
    pub id: String,
    #[serde(rename = "passwd")]
    pub password: String,
    // TODO(online-upgrade): keep this default until every deployed users.json
    // has been rewritten at least once with the explicit banned field.
    #[serde(default, skip_serializing_if = "is_false")]
    pub banned: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct UserAccessEntry {
    pub id: String,
    pub banned: bool,
}

pub struct UserAccessStore {
    path: PathBuf,
    users: RwLock<BTreeMap<String, PredefinedUser>>,
}

impl UserAccessStore {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let users = read_users(&path)?;
        Ok(Self {
            path,
            users: RwLock::new(users),
        })
    }

    pub fn password_for(&self, id: &str) -> Option<String> {
        self.users
            .read()
            .expect("user access store poisoned")
            .get(id)
            .filter(|user| !user.banned)
            .map(|user| user.password.clone())
    }

    pub fn is_banned(&self, id: &str) -> bool {
        self.users
            .read()
            .expect("user access store poisoned")
            .get(id)
            .map(|user| user.banned)
            .unwrap_or(false)
    }

    pub fn contains(&self, id: &str) -> bool {
        self.users
            .read()
            .expect("user access store poisoned")
            .contains_key(id)
    }

    pub fn list(&self) -> Vec<UserAccessEntry> {
        self.users
            .read()
            .expect("user access store poisoned")
            .values()
            .map(|user| UserAccessEntry {
                id: user.id.clone(),
                banned: user.banned,
            })
            .collect()
    }

    pub fn add_or_unban(&self, id: String, password: String) -> Result<()> {
        let mut users = self.users.write().expect("user access store poisoned");
        users.insert(
            id.clone(),
            PredefinedUser {
                id,
                password,
                banned: false,
            },
        );
        self.persist_locked(&users)
    }

    pub fn ban(&self, id: &str) -> Result<()> {
        let mut users = self.users.write().expect("user access store poisoned");
        if let Some(user) = users.get_mut(id) {
            user.banned = true;
        } else {
            users.insert(
                id.to_string(),
                PredefinedUser {
                    id: id.to_string(),
                    password: String::new(),
                    banned: true,
                },
            );
        };
        self.persist_locked(&users)?;
        Ok(())
    }

    fn persist_locked(
        &self,
        users: &BTreeMap<String, PredefinedUser>,
    ) -> Result<()> {
        let rows = users.values().cloned().collect::<Vec<_>>();
        let body = serde_json::to_string_pretty(&rows)?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let tmp = self.path.with_extension(format!(
            "json.tmp.{}.{}",
            std::process::id(),
            nonce
        ));
        // TODO(online-upgrade): preserving mode makes the first runtime rewrite
        // safe for existing PVC files. Once all deployments have passed through
        // this migration, this can be simplified to a plain atomic write.
        let permissions = fs::metadata(&self.path)
            .map(|metadata| metadata.permissions())
            .ok();
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)
            .with_context(|| {
                format!("failed to write users file: {}", tmp.display())
            })?;
        file.write_all(format!("{body}\n").as_bytes())
            .with_context(|| {
                format!("failed to write users file: {}", tmp.display())
            })?;
        if let Some(permissions) = permissions {
            file.set_permissions(permissions).with_context(|| {
                format!(
                    "failed to set users file permissions: {}",
                    tmp.display()
                )
            })?;
        }
        file.sync_all().with_context(|| {
            format!("failed to sync users file: {}", tmp.display())
        })?;
        drop(file);
        fs::rename(&tmp, &self.path).with_context(|| {
            format!("failed to replace users file: {}", self.path.display())
        })?;
        Ok(())
    }
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

    #[test]
    fn add_unban_and_ban_persist_to_file() {
        let path = std::env::temp_dir()
            .join(format!("secoder-users-test-{}.json", std::process::id()));
        fs::write(&path, r#"[{"id":"alice","passwd":"old","banned":true}]"#)
            .unwrap();

        let store = UserAccessStore::load(&path).unwrap();
        assert!(store.is_banned("alice"));

        store
            .add_or_unban("alice".to_string(), "new".to_string())
            .unwrap();
        assert_eq!(store.password_for("alice").as_deref(), Some("new"));
        assert!(!store.is_banned("alice"));

        store.ban("alice").unwrap();
        assert!(store.is_banned("alice"));
        assert!(store.password_for("alice").is_none());

        let persisted = fs::read_to_string(&path).unwrap();
        let rows: Vec<PredefinedUser> =
            serde_json::from_str(&persisted).unwrap();
        assert_eq!(rows[0].id, "alice");
        assert_eq!(rows[0].password, "new");
        assert!(rows[0].banned);

        let _ = fs::remove_file(path);
    }
}
