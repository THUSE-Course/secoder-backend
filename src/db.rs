use crate::error::AppError;
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};

#[derive(Debug)]
pub struct UserRow {
    pub student_id: String,
    pub name: String,
    pub email: String,
    pub password_hash: String,
    pub group_code_name: Option<String>,
}

pub fn init_db(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;

    let mut has_registration_password = false;
    if let Ok(mut stmt) = conn.prepare("PRAGMA table_info(users)") {
        let rows = stmt.query_map(params![], |row| row.get::<_, String>(1))?;
        for row in rows {
            let name = row?;
            if name == "registration_password" {
                has_registration_password = true;
                break;
            }
        }
    }

    if has_registration_password {
        conn.execute_batch(
            r#"
            BEGIN;
            ALTER TABLE users RENAME TO users_old;
            CREATE TABLE users (
                student_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                group_code_name TEXT
            );
            INSERT INTO users (student_id, name, email, password_hash, group_code_name)
                SELECT student_id, name, email, password_hash, group_code_name FROM users_old;
            DROP TABLE users_old;
            DROP TABLE IF EXISTS predefined_users;
            COMMIT;
            "#,
        )?;
    }

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            student_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            group_code_name TEXT
        );
        CREATE TABLE IF NOT EXISTS groups (
            code_name TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            leader_id TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS group_members (
            group_code_name TEXT NOT NULL,
            student_id TEXT NOT NULL,
            PRIMARY KEY (group_code_name, student_id)
        );
        CREATE TABLE IF NOT EXISTS invitations (
            token TEXT PRIMARY KEY,
            group_code_name TEXT NOT NULL,
            inviter_id TEXT NOT NULL,
            invitee_id TEXT NOT NULL,
            typ TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS join_requests (
            token TEXT PRIMARY KEY,
            group_code_name TEXT NOT NULL,
            requester_id TEXT NOT NULL,
            typ TEXT NOT NULL
        );
        "#,
    )?;
    Ok(())
}

pub fn get_user(
    conn: &Connection,
    student_id: &str,
) -> Result<Option<UserRow>, AppError> {
    let mut stmt = conn.prepare(
        "SELECT student_id, name, email, password_hash, group_code_name \
         FROM users WHERE student_id = ?",
    )?;
    let user = stmt
        .query_row(params![student_id], |row| {
            Ok(UserRow {
                student_id: row.get(0)?,
                name: row.get(1)?,
                email: row.get(2)?,
                password_hash: row.get(3)?,
                group_code_name: row.get(4)?,
            })
        })
        .optional()?;
    Ok(user)
}

pub fn group_members(
    conn: &Connection,
    code_name: &str,
) -> Result<Vec<String>, AppError> {
    let mut stmt = conn.prepare(
        "SELECT student_id FROM group_members WHERE group_code_name = ? ORDER BY student_id",
    )?;
    let rows = stmt.query_map(params![code_name], |row| row.get(0))?;
    let mut members = Vec::new();
    for row in rows {
        members.push(row?);
    }
    Ok(members)
}
