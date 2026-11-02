//! Accounts: the user rows and what changes them. Every change is audited by the caller.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::db::Db;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Viewer,
}

impl Role {
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "admin" => Some(Role::Admin),
            "viewer" => Some(Role::Viewer),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Viewer => "viewer",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct User {
    #[serde(skip)]
    pub id: i64,
    pub user_id: String,
    pub name: String,
    pub role: Role,
    #[serde(skip)]
    pub password_hash: String,
    pub must_change: bool,
    pub disabled: bool,
    #[serde(skip)]
    pub failed_count: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub password_set_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_sign_in: Option<DateTime<Utc>>,
    #[serde(skip)]
    pub password_version: i32,
}

const COLS: &str = "id, user_id, name, role, password_hash, must_change, disabled, failed_count, locked_until, \
                    password_set_at, created_at, last_sign_in, password_version";

fn from_row(r: &tokio_postgres::Row) -> User {
    User {
        id: r.get(0),
        user_id: r.get(1),
        name: r.get(2),
        role: Role::parse(r.get::<_, &str>(3)).unwrap_or(Role::Viewer),
        password_hash: r.get(4),
        must_change: r.get(5),
        disabled: r.get(6),
        failed_count: r.get(7),
        locked_until: r.get(8),
        password_set_at: r.get(9),
        created_at: r.get(10),
        last_sign_in: r.get(11),
        password_version: r.get(12),
    }
}

/// A user ID: 1 to 64 of letters, digits, '.', '_', '-', '@' (an email address works).
pub fn valid_user_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
}

pub async fn by_user_id(db: &Db, user_id: &str) -> Result<Option<User>> {
    let c = db.get().await?;
    Ok(c.query_opt(&format!("SELECT {COLS} FROM users WHERE user_id = $1"), &[&user_id])
        .await?
        .map(|r| from_row(&r)))
}

pub async fn by_id(db: &Db, id: i64) -> Result<Option<User>> {
    let c = db.get().await?;
    Ok(c.query_opt(&format!("SELECT {COLS} FROM users WHERE id = $1"), &[&id]).await?.map(|r| from_row(&r)))
}

pub async fn list(db: &Db) -> Result<Vec<User>> {
    let c = db.get().await?;
    Ok(c.query(&format!("SELECT {COLS} FROM users ORDER BY user_id"), &[]).await?.iter().map(from_row).collect())
}

/// A new account with a password hash; false if the user ID is taken.
pub async fn create(db: &Db, user_id: &str, name: &str, role: Role, hash: &str, must_change: bool) -> Result<bool> {
    let c = db.get().await?;
    let n = c
        .execute(
            "INSERT INTO users (user_id, name, role, password_hash, must_change) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (user_id) DO NOTHING",
            &[&user_id, &name, &role.as_str(), &hash, &must_change],
        )
        .await?;
    Ok(n == 1)
}

/// A new password: `must_change` for one an admin or root set; the lockout is cleared and the
/// password version goes up (sessions opened with the old one end). Returns the new version.
pub async fn set_password(db: &Db, id: i64, hash: &str, must_change: bool) -> Result<i32> {
    let c = db.get().await?;
    Ok(c.query_one(
        "UPDATE users SET password_hash = $2, must_change = $3, password_set_at = now(), failed_count = 0,
                          locked_until = NULL, password_version = password_version + 1
         WHERE id = $1 RETURNING password_version",
        &[&id, &hash, &must_change],
    )
    .await?
    .get(0))
}

/// `update`, refused (false) when it would leave no enabled administrator: the check and the change
/// in one transaction that holds every enabled administrator's row, so two administrators
/// disabling each other at once can't both succeed.
pub async fn update_guarded(db: &Db, id: i64, name: Option<&str>, role: Option<Role>, disabled: Option<bool>) -> Result<bool> {
    let mut c = db.get().await?;
    let tx = c.transaction().await?;
    let admins: Vec<i64> = tx
        .query("SELECT id FROM users WHERE role = 'admin' AND NOT disabled ORDER BY id FOR UPDATE", &[])
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let removes = admins.contains(&id) && (role == Some(Role::Viewer) || disabled == Some(true));
    if removes && admins.iter().all(|&a| a == id) {
        return Ok(false);
    }
    tx.execute(
        "UPDATE users SET name = COALESCE($2, name), role = COALESCE($3, role), disabled = COALESCE($4, disabled)
         WHERE id = $1",
        &[&id, &name, &role.map(|r| r.as_str()), &disabled],
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

pub async fn update(db: &Db, id: i64, name: Option<&str>, role: Option<Role>, disabled: Option<bool>) -> Result<()> {
    let c = db.get().await?;
    c.execute(
        "UPDATE users SET name = COALESCE($2, name), role = COALESCE($3, role), disabled = COALESCE($4, disabled)
         WHERE id = $1",
        &[&id, &name, &role.map(|r| r.as_str()), &disabled],
    )
    .await?;
    Ok(())
}

pub async fn unlock(db: &Db, id: i64) -> Result<()> {
    let c = db.get().await?;
    c.execute("UPDATE users SET failed_count = 0, locked_until = NULL WHERE id = $1", &[&id]).await?;
    Ok(())
}

/// What reserving a password attempt found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    /// The account is paused (or disabled): no attempt.
    Refused,
    /// Counted as a failure until it succeeds; `locks` if it was the last one allowed.
    Counted { locks: bool },
}

/// Counts a password attempt before the password is checked, in one statement, so concurrent
/// attempts can't get past the limit: at `limit` attempts in a row the account waits `minutes`
/// (the count starts over then). A correct password clears it (`record_success`).
pub async fn reserve_attempt(db: &Db, id: i64, limit: i32, minutes: i64) -> Result<Attempt> {
    let c = db.get().await?;
    let r = c
        .query_opt(
            "UPDATE users SET failed_count = CASE WHEN failed_count + 1 >= $2 THEN 0 ELSE failed_count + 1 END,
                              locked_until = CASE WHEN failed_count + 1 >= $2
                                                  THEN now() + make_interval(mins => $3::int) ELSE NULL END
             WHERE id = $1 AND NOT disabled AND (locked_until IS NULL OR locked_until <= now())
             RETURNING locked_until IS NOT NULL",
            &[&id, &limit, &(minutes as i32)],
        )
        .await?;
    Ok(match r {
        None => Attempt::Refused,
        Some(row) => Attempt::Counted { locks: row.get(0) },
    })
}

pub async fn record_success(db: &Db, id: i64) -> Result<()> {
    let c = db.get().await?;
    c.execute("UPDATE users SET failed_count = 0, locked_until = NULL, last_sign_in = now() WHERE id = $1", &[&id])
        .await?;
    Ok(())
}

/// Enabled admins other than `except` (an admin can't remove the last way in).
pub async fn other_active_admins(db: &Db, except: i64) -> Result<i64> {
    let c = db.get().await?;
    Ok(c.query_one(
        "SELECT count(*) FROM users WHERE role = 'admin' AND NOT disabled AND id <> $1",
        &[&except],
    )
    .await?
    .get(0))
}

pub async fn any_admin(db: &Db) -> Result<bool> {
    let c = db.get().await?;
    Ok(c.query_one("SELECT EXISTS (SELECT 1 FROM users WHERE role = 'admin')", &[]).await?.get(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_ids() {
        assert!(valid_user_id("ann"));
        assert!(valid_user_id("ann.lee@example.com"));
        assert!(!valid_user_id(""));
        assert!(!valid_user_id("ann lee"));
        assert!(!valid_user_id("ann'--"));
        assert!(!valid_user_id(&"a".repeat(65)));
        assert_eq!(Role::parse("admin"), Some(Role::Admin));
        assert_eq!(Role::parse("root"), None);
    }
}
