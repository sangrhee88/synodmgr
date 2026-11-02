//! Sign-in and sessions. The console keeps its session in a cookie scripts can't read and other
//! sites can't send (HttpOnly, Secure, SameSite=Strict); `synodmgr login` gets a bearer token.
//! Console sessions end after 30 minutes idle, every session 12 hours after sign-in.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, Method, StatusCode};
use chrono::{DateTime, Utc};
use serde_json::json;

use crate::App;
use crate::api::ApiError;
use crate::audit::{self, Entry};
use crate::crypto;
use crate::passwords;
use crate::users::{self, Role, User};

pub const COOKIE: &str = "synodmgr_session";
/// State-changing requests on a console session must carry this header: a page on another site
/// can't add it without the manager allowing that site (it never does).
pub const CSRF_HEADER: &str = "x-synodmgr";

/// Wrong passwords from one address: after this many in the window, that address waits.
const ADDRESS_FAILURES: u32 = 20;
const ADDRESS_WINDOW: Duration = Duration::from_secs(600);

/// One message for every failed sign-in, so it never tells whether a user ID exists.
pub const SIGN_IN_FAILED: &str =
    "Sign-in failed: the user ID or password is wrong, or the account is paused for up to 15 minutes after repeated failures.";

#[derive(Default)]
pub struct Throttle {
    by_address: Mutex<HashMap<String, (Instant, u32)>>,
}

impl Throttle {
    pub fn blocked(&self, address: &str) -> bool {
        let m = self.by_address.lock().unwrap();
        matches!(m.get(address), Some((start, n)) if start.elapsed() < ADDRESS_WINDOW && *n >= ADDRESS_FAILURES)
    }

    pub fn failed(&self, address: &str) {
        let mut m = self.by_address.lock().unwrap();
        if m.len() > 10_000 {
            m.retain(|_, (start, _)| start.elapsed() < ADDRESS_WINDOW);
        }
        let e = m.entry(address.to_string()).or_insert((Instant::now(), 0));
        if e.0.elapsed() >= ADDRESS_WINDOW {
            *e = (Instant::now(), 0);
        }
        e.1 += 1;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Web,
    Cli,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Web => "web",
            Kind::Cli => "cli",
        }
    }
}

/// Who is asking.
#[derive(Debug, Clone)]
pub struct Principal {
    pub user: User,
    pub kind: Kind,
    pub token_hash: Vec<u8>,
    pub address: String,
    /// The password must be changed before anything else (first sign-in, a reset, an expiry).
    pub must_change: bool,
}

impl Principal {
    /// Anything but the account's own password change and sign-out.
    pub fn ready(&self) -> Result<(), ApiError> {
        if self.must_change {
            return Err(ApiError(StatusCode::FORBIDDEN, "Change your password first (POST /api/v1/me/password).".into()));
        }
        Ok(())
    }

    pub fn admin(&self) -> Result<(), ApiError> {
        self.ready()?;
        if self.user.role != Role::Admin {
            return Err(ApiError(StatusCode::FORBIDDEN, "Only an administrator can do this.".into()));
        }
        Ok(())
    }

    pub fn entry(&self, action: &str, target: &str) -> Entry {
        Entry {
            actor: self.user.user_id.clone(),
            address: self.address.clone(),
            action: action.into(),
            target: target.into(),
            ..Default::default()
        }
    }
}

pub struct SignedIn {
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub user: User,
    pub must_change: bool,
}

fn expired_password(app: &App, u: &User) -> bool {
    let d = app.cfg.passwords.expire_days;
    d > 0 && u.password_set_at < Utc::now() - chrono::Duration::days(d)
}

pub async fn sign_in(app: &App, user_id: &str, password: &str, kind: Kind, address: &str) -> Result<SignedIn, ApiError> {
    let fail = |why: &str| {
        let e = Entry {
            actor: user_id.chars().take(64).collect(),
            address: address.into(),
            action: "sign_in".into(),
            target: kind.as_str().into(),
            result: format!("failed: {why}"),
            ..Default::default()
        };
        (e, ApiError(StatusCode::UNAUTHORIZED, SIGN_IN_FAILED.into()))
    };
    if app.throttle.blocked(address) {
        let (mut e, _) = fail("too many failures from this address");
        e.result = "refused: too many failures from this address".into();
        audit::append(&app.db, e).await?;
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many failed sign-ins from this address. Wait a few minutes and try again.".into(),
        ));
    }
    let user = users::by_user_id(&app.db, user_id).await?;
    // the hash is checked even for an unknown user ID, so both take as long
    let hash = user.as_ref().map(|u| u.password_hash.clone()).unwrap_or_else(|| passwords::dummy_hash().to_string());
    let pw = password.to_string();
    let ok = tokio::task::spawn_blocking(move || passwords::verify(&pw, &hash)).await.unwrap_or(false);
    let Some(user) = user else {
        app.throttle.failed(address);
        let (e, err) = fail("unknown user ID");
        audit::append(&app.db, e).await?;
        return Err(err);
    };
    if user.disabled {
        app.throttle.failed(address);
        let (e, err) = fail("account disabled");
        audit::append(&app.db, e).await?;
        return Err(err);
    }
    if let Some(t) = user.locked_until {
        if t > Utc::now() {
            app.throttle.failed(address);
            let (e, err) = fail(&format!("account paused until {}", t.format("%H:%M:%S UTC")));
            audit::append(&app.db, e).await?;
            return Err(err);
        }
    }
    if !ok {
        app.throttle.failed(address);
        let locked = users::record_failure(
            &app.db,
            user.id,
            app.cfg.passwords.lockout_failures,
            app.cfg.passwords.lockout_minutes,
        )
        .await?;
        let why = if locked {
            format!(
                "wrong password; {} in a row: paused for {} minutes",
                app.cfg.passwords.lockout_failures, app.cfg.passwords.lockout_minutes
            )
        } else {
            "wrong password".into()
        };
        let (e, err) = fail(&why);
        audit::append(&app.db, e).await?;
        return Err(err);
    }
    users::record_success(&app.db, user.id).await?;
    let token = crypto::new_token();
    let expires_at = Utc::now() + chrono::Duration::hours(app.cfg.sessions.max_hours);
    let c = app.db.get().await.map_err(anyhow::Error::from)?;
    c.execute(
        "INSERT INTO sessions (token_hash, user_ref, kind, expires_at, address) VALUES ($1, $2, $3, $4, $5)",
        &[&crypto::token_hash(&token), &user.id, &kind.as_str(), &expires_at, &address],
    )
    .await
    .map_err(anyhow::Error::from)?;
    let must_change = user.must_change || expired_password(app, &user);
    audit::append(
        &app.db,
        Entry {
            actor: user.user_id.clone(),
            address: address.into(),
            action: "sign_in".into(),
            target: kind.as_str().into(),
            result: if must_change { "ok: must change the password".into() } else { "ok".into() },
            ..Default::default()
        },
    )
    .await?;
    Ok(SignedIn { token, expires_at, user, must_change })
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    for v in headers.get_all(axum::http::header::COOKIE) {
        for part in v.to_str().ok()?.split(';') {
            if let Some((k, val)) = part.trim().split_once('=') {
                if k == COOKIE && !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    v.strip_prefix("Bearer ").map(|t| t.trim().to_string()).filter(|t| !t.is_empty())
}

/// A console request that changes something must carry the CSRF header, and its Origin (when
/// the browser sends one) must be this host.
fn csrf_ok(headers: &HeaderMap) -> bool {
    if headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()) != Some("1") {
        return false;
    }
    match (headers.get("origin").and_then(|v| v.to_str().ok()), headers.get("host").and_then(|v| v.to_str().ok())) {
        (Some(o), Some(h)) => o.split_once("://").map(|(_, rest)| rest) == Some(h),
        _ => true,
    }
}

pub async fn authenticate(app: &App, headers: &HeaderMap, method: &Method, address: &str) -> Result<Principal, ApiError> {
    let unauth = || ApiError(StatusCode::UNAUTHORIZED, "Sign in first.".into());
    let (token, from_cookie) = match (bearer_token(headers), cookie_token(headers)) {
        (Some(t), _) => (t, false),
        (None, Some(t)) => (t, true),
        _ => return Err(unauth()),
    };
    if from_cookie && *method != Method::GET && *method != Method::HEAD && !csrf_ok(headers) {
        return Err(ApiError(StatusCode::FORBIDDEN, "Missing the console's request header (x-synodmgr).".into()));
    }
    let th = crypto::token_hash(&token);
    let c = app.db.get().await.map_err(anyhow::Error::from)?;
    let row = c
        .query_opt(
            "SELECT user_ref, kind, last_seen, expires_at FROM sessions WHERE token_hash = $1",
            &[&th],
        )
        .await
        .map_err(anyhow::Error::from)?
        .ok_or_else(unauth)?;
    let user_ref: i64 = row.get(0);
    let kind = if row.get::<_, &str>(1) == "web" { Kind::Web } else { Kind::Cli };
    let last_seen: DateTime<Utc> = row.get(2);
    let expires_at: DateTime<Utc> = row.get(3);
    let now = Utc::now();
    let idle_out = kind == Kind::Web && last_seen + chrono::Duration::minutes(app.cfg.sessions.idle_minutes) < now;
    if expires_at < now || idle_out {
        c.execute("DELETE FROM sessions WHERE token_hash = $1", &[&th]).await.map_err(anyhow::Error::from)?;
        return Err(ApiError(StatusCode::UNAUTHORIZED, "Your session ended. Sign in again.".into()));
    }
    let user = users::by_id(&app.db, user_ref).await?.ok_or_else(unauth)?;
    if user.disabled {
        c.execute("DELETE FROM sessions WHERE user_ref = $1", &[&user.id]).await.map_err(anyhow::Error::from)?;
        return Err(unauth());
    }
    if now - last_seen > chrono::Duration::seconds(30) {
        c.execute("UPDATE sessions SET last_seen = now() WHERE token_hash = $1", &[&th])
            .await
            .map_err(anyhow::Error::from)?;
    }
    let must_change = user.must_change || expired_password(app, &user);
    Ok(Principal { user, kind, token_hash: th, address: address.to_string(), must_change })
}

pub async fn sign_out(app: &App, p: &Principal) -> Result<(), ApiError> {
    let c = app.db.get().await.map_err(anyhow::Error::from)?;
    c.execute("DELETE FROM sessions WHERE token_hash = $1", &[&p.token_hash]).await.map_err(anyhow::Error::from)?;
    audit::append(&app.db, Entry { result: "ok".into(), ..p.entry("sign_out", p.kind.as_str()) }).await?;
    Ok(())
}

/// Ends a user's sessions; `keep` one of them (the one that changed its own password).
pub async fn end_sessions(app: &App, user_ref: i64, keep: Option<&[u8]>) -> anyhow::Result<u64> {
    let c = app.db.get().await?;
    Ok(match keep {
        Some(k) => {
            c.execute("DELETE FROM sessions WHERE user_ref = $1 AND token_hash <> $2", &[&user_ref, &k]).await?
        }
        None => c.execute("DELETE FROM sessions WHERE user_ref = $1", &[&user_ref]).await?,
    })
}

/// The Set-Cookie value for a console session (or for ending one, with an empty token).
pub fn session_cookie(token: &str, secure: bool, max_age_s: i64) -> String {
    format!(
        "{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age_s}{}",
        if secure { "; Secure" } else { "" }
    )
}

pub async fn change_own_password(app: &App, p: &Principal, current: &str, new: &str) -> Result<(), ApiError> {
    let hash = p.user.password_hash.clone();
    let cur = current.to_string();
    let ok = tokio::task::spawn_blocking(move || passwords::verify(&cur, &hash)).await.unwrap_or(false);
    if !ok {
        audit::append(&app.db, Entry { result: "failed: wrong current password".into(), ..p.entry("password_change", &p.user.user_id) })
            .await?;
        return Err(ApiError(StatusCode::BAD_REQUEST, "The current password is wrong.".into()));
    }
    if current == new {
        return Err(ApiError(StatusCode::BAD_REQUEST, "Choose a password different from the current one.".into()));
    }
    if let Some(why) = passwords::check(new, &p.user.user_id, &p.user.name, &app.cfg.passwords) {
        audit::append(&app.db, Entry { result: format!("refused: {why}"), ..p.entry("password_change", &p.user.user_id) })
            .await?;
        return Err(ApiError(StatusCode::BAD_REQUEST, why));
    }
    let n = new.to_string();
    let hash = tokio::task::spawn_blocking(move || passwords::hash(&n)).await.map_err(anyhow::Error::from)?;
    users::set_password(&app.db, p.user.id, &hash, false).await?;
    let ended = end_sessions(app, p.user.id, Some(&p.token_hash)).await?;
    audit::append(
        &app.db,
        Entry {
            result: "ok".into(),
            request: json!({ "other_sessions_ended": ended }),
            ..p.entry("password_change", &p.user.user_id)
        },
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn throttle() {
        let t = Throttle::default();
        for _ in 0..ADDRESS_FAILURES - 1 {
            t.failed("10.0.0.9");
        }
        assert!(!t.blocked("10.0.0.9"));
        t.failed("10.0.0.9");
        assert!(t.blocked("10.0.0.9"));
        assert!(!t.blocked("10.0.0.8"));
    }

    #[test]
    fn tokens_from_headers() {
        let mut h = HeaderMap::new();
        h.insert("cookie", HeaderValue::from_static("a=b; synodmgr_session=tok123; c=d"));
        assert_eq!(cookie_token(&h).as_deref(), Some("tok123"));
        h.insert("authorization", HeaderValue::from_static("Bearer xyz"));
        assert_eq!(bearer_token(&h).as_deref(), Some("xyz"));
    }

    #[test]
    fn csrf() {
        let mut h = HeaderMap::new();
        assert!(!csrf_ok(&h));
        h.insert(CSRF_HEADER, HeaderValue::from_static("1"));
        assert!(csrf_ok(&h));
        h.insert("host", HeaderValue::from_static("mgr.example:8443"));
        h.insert("origin", HeaderValue::from_static("https://mgr.example:8443"));
        assert!(csrf_ok(&h));
        h.insert("origin", HeaderValue::from_static("https://evil.example"));
        assert!(!csrf_ok(&h));
    }

    #[test]
    fn cookie() {
        let c = session_cookie("t", true, 43200);
        assert!(c.contains("HttpOnly") && c.contains("SameSite=Strict") && c.contains("Secure") && c.contains("Max-Age=43200"));
        assert!(!session_cookie("t", false, 1).contains("Secure"));
    }
}
