//! Sign-in and sessions. The console keeps its session in a cookie scripts can't read and other
//! sites can't send (HttpOnly, Secure, SameSite=Strict); `synodmgr login` gets a bearer token.
//! Console sessions end after 30 minutes idle, every session 12 hours after sign-in, and every
//! session opened before the account's password last changed.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, Method, StatusCode};
use chrono::{DateTime, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::App;
use crate::api::ApiError;
use crate::audit::Entry;
use crate::crypto;
use crate::passwords;
use crate::users::{self, Attempt, Role, User};

pub const COOKIE: &str = "synodmgr_session";
/// State-changing requests on a console session must carry this header: a page on another site
/// can't add it without the manager allowing that site (it never does).
pub const CSRF_HEADER: &str = "x-synodmgr";
/// The host the request was sent to, set by the manager itself (api.rs) from the URI's authority
/// (HTTP/2) or the Host header; a value a client sends is replaced.
pub const HOST_HEADER: &str = "x-synodmgr-host";

/// Wrong passwords from one address (IPv6: its /64): after this many in the window, it waits.
const ADDRESS_FAILURES: u32 = 20;
const ADDRESS_WINDOW: Duration = Duration::from_secs(600);
/// How long a sign-in waits for a free password check before it is turned away.
const HASH_WAIT: Duration = Duration::from_secs(10);

/// One message for every failed sign-in, so it never tells whether a user ID exists.
pub const SIGN_IN_FAILED: &str =
    "Sign-in failed: the user ID or password is wrong, or the account is paused for up to 15 minutes after repeated failures.";

/// The throttle's key for an address: IPv4 as it is, IPv6 by its /64 (one host's range).
pub fn address_key(address: &str) -> String {
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V6(a)) if a.to_ipv4_mapped().is_none() => {
            let s = a.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        Ok(IpAddr::V6(a)) => a.to_ipv4_mapped().unwrap().to_string(),
        _ => address.to_string(),
    }
}

#[derive(Default)]
pub struct Throttle {
    by_address: Mutex<HashMap<String, (Instant, u32)>>,
}

impl Throttle {
    pub fn blocked(&self, address: &str) -> bool {
        let m = self.by_address.lock().unwrap();
        matches!(m.get(&address_key(address)), Some((start, n)) if start.elapsed() < ADDRESS_WINDOW && *n >= ADDRESS_FAILURES)
    }

    /// Forgets every address (tests; an operator's restart does the same).
    pub fn clear(&self) {
        self.by_address.lock().unwrap().clear();
    }

    pub fn failed(&self, address: &str) {
        let mut m = self.by_address.lock().unwrap();
        if m.len() > 10_000 {
            m.retain(|_, (start, _)| start.elapsed() < ADDRESS_WINDOW);
        }
        let e = m.entry(address_key(address)).or_insert((Instant::now(), 0));
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

/// What the audit log keeps of a user ID typed at a failed sign-in: an existing user's ID as it
/// is; anything else as a short hash (it may be a password typed into the wrong box).
pub fn typed_user_id(typed: &str, exists: bool) -> String {
    if exists {
        typed.to_string()
    } else {
        format!("unknown:{}", &hex::encode(Sha256::digest(typed.as_bytes()))[..12])
    }
}

/// Checks a password against a hash on the blocking pool, a few at a time.
async fn check_password(app: &App, password: &str, hash: String) -> Result<bool, ApiError> {
    let _permit = tokio::time::timeout(HASH_WAIT, app.hashing.acquire())
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "The manager is busy. Try again in a moment.".into()))?
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let pw = password.to_string();
    Ok(tokio::task::spawn_blocking(move || passwords::verify(&pw, &hash)).await.unwrap_or(false))
}

pub async fn sign_in(app: &App, user_id: &str, password: &str, kind: Kind, address: &str) -> Result<SignedIn, ApiError> {
    let cfgp = &app.cfg.passwords;
    let entry = |actor: String, result: String| Entry {
        actor,
        address: address.into(),
        action: "sign_in".into(),
        target: kind.as_str().into(),
        result,
        ..Default::default()
    };
    let failed = || ApiError(StatusCode::UNAUTHORIZED, SIGN_IN_FAILED.into());
    let user = users::by_user_id(&app.db, user_id).await?;
    let actor = typed_user_id(user_id, user.is_some());
    if app.throttle.blocked(address) {
        app.audit.append(entry(actor, "refused: too many failures from this address".into())).await?;
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many failed sign-ins from this address. Wait a few minutes and try again.".into(),
        ));
    }
    // The attempt is counted before the password is checked, in one statement: a burst of
    // concurrent guesses gets no more tries than the limit. Unknown, paused and disabled
    // accounts still have a hash checked, so every failure takes as long.
    let attempt = match &user {
        Some(u) => users::reserve_attempt(&app.db, u.id, cfgp.lockout_failures, cfgp.lockout_minutes).await?,
        None => Attempt::Refused,
    };
    let hash = match (&user, attempt) {
        (Some(u), Attempt::Counted { .. }) => u.password_hash.clone(),
        _ => passwords::dummy_hash().to_string(),
    };
    let ok = check_password(app, password, hash).await?;
    let Some(user) = user else {
        app.throttle.failed(address);
        app.audit.append(entry(actor, "failed: unknown user ID".into())).await?;
        return Err(failed());
    };
    let Attempt::Counted { locks } = attempt else {
        app.throttle.failed(address);
        let why = if user.disabled { "failed: account disabled".to_string() } else { "failed: account paused".to_string() };
        app.audit.append(entry(actor, why)).await?;
        return Err(failed());
    };
    if !ok {
        app.throttle.failed(address);
        let why = if locks {
            format!("failed: wrong password; {} in a row: paused for {} minutes", cfgp.lockout_failures, cfgp.lockout_minutes)
        } else {
            "failed: wrong password".into()
        };
        app.audit.append(entry(actor, why)).await?;
        return Err(failed());
    }
    users::record_success(&app.db, user.id).await?;
    let token = crypto::new_token();
    let expires_at = Utc::now() + chrono::Duration::hours(app.cfg.sessions.max_hours);
    let c = app.db.get().await?;
    // the password version read before the check: if the password changed meanwhile, this
    // session is refused at its first use
    c.execute(
        "INSERT INTO sessions (token_hash, user_ref, kind, expires_at, address, password_version)
         VALUES ($1, $2, $3, $4, $5, $6)",
        &[&crypto::token_hash(&token), &user.id, &kind.as_str(), &expires_at, &address, &user.password_version],
    )
    .await?;
    let must_change = user.must_change || expired_password(app, &user);
    app.audit
        .append(entry(user.user_id.clone(), if must_change { "ok: must change the password".into() } else { "ok".into() }))
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
/// the browser sends one) must be the host it was sent to.
fn csrf_ok(headers: &HeaderMap) -> bool {
    if headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()) != Some("1") {
        return false;
    }
    let host = headers
        .get(HOST_HEADER)
        .or_else(|| headers.get("host"))
        .and_then(|v| v.to_str().ok());
    match (headers.get("origin").and_then(|v| v.to_str().ok()), host) {
        (Some(o), Some(h)) => o.split_once("://").map(|(_, rest)| rest) == Some(h),
        (Some(_), None) => false,
        (None, _) => true,
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
    let c = app.db.get().await?;
    let row = c
        .query_opt(
            "SELECT s.user_ref, s.kind, s.last_seen, s.expires_at, s.password_version = u.password_version
             FROM sessions s JOIN users u ON u.id = s.user_ref WHERE s.token_hash = $1",
            &[&th],
        )
        .await?
        .ok_or_else(unauth)?;
    let user_ref: i64 = row.get(0);
    let kind = if row.get::<_, &str>(1) == "web" { Kind::Web } else { Kind::Cli };
    let last_seen: DateTime<Utc> = row.get(2);
    let expires_at: DateTime<Utc> = row.get(3);
    let same_password: bool = row.get(4);
    let now = Utc::now();
    let idle_out = kind == Kind::Web && last_seen + chrono::Duration::minutes(app.cfg.sessions.idle_minutes) < now;
    if expires_at < now || idle_out || !same_password {
        c.execute("DELETE FROM sessions WHERE token_hash = $1", &[&th]).await?;
        return Err(ApiError(StatusCode::UNAUTHORIZED, "Your session ended. Sign in again.".into()));
    }
    let user = users::by_id(&app.db, user_ref).await?.ok_or_else(unauth)?;
    if user.disabled {
        c.execute("DELETE FROM sessions WHERE user_ref = $1", &[&user.id]).await?;
        return Err(unauth());
    }
    if now - last_seen > chrono::Duration::seconds(30) {
        c.execute("UPDATE sessions SET last_seen = now() WHERE token_hash = $1", &[&th]).await?;
    }
    let must_change = user.must_change || expired_password(app, &user);
    Ok(Principal { user, kind, token_hash: th, address: address.to_string(), must_change })
}

pub async fn sign_out(app: &App, p: &Principal) -> Result<(), ApiError> {
    let c = app.db.get().await?;
    c.execute("DELETE FROM sessions WHERE token_hash = $1", &[&p.token_hash]).await?;
    app.audit.append(Entry { result: "ok".into(), ..p.entry("sign_out", p.kind.as_str()) }).await?;
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

/// The current password is checked like a sign-in: each try counts toward the lockout, and the
/// try that pauses the account also signs it out everywhere.
pub async fn change_own_password(app: &App, p: &Principal, current: &str, new: &str) -> Result<(), ApiError> {
    let cfgp = &app.cfg.passwords;
    let attempt = users::reserve_attempt(&app.db, p.user.id, cfgp.lockout_failures, cfgp.lockout_minutes).await?;
    let hash = match attempt {
        Attempt::Counted { .. } => p.user.password_hash.clone(),
        Attempt::Refused => passwords::dummy_hash().to_string(),
    };
    let ok = check_password(app, current, hash).await?;
    if !ok {
        let locks = matches!(attempt, Attempt::Counted { locks: true }) || attempt == Attempt::Refused;
        let mut result = "failed: wrong current password".to_string();
        if locks {
            let n = end_sessions(app, p.user.id, None).await?;
            result = format!("failed: wrong current password; account paused, {n} sessions signed out");
        }
        app.audit.append(Entry { result, ..p.entry("password_change", &p.user.user_id) }).await?;
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            if locks {
                "The current password is wrong. After repeated failures the account is paused and signed out.".into()
            } else {
                "The current password is wrong.".into()
            },
        ));
    }
    users::record_success(&app.db, p.user.id).await?;
    if current == new {
        return Err(ApiError(StatusCode::BAD_REQUEST, "Choose a password different from the current one.".into()));
    }
    if let Some(why) = passwords::check(new, &p.user.user_id, &p.user.name, cfgp) {
        app.audit.append(Entry { result: format!("refused: {why}"), ..p.entry("password_change", &p.user.user_id) }).await?;
        return Err(ApiError(StatusCode::BAD_REQUEST, why));
    }
    let n = new.to_string();
    let hash = tokio::task::spawn_blocking(move || passwords::hash(&n)).await.map_err(anyhow::Error::from)?;
    let version = users::set_password(&app.db, p.user.id, &hash, false).await?;
    // this session goes on with the new password; every other one ends
    let c = app.db.get().await?;
    c.execute("UPDATE sessions SET password_version = $2 WHERE token_hash = $1", &[&p.token_hash, &version]).await?;
    let ended = end_sessions(app, p.user.id, Some(&p.token_hash)).await?;
    app.audit
        .append(Entry {
            result: "ok".into(),
            request: json!({ "other_sessions_ended": ended }),
            ..p.entry("password_change", &p.user.user_id)
        })
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
        // IPv6: the whole /64 counts as one address
        for i in 0..ADDRESS_FAILURES {
            t.failed(&format!("2001:db8:1:2::{i:x}"));
        }
        assert!(t.blocked("2001:db8:1:2:ffff::1"));
        assert!(!t.blocked("2001:db8:1:3::1"));
        assert_eq!(address_key("::ffff:10.0.0.9"), "10.0.0.9");
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
        h.insert("origin", HeaderValue::from_static("https://mgr.example:8443"));
        assert!(!csrf_ok(&h), "an Origin with no host to compare: refused");
        h.insert(HOST_HEADER, HeaderValue::from_static("mgr.example:8443"));
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

    #[test]
    fn typed_ids() {
        assert_eq!(typed_user_id("ann", true), "ann");
        let t = typed_user_id("my secret password 123", false);
        assert!(t.starts_with("unknown:") && t.len() == 20 && !t.contains("secret"));
        assert_eq!(t, typed_user_id("my secret password 123", false), "the same typing, the same entry");
    }
}
