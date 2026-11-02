//! The API against a real state database: sign-in rules, lockout, sessions, roles, users, the
//! audit chain. Needs a scratch Postgres the test may create databases in:
//!
//!     SYNODMGR_TEST_DATABASE_URL="host=/var/tmp/synodmgr-pg port=55432 user=postgres" cargo test --test api
//!
//! (key=value form, without dbname). Skipped when the variable is unset.

use std::net::SocketAddr;

use reqwest::StatusCode;
use serde_json::{Value, json};
use synod_manager::config::{Config, PasswordConfig, SessionConfig};
use synod_manager::{AppState, api, db, passwords, users};
use tokio_postgres::NoTls;

const ADMIN_PW: &str = "initial one-time pass 77";

struct Env {
    base: String,
    http: reqwest::Client,
    db_url: String,
    _dir: tempfile::TempDir,
}

async fn start() -> Option<Env> {
    let base_url = std::env::var("SYNODMGR_TEST_DATABASE_URL").ok()?;
    let name = format!("synodmgr_test_{}", std::process::id());
    let (c, conn) = tokio_postgres::connect(&format!("{base_url} dbname=postgres"), NoTls).await.unwrap();
    tokio::spawn(conn);
    c.batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)")).await.unwrap();
    c.batch_execute(&format!("CREATE DATABASE {name}")).await.unwrap();
    let db_url = format!("{base_url} dbname={name}");
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        database_url: db_url.clone(),
        tls_cert: None,
        tls_key: None,
        plain_http_on_loopback: true,
        key_file: dir.path().join("key"),
        data_dir: dir.path().join("data"),
        metrics_url: "http://127.0.0.1:9".into(),
        sessions: SessionConfig::default(),
        passwords: PasswordConfig::default(),
    };
    let app = AppState::new(cfg).unwrap();
    db::migrate(&app.db).await.unwrap();
    users::create(&app.db, "admin", "Administrator", users::Role::Admin, &passwords::hash(ADMIN_PW), true)
        .await
        .unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let router = api::router(app).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    Some(Env { base: format!("http://{addr}"), http: reqwest::Client::new(), db_url, _dir: dir })
}

impl Env {
    async fn sql(&self, q: &str) -> Vec<tokio_postgres::Row> {
        let (c, conn) = tokio_postgres::connect(&self.db_url, NoTls).await.unwrap();
        tokio::spawn(conn);
        c.query(q, &[]).await.unwrap()
    }

    async fn sign_in(&self, user: &str, pw: &str) -> (StatusCode, Value) {
        let r = self
            .http
            .post(format!("{}/api/v1/sign-in", self.base))
            .json(&json!({ "user_id": user, "password": pw, "client": "cli" }))
            .send()
            .await
            .unwrap();
        (r.status(), r.json().await.unwrap_or(Value::Null))
    }

    async fn token(&self, user: &str, pw: &str) -> String {
        let (s, v) = self.sign_in(user, pw).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        v["token"].as_str().unwrap().to_string()
    }

    async fn call(&self, method: &str, path: &str, token: &str, body: Option<Value>) -> (StatusCode, Value) {
        let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let mut r = self.http.request(m, format!("{}{path}", self.base)).bearer_auth(token);
        if let Some(b) = body {
            r = r.json(&b);
        }
        let r = r.send().await.unwrap();
        let s = r.status();
        let text = r.text().await.unwrap();
        (s, serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }
}

const GOOD: &str = "lantern orbit cactus mellow";
const GOOD2: &str = "violet harbor tundra pickle";

#[tokio::test]
async fn sign_in_accounts_and_audit() {
    let Some(e) = start().await else {
        eprintln!("SYNODMGR_TEST_DATABASE_URL is not set: skipping");
        return;
    };

    // --- open endpoints; nothing else without a session ---
    let r = e.http.get(format!("{}/api/v1/health", e.base)).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["x-frame-options"], "DENY");
    let (s, _) = e.call("GET", "/api/v1/installations", "nonsense", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // --- the same message for an unknown user and a wrong password ---
    let (s1, v1) = e.sign_in("nobody", "whatever whatever").await;
    let (s2, v2) = e.sign_in("admin", "wrong wrong wrong").await;
    assert_eq!((s1, s2), (StatusCode::UNAUTHORIZED, StatusCode::UNAUTHORIZED));
    assert_eq!(v1["error"], v2["error"]);

    // --- first sign-in: the one-time password must be changed before anything else ---
    let t = e.token("admin", ADMIN_PW).await;
    let (s, v) = e.call("GET", "/api/v1/me", &t, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["must_change_password"], true);
    let (s, v) = e.call("GET", "/api/v1/installations", &t, None).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(v["error"].as_str().unwrap().contains("Change your password first"));
    // rules
    for (bad, why) in [("short one", "at least 15"), ("passwordpassword1", "too easy"), ("admin is my name ok ok ok", "user ID")] {
        let (s, v) = e.call("POST", "/api/v1/me/password", &t, Some(json!({"current_password": ADMIN_PW, "new_password": bad}))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {v}");
        assert!(v["error"].as_str().unwrap().contains(why), "{bad}: {v}");
    }
    let (s, _) = e.call("POST", "/api/v1/me/password", &t, Some(json!({"current_password": "wrong", "new_password": GOOD}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // a second session of the same user ends when the password changes
    let t_other = e.token("admin", ADMIN_PW).await;
    let (s, v) = e.call("POST", "/api/v1/me/password", &t, Some(json!({"current_password": ADMIN_PW, "new_password": GOOD}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(e.call("GET", "/api/v1/me", &t_other, None).await.0, StatusCode::UNAUTHORIZED, "other session signed out");
    assert_eq!(e.call("GET", "/api/v1/installations", &t, None).await.0, StatusCode::OK, "this session goes on");
    assert_eq!(e.sign_in("admin", ADMIN_PW).await.0, StatusCode::UNAUTHORIZED, "the old password is gone");
    let stored: String = e.sql("SELECT password_hash FROM users WHERE user_id = 'admin'").await[0].get(0);
    assert!(stored.starts_with("$argon2id$") && !stored.contains(GOOD));

    // --- an administrator adds a viewer, with a temporary password shown once ---
    let (s, v) = e.call("POST", "/api/v1/users", &t, Some(json!({"user_id": "bob", "name": "Bob Lee", "role": "viewer"}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let temp = v["temporary_password"].as_str().unwrap().to_string();
    assert_eq!(e.call("POST", "/api/v1/users", &t, Some(json!({"user_id": "bob", "role": "viewer"}))).await.0, StatusCode::CONFLICT);
    assert_eq!(e.call("POST", "/api/v1/users", &t, Some(json!({"user_id": "bad id", "role": "viewer"}))).await.0, StatusCode::BAD_REQUEST);
    let tb = e.token("bob", &temp).await;
    assert_eq!(e.call("GET", "/api/v1/fleet", &tb, None).await.0, StatusCode::FORBIDDEN, "bob must change first");
    let (s, v) = e.call("POST", "/api/v1/me/password", &tb, Some(json!({"current_password": temp, "new_password": GOOD2}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // a viewer sees, but doesn't administer
    assert_eq!(e.call("GET", "/api/v1/fleet", &tb, None).await.0, StatusCode::OK);
    assert_eq!(e.call("GET", "/api/v1/users", &tb, None).await.0, StatusCode::FORBIDDEN);
    assert_eq!(e.call("POST", "/api/v1/users", &tb, Some(json!({"user_id": "eve", "role": "admin"}))).await.0, StatusCode::FORBIDDEN);
    let (s, v) = e.call("GET", "/api/v1/users", &t, None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(v.to_string().contains("\"bob\"") && !v.to_string().contains("argon2"), "no hashes in answers: {v}");

    // --- lockout: 10 wrong passwords in a row, then even the right one waits ---
    for _ in 0..10 {
        assert_eq!(e.sign_in("bob", "not bob's password at all").await.0, StatusCode::UNAUTHORIZED);
    }
    let (s, v) = e.sign_in("bob", GOOD2).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "paused: {v}");
    assert_eq!(v["error"], v1["error"], "the same message");
    let locked: bool = e.sql("SELECT locked_until > now() FROM users WHERE user_id = 'bob'").await[0].get(0);
    assert!(locked);
    assert_eq!(e.call("POST", "/api/v1/users/bob/unlock", &t, None).await.0, StatusCode::OK);
    let tb = e.token("bob", GOOD2).await;

    // --- an administrator resets bob's password: his sessions end, he must change it ---
    let (s, v) = e.call("POST", "/api/v1/users/bob/reset-password", &t, None).await;
    assert_eq!(s, StatusCode::OK);
    let temp2 = v["temporary_password"].as_str().unwrap().to_string();
    assert_eq!(e.call("GET", "/api/v1/me", &tb, None).await.0, StatusCode::UNAUTHORIZED);
    let tb = e.token("bob", &temp2).await;
    assert_eq!(e.call("GET", "/api/v1/me", &tb, None).await.1["must_change_password"], true);

    // --- disable: sessions end, sign-in refused; the last administrator can't be removed ---
    assert_eq!(e.call("PATCH", "/api/v1/users/bob", &t, Some(json!({"disabled": true}))).await.0, StatusCode::OK);
    assert_eq!(e.call("GET", "/api/v1/me", &tb, None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(e.sign_in("bob", &temp2).await.0, StatusCode::UNAUTHORIZED);
    let (s, v) = e.call("PATCH", "/api/v1/users/admin", &t, Some(json!({"role": "viewer"}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(v["error"].as_str().unwrap().contains("last enabled administrator"));

    // --- console sessions: the cookie, the CSRF header, the idle limit ---
    let r = e
        .http
        .post(format!("{}/api/v1/sign-in", e.base))
        .json(&json!({ "user_id": "admin", "password": GOOD }))
        .send()
        .await
        .unwrap();
    let cookie = r.headers()["set-cookie"].to_str().unwrap().to_string();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
    assert!(r.json::<Value>().await.unwrap().get("token").is_none(), "the console's token stays in the cookie");
    let cv = cookie.split(';').next().unwrap().to_string();
    let get = e.http.get(format!("{}/api/v1/me", e.base)).header("cookie", &cv).send().await.unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    let post = e.http.post(format!("{}/api/v1/users", e.base)).header("cookie", &cv)
        .json(&json!({"user_id": "carol", "role": "viewer"})).send().await.unwrap();
    assert_eq!(post.status(), StatusCode::FORBIDDEN, "no CSRF header");
    let post = e.http.post(format!("{}/api/v1/users", e.base)).header("cookie", &cv).header("x-synodmgr", "1")
        .header("origin", "https://evil.example").json(&json!({"user_id": "carol", "role": "viewer"})).send().await.unwrap();
    assert_eq!(post.status(), StatusCode::FORBIDDEN, "another site's origin");
    let post = e.http.post(format!("{}/api/v1/users", e.base)).header("cookie", &cv).header("x-synodmgr", "1")
        .json(&json!({"user_id": "carol", "role": "viewer"})).send().await.unwrap();
    assert_eq!(post.status(), StatusCode::OK);
    e.sql("UPDATE sessions SET last_seen = now() - interval '31 minutes' WHERE kind = 'web'").await;
    let get = e.http.get(format!("{}/api/v1/me", e.base)).header("cookie", &cv).send().await.unwrap();
    assert_eq!(get.status(), StatusCode::UNAUTHORIZED, "30 minutes idle");
    e.sql("UPDATE sessions SET expires_at = now() - interval '1 second' WHERE kind = 'cli'").await;
    assert_eq!(e.call("GET", "/api/v1/me", &t, None).await.0, StatusCode::UNAUTHORIZED, "12 hours after sign-in");
    let t = e.token("admin", GOOD).await;

    // --- sign-out ---
    let t2 = e.token("admin", GOOD).await;
    assert_eq!(e.call("POST", "/api/v1/sign-out", &t2, None).await.0, StatusCode::OK);
    assert_eq!(e.call("GET", "/api/v1/me", &t2, None).await.0, StatusCode::UNAUTHORIZED);

    // --- the audit log: every step recorded, no passwords, the chain intact; a changed row shows ---
    let (s, rows) = e.call("GET", "/api/v1/audit?limit=1000", &t, None).await;
    assert_eq!(s, StatusCode::OK);
    let text = rows.to_string();
    for action in ["\"sign_in\"", "\"password_change\"", "\"user_add\"", "\"user_unlock\"", "\"password_reset\"", "\"user_update\"", "\"sign_out\""] {
        assert!(text.contains(action), "audit has {action}");
    }
    assert!(text.contains("failed: unknown user ID") && text.contains("paused for 15 minutes"));
    for secret in [GOOD, GOOD2, ADMIN_PW, temp.as_str(), temp2.as_str()] {
        assert!(!text.contains(secret), "a password in the audit log");
    }
    let (_, v) = e.call("GET", "/api/v1/audit/verify", &t, None).await;
    assert_eq!(v["intact"], true, "{v}");
    let csv = e.call("GET", "/api/v1/audit?format=csv", &t, None).await.1;
    assert!(csv.as_str().unwrap().starts_with("id,at,actor,"));
    // the table refuses changes; an owner who forces one is caught by the chain
    let (c, conn) = tokio_postgres::connect(&e.db_url, NoTls).await.unwrap();
    tokio::spawn(conn);
    assert!(c.batch_execute("UPDATE audit SET result = 'ok' WHERE id = 3").await.is_err());
    assert!(c.batch_execute("DELETE FROM audit WHERE id = 3").await.is_err());
    c.batch_execute("ALTER TABLE audit DISABLE TRIGGER audit_append_only; UPDATE audit SET result = 'ok' WHERE id = 3;").await.unwrap();
    let (_, v) = e.call("GET", "/api/v1/audit/verify", &t, None).await;
    assert_eq!(v["intact"], false);
    assert_eq!(v["first_bad_row"], 3);

    // --- many failures from one address: that address waits ---
    let mut last = StatusCode::OK;
    for _ in 0..25 {
        last = e.sign_in("nobody", "guessing guessing").await.0;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}
