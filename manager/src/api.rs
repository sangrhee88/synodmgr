//! The API the console and `synodmgr` share (all JSON, under /api/v1).
//!
//! Open: `GET /api/v1/health`, `POST /api/v1/sign-in`.
//! Signed in: `POST /api/v1/sign-out`, `GET /api/v1/me`, `POST /api/v1/me/password`,
//! `GET /api/v1/installations`, `GET /api/v1/fleet`, `GET /api/v1/events`,
//! `GET /api/v1/metrics/query`, `GET /api/v1/audit`, `GET /api/v1/audit/verify`.
//! Administrators: `GET/POST /api/v1/users`, `PATCH /api/v1/users/{id}`,
//! `POST /api/v1/users/{id}/reset-password|unlock|sign-out`, `POST /api/v1/installations`,
//! `DELETE /api/v1/installations/{name}`, `GET/POST /api/v1/backups`.
//! Operator actions (api/actions.rs): sessions (`GET .../clusters/{c}/sessions`, `GET
//! .../databases/{d}/sessions`: signed in); `POST` stop, start, restart of
//! `.../databases/{d}`, `.../clusters/{c}/slots/{s}` and `.../clusters/{c}`, and cancel or
//! terminate of a session (Administrators), all under `/api/v1/installations/{name}`.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

mod actions;

use crate::App;
use crate::audit::{self, Entry};
use crate::auth::{self, Kind, Principal};
use crate::cplane;
use crate::crypto;
use crate::passwords;
use crate::users::{self, Role};

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String);

pub const REPOSITORY_UNAVAILABLE: &str =
    "The manager's repository is not reachable right now (its writer may be moving to another host); try again in a moment.";

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut r = (self.0, Json(json!({ "error": self.1 }))).into_response();
        if self.0 == StatusCode::SERVICE_UNAVAILABLE {
            r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("2"));
        }
        r
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        if crate::db::unavailable(&e) {
            // a failover of the repository's writer: the pool connects to the new one by itself
            tracing::warn!("repository not reachable: {e:#}");
            return ApiError(StatusCode::SERVICE_UNAVAILABLE, REPOSITORY_UNAVAILABLE.into());
        }
        tracing::error!("{e:#}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Internal error; see the manager's log.".into())
    }
}

impl From<tokio_postgres::Error> for ApiError {
    fn from(e: tokio_postgres::Error) -> Self {
        anyhow::Error::from(e).into()
    }
}

impl From<deadpool_postgres::PoolError> for ApiError {
    fn from(e: deadpool_postgres::PoolError) -> Self {
        anyhow::Error::from(e).into()
    }
}

type ApiResult<T> = Result<T, ApiError>;

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

pub fn router(app: App) -> Router {
    Router::new()
        .route("/", get(console_index))
        .route("/console.js", get(console_js))
        .route("/console.css", get(console_css))
        .route("/favicon.svg", get(console_icon))
        .route("/api/v1/health", get(health))
        .route("/api/v1/sign-in", post(sign_in))
        .route("/api/v1/sign-out", post(sign_out))
        .route("/api/v1/me", get(me))
        .route("/api/v1/me/password", post(change_password))
        .route("/api/v1/users", get(list_users).post(add_user))
        .route("/api/v1/users/{user_id}", patch(update_user))
        .route("/api/v1/users/{user_id}/reset-password", post(reset_password))
        .route("/api/v1/users/{user_id}/unlock", post(unlock_user))
        .route("/api/v1/users/{user_id}/sign-out", post(sign_out_user))
        .route("/api/v1/installations", get(list_installations).post(add_installation))
        .route("/api/v1/installations/{name}", delete(remove_installation))
        .route("/api/v1/fleet", get(fleet))
        .route("/api/v1/events", get(events))
        .route("/api/v1/metrics/query", get(metrics_query))
        .route("/api/v1/audit", get(audit_list))
        .route("/api/v1/audit/verify", get(audit_verify))
        .route("/api/v1/backups", get(list_backups).post(backup_now))
        // operator actions and sessions (api/actions.rs)
        .route("/api/v1/installations/{inst}/databases/{db}/sessions", get(actions::database_sessions))
        .route("/api/v1/installations/{inst}/databases/{db}/sessions/{pid}/{action}", post(actions::kill_database_session))
        .route("/api/v1/installations/{inst}/databases/{db}/{action}", post(actions::database_action))
        .route("/api/v1/installations/{inst}/clusters/{cluster}/sessions", get(actions::cluster_sessions))
        .route("/api/v1/installations/{inst}/clusters/{cluster}/sessions/{slot}/{pid}/{action}", post(actions::kill_cluster_session))
        .route("/api/v1/installations/{inst}/clusters/{cluster}/slots/{slot}/{action}", post(actions::writer_action))
        .route("/api/v1/installations/{inst}/clusters/{cluster}/{action}", post(actions::cluster_action))
        .fallback(not_found)
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(app)
}

async fn security_headers(mut req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    // the host this request was sent to, for the CSRF check (HTTP/2 has no Host header); never
    // what a client says it is
    let host = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| req.headers().get(header::HOST).and_then(|v| v.to_str().ok()).map(str::to_string));
    req.headers_mut().remove(auth::HOST_HEADER);
    if let Some(h) = host.and_then(|h| HeaderValue::from_str(&h).ok()) {
        req.headers_mut().insert(auth::HOST_HEADER, h);
    }
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    h.insert("strict-transport-security", HeaderValue::from_static("max-age=31536000"));
    // the console's own files only: no inline script or style, nothing from elsewhere
    h.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; \
             base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    r
}

async fn not_found() -> ApiError {
    ApiError(StatusCode::NOT_FOUND, "No such endpoint.".into())
}

async fn who(app: &App, headers: &HeaderMap, method: &Method, addr: SocketAddr) -> ApiResult<Principal> {
    auth::authenticate(app, headers, method, &addr.ip().to_string()).await
}

async fn health(State(app): State<App>) -> Json<Value> {
    // background_jobs: this machine holds the background lease (with two manager machines, one does)
    Json(json!({ "ok": true, "version": crate::VERSION,
                 "background_jobs": app.leader.load(std::sync::atomic::Ordering::SeqCst) }))
}

// ---- sign-in and the account ----

#[derive(Deserialize)]
struct SignIn {
    user_id: String,
    password: String,
    /// "web" (the console: a cookie) or "cli" (a bearer token in the answer)
    #[serde(default)]
    client: Option<String>,
}

async fn sign_in(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<SignIn>,
) -> ApiResult<Response> {
    let kind = if req.client.as_deref() == Some("cli") { Kind::Cli } else { Kind::Web };
    let s = auth::sign_in(&app, req.user_id.trim(), &req.password, kind, &addr.ip().to_string()).await?;
    let body = json!({
        "user": s.user,
        "must_change_password": s.must_change,
        "expires_at": s.expires_at,
    });
    Ok(match kind {
        Kind::Cli => {
            let mut b = body;
            b["token"] = json!(s.token);
            Json(b).into_response()
        }
        Kind::Web => {
            let max_age = app.cfg.sessions.max_hours * 3600;
            let cookie = auth::session_cookie(&s.token, app.cfg.https(), max_age);
            ([(header::SET_COOKIE, cookie)], Json(body)).into_response()
        }
    })
}

async fn sign_out(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let p = who(&app, &headers, &method, addr).await?;
    auth::sign_out(&app, &p).await?;
    let cookie = auth::session_cookie("", app.cfg.https(), 0);
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response())
}

async fn me(State(app): State<App>, ConnectInfo(addr): ConnectInfo<SocketAddr>, method: Method, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    Ok(Json(json!({ "user": p.user, "must_change_password": p.must_change, "session": match p.kind { Kind::Web => "web", Kind::Cli => "cli" } })))
}

#[derive(Deserialize)]
struct ChangePassword {
    current_password: String,
    new_password: String,
}

async fn change_password(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Json(req): Json<ChangePassword>,
) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    auth::change_own_password(&app, &p, &req.current_password, &req.new_password).await?;
    Ok(Json(json!({ "ok": true, "other_sessions": "signed out" })))
}

// ---- users (administrators) ----

async fn list_users(State(app): State<App>, ConnectInfo(addr): ConnectInfo<SocketAddr>, method: Method, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    p.admin()?;
    Ok(Json(json!(users::list(&app.db).await?)))
}

#[derive(Deserialize)]
struct AddUser {
    user_id: String,
    #[serde(default)]
    name: String,
    role: String,
}

async fn temp_password() -> ApiResult<(String, String)> {
    let pw = crypto::one_time_password();
    let p2 = pw.clone();
    let hash = tokio::task::spawn_blocking(move || passwords::hash(&p2)).await.map_err(anyhow::Error::from)?;
    Ok((pw, hash))
}

async fn add_user(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Json(req): Json<AddUser>,
) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    p.admin()?;
    let user_id = req.user_id.trim();
    if !users::valid_user_id(user_id) {
        return Err(bad("User ID: 1 to 64 letters, digits, '.', '_', '-' or '@'."));
    }
    let role = Role::parse(&req.role).ok_or_else(|| bad("role: \"admin\" or \"viewer\"."))?;
    let (pw, hash) = temp_password().await?;
    let made = users::create(&app.db, user_id, req.name.trim(), role, &hash, true).await?;
    let request = json!({ "user_id": user_id, "name": req.name.trim(), "role": role.as_str() });
    if !made {
        app.audit.append(Entry { result: "refused: the user ID is taken".into(), request, ..p.entry("user_add", user_id) }).await?;
        return Err(ApiError(StatusCode::CONFLICT, format!("A user {user_id} exists.")));
    }
    app.audit.append(Entry { result: "ok".into(), request, ..p.entry("user_add", user_id) }).await?;
    Ok(Json(json!({
        "user_id": user_id,
        "role": role.as_str(),
        "temporary_password": pw,
        "note": "Give this temporary password to the person; it is shown once. They must change it at first sign-in.",
    })))
}

#[derive(Deserialize)]
struct UpdateUser {
    name: Option<String>,
    role: Option<String>,
    disabled: Option<bool>,
}

async fn target_user(app: &App, user_id: &str) -> ApiResult<users::User> {
    users::by_user_id(&app.db, user_id).await?.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, format!("No user {user_id}.")))
}

async fn update_user(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Json(req): Json<UpdateUser>,
) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    p.admin()?;
    let u = target_user(&app, &user_id).await?;
    let role = match &req.role {
        Some(r) => Some(Role::parse(r).ok_or_else(|| bad("role: \"admin\" or \"viewer\"."))?),
        None => None,
    };
    let request = json!({ "name": req.name, "role": req.role, "disabled": req.disabled });
    if !users::update_guarded(&app.db, u.id, req.name.as_deref().map(str::trim), role, req.disabled).await? {
        app.audit.append(Entry { result: "refused: the last administrator".into(), request, ..p.entry("user_update", &user_id) }).await?;
        return Err(bad("This is the last enabled administrator: make another administrator first."));
    }
    if req.disabled == Some(true) {
        auth::end_sessions(&app, u.id, None).await?;
    }
    app.audit.append(Entry { result: "ok".into(), request, ..p.entry("user_update", &user_id) }).await?;
    Ok(Json(json!(users::by_id(&app.db, u.id).await?)))
}

async fn reset_password(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    p.admin()?;
    let u = target_user(&app, &user_id).await?;
    let (pw, hash) = temp_password().await?;
    users::set_password(&app.db, u.id, &hash, true).await?;
    let ended = auth::end_sessions(&app, u.id, None).await?;
    app.audit
        .append(Entry { result: "ok".into(), request: json!({ "sessions_ended": ended }), ..p.entry("password_reset", &user_id) })
        .await?;
    Ok(Json(json!({
        "user_id": user_id,
        "temporary_password": pw,
        "note": "Shown once. The person must change it at their next sign-in; their sessions were signed out.",
    })))
}

async fn unlock_user(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    p.admin()?;
    let u = target_user(&app, &user_id).await?;
    users::unlock(&app.db, u.id).await?;
    app.audit.append(Entry { result: "ok".into(), ..p.entry("user_unlock", &user_id) }).await?;
    Ok(Json(json!({ "ok": true })))
}

async fn sign_out_user(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    p.admin()?;
    let u = target_user(&app, &user_id).await?;
    let n = auth::end_sessions(&app, u.id, None).await?;
    app.audit.append(Entry { result: "ok".into(), request: json!({ "sessions_ended": n }), ..p.entry("user_sign_out", &user_id) })
        .await?;
    Ok(Json(json!({ "sessions_ended": n })))
}

// ---- installations ----

async fn list_installations(State(app): State<App>, ConnectInfo(addr): ConnectInfo<SocketAddr>, method: Method, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    p.ready()?;
    Ok(Json(json!(cplane::installations(&app).await?)))
}

#[derive(Deserialize)]
struct AddInstallation {
    name: String,
    front_door: String,
    admin_token: String,
    #[serde(default)]
    metrics_token: String,
    #[serde(default)]
    ca_cert: String,
    #[serde(default)]
    extra_targets: Value,
}

async fn add_installation(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Json(req): Json<AddInstallation>,
) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    p.admin()?;
    if !cplane::valid_name(&req.name) {
        return Err(bad("name: 1 to 40 lowercase letters, digits or '-'."));
    }
    if !(req.front_door.starts_with("http://") || req.front_door.starts_with("https://")) {
        return Err(bad("front_door: the control plane's URL, e.g. http://10.0.0.5:4200"));
    }
    let extra = if req.extra_targets.is_null() { json!([]) } else { req.extra_targets.clone() };
    if !extra.is_array() {
        return Err(bad("extra_targets: the JSON list `synod-install INVENTORY targets` prints."));
    }
    let request = json!({ "name": req.name, "front_door": req.front_door, "admin_token": "x", "metrics_token": "x",
                          "ca_cert": !req.ca_cert.is_empty(), "extra_targets": extra.as_array().map(|a| a.len()) });
    let version = match cplane::check(&app, &req.front_door, &req.admin_token).await {
        Ok(v) => v,
        Err(e) => {
            app.audit.append(Entry { result: format!("refused: {e:#}"), request, ..p.entry("installation_add", &req.name) }).await?;
            return Err(bad(format!("The control plane didn't answer as expected: {e:#}")));
        }
    };
    let c = app.db.get().await?;
    let n = c
        .execute(
            "INSERT INTO installations (name, front_door, admin_token, metrics_token, ca_cert, extra_targets)
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (name) DO NOTHING",
            &[
                &req.name,
                &req.front_door.trim_end_matches('/'),
                &app.secrets.seal(&req.admin_token)?,
                &app.secrets.seal(&req.metrics_token)?,
                &req.ca_cert,
                &extra,
            ],
        )
        .await?;
    if n == 0 {
        app.audit.append(Entry { result: "refused: the name is taken".into(), request, ..p.entry("installation_add", &req.name) }).await?;
        return Err(ApiError(StatusCode::CONFLICT, format!("An installation {} exists.", req.name)));
    }
    app.audit.append(Entry { result: "ok".into(), request, ..p.entry("installation_add", &req.name) }).await?;
    if let Some(inst) = cplane::installation(&app, &req.name).await? {
        crate::fleet::refresh_one(&app, &inst).await;
    }
    if let Err(e) = crate::tasks::write_scrape_config(&app).await {
        tracing::warn!("scrape configuration: {e:#}");
    }
    Ok(Json(json!({ "name": req.name, "control_plane": version })))
}

async fn remove_installation(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    p.admin()?;
    let c = app.db.get().await?;
    let n = c.execute("DELETE FROM installations WHERE name = $1", &[&name]).await?;
    if n == 0 {
        return Err(ApiError(StatusCode::NOT_FOUND, format!("No installation {name}.")));
    }
    app.audit.append(Entry { result: "ok".into(), ..p.entry("installation_remove", &name) }).await?;
    let _ = crate::tasks::write_scrape_config(&app).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct FleetQuery {
    installation: Option<String>,
}

/// Every installation (or `?installation=`): its control planes, clusters (slots, writers), hosts
/// and each cluster's newest restore point, from the copy refreshed every 10 s (`as_of`, `age_s`).
/// An installation that doesn't answer is listed with its error.
async fn fleet(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Query(q): Query<FleetQuery>,
) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    p.ready()?;
    Ok(Json(json!(crate::fleet::view(&app, q.installation.as_deref()).await?)))
}

#[derive(Deserialize)]
struct EventsQuery {
    installation: Option<String>,
    cluster: Option<String>,
    after: Option<i64>,
    limit: Option<i64>,
}

async fn events(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Query(q): Query<EventsQuery>,
) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    p.ready()?;
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let c = app.db.get().await?;
    // a cluster's events: the cluster's own and its slots' (<cluster>-<letter>)
    let rows = c
        .query(
            "SELECT i.name, e.id, e.at, e.database, e.kind, e.detail FROM events e JOIN installations i ON i.id = e.installation
             WHERE ($1::text IS NULL OR i.name = $1)
               AND ($2::text IS NULL OR e.database = $2
                    OR (left(e.database, length($2) + 1) = $2 || '-' AND length(e.database) = length($2) + 2))
               AND ($3::bigint IS NULL OR e.id > $3)
             ORDER BY e.at DESC, e.id DESC LIMIT $4",
            &[&q.installation, &q.cluster, &q.after, &limit],
        )
        .await?;
    let list: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({ "installation": r.get::<_, String>(0), "id": r.get::<_, i64>(1),
                    "at": r.get::<_, chrono::DateTime<chrono::Utc>>(2), "database": r.get::<_, Option<String>>(3),
                    "kind": r.get::<_, String>(4), "detail": r.get::<_, String>(5) })
        })
        .collect();
    Ok(Json(json!(list)))
}

#[derive(Deserialize)]
struct MetricsQuery {
    query: String,
    start: Option<String>,
    end: Option<String>,
    step: Option<String>,
    time: Option<String>,
}

/// PromQL against the metrics store, for the console's charts (instant, or a range with
/// start/end/step).
async fn metrics_query(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Query(q): Query<MetricsQuery>,
) -> ApiResult<Response> {
    let p = who(&app, &headers, &method, addr).await?;
    p.ready()?;
    let base = app.cfg.metrics_url.trim_end_matches('/');
    let (path, mut params) = if q.start.is_some() {
        ("query_range", vec![("query", q.query.clone())])
    } else {
        ("query", vec![("query", q.query.clone())])
    };
    for (k, v) in [("start", &q.start), ("end", &q.end), ("step", &q.step), ("time", &q.time)] {
        if let Some(v) = v {
            params.push((k, v.clone()));
        }
    }
    let r = app
        .http
        .get(format!("{base}/api/v1/{path}"))
        .query(&params)
        .send()
        .await
        .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, format!("The metrics store didn't answer: {e}")))?;
    let status = StatusCode::from_u16(r.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let body = r.bytes().await.map_err(|e| ApiError(StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok((status, [(header::CONTENT_TYPE, "application/json")], body).into_response())
}

// ---- the audit log ----

#[derive(Deserialize)]
struct AuditQuery {
    after: Option<i64>,
    limit: Option<i64>,
    format: Option<String>,
}

async fn audit_list(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Response> {
    let p = who(&app, &headers, &method, addr).await?;
    p.ready()?;
    let rows = app.audit.list(q.after.unwrap_or(0), q.limit.unwrap_or(1000)).await?;
    Ok(match q.format.as_deref() {
        Some("csv") => ([(header::CONTENT_TYPE, "text/csv; charset=utf-8")], audit::csv(&rows)).into_response(),
        _ => Json(json!(rows)).into_response(),
    })
}

async fn audit_verify(State(app): State<App>, ConnectInfo(addr): ConnectInfo<SocketAddr>, method: Method, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    p.ready()?;
    Ok(Json(json!(app.audit.verify().await?)))
}

// ---- backups ----

async fn list_backups(State(app): State<App>, ConnectInfo(addr): ConnectInfo<SocketAddr>, method: Method, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    p.admin()?;
    let b = &app.cfg.backup;
    let mut all = match &b.dir {
        Some(d) => crate::backup::list(d)?,
        None => vec![],
    };
    all.sort_by_key(|(_, t, _)| std::cmp::Reverse(*t));
    let list: Vec<Value> = all
        .iter()
        .map(|(p, t, n)| json!({ "name": p.file_name().map(|x| x.to_string_lossy().to_string()), "at": t, "bytes": n }))
        .collect();
    Ok(Json(json!({
        "dir": b.dir, "keep_days": b.keep_days, "at": b.at, "metrics": b.metrics_data.is_some(),
        "key_set": crate::backup::key_from_env().is_ok(), "backups": list,
    })))
}

async fn backup_now(State(app): State<App>, ConnectInfo(addr): ConnectInfo<SocketAddr>, method: Method, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    p.admin()?;
    let Some(dir) = app.cfg.backup.dir.clone() else {
        return Err(bad("No backup directory is set ([backup] dir in the manager's configuration)."));
    };
    // it may take minutes (the metrics): it runs on; the list and the audit log show how it went
    let (a, who) = (app.clone(), p.user.user_id.clone());
    tokio::spawn(async move { crate::tasks::backup_now(&a, &dir, &who).await });
    Ok(Json(json!({ "started": true })))
}

// ---- the console: four files built into the binary

async fn console_index() -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], include_str!("../console/index.html")).into_response()
}

async fn console_js() -> Response {
    ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], include_str!("../console/console.js")).into_response()
}

async fn console_css() -> Response {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], include_str!("../console/console.css")).into_response()
}

async fn console_icon() -> Response {
    ([(header::CONTENT_TYPE, "image/svg+xml")], include_str!("../console/favicon.svg")).into_response()
}
