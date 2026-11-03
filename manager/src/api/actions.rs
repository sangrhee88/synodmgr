//! Operator actions on Synod installations: stop, start and restart a one-writer database, one
//! writer of a cluster or a whole cluster (a rolling restart, one writer at a time), and the live
//! sessions on the writers (list; cancel a query or end a session). The control plane does the
//! work (cplane API level 2, its server/lifecycle.rs); the manager checks who asks and the
//! confirmation, writes the audit row, passes the user's name on to the control plane's events,
//! and refreshes its copy of the installation.
//!
//! Confirmation, the same for the console and the CLI: stopping or restarting needs the target's
//! name typed (`confirm`: the database's name, the writer's slot name such as rac1-b, or the
//! cluster's name); a stop also needs a reason. Starting and session actions need neither.
//! Viewers may list sessions; everything else needs an Admin.

use std::time::Duration;

use super::*;

/// A database's or one writer's action: a fast shutdown and a start take seconds; this allows
/// for a slow shutdown (the agent's 15 s), a rejoin and a busy host.
const ONE_TIMEOUT: Duration = Duration::from_secs(6 * 60);
/// A whole cluster's: a rolling restart goes one writer at a time.
const CLUSTER_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const SESSIONS_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct ActionBody {
    /// The target's name, typed (stop and restart).
    #[serde(default)]
    confirm: Option<String>,
    /// Why (required to stop). The control plane's events show it with the user's ID.
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct SessionsQuery {
    /// Background processes too.
    #[serde(default)]
    all: bool,
}

/// A database, cluster or slot name as the control plane makes them: it goes into a URL path.
fn valid_ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn verb(action: &str) -> ApiResult<&'static str> {
    match action {
        "stop" => Ok("stop"),
        "start" => Ok("start"),
        "restart" => Ok("restart"),
        _ => Err(ApiError(StatusCode::NOT_FOUND, "No such endpoint.".into())),
    }
}

async fn installation_or_404(app: &App, name: &str) -> ApiResult<cplane::Installation> {
    cplane::installation(app, name)
        .await?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, format!("No installation {name}.")))
}

/// The control plane's answer as the manager's: its error message, and a status that doesn't
/// look like the manager's own (a refused token or a control plane fault is a bad gateway).
fn from_cplane(status: u16, text: &str) -> ApiError {
    let v: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    let msg = v.get("error").and_then(Value::as_str).map(str::to_string);
    match (status, msg) {
        (404, None) => ApiError(
            StatusCode::CONFLICT,
            "This installation's control plane has no operator actions yet (they need control plane API level 2): upgrade Synod there first.".into(),
        ),
        (401, _) | (403, _) => ApiError(StatusCode::BAD_GATEWAY, "The control plane refused the manager's token for this installation.".into()),
        (s, Some(m)) if (400..500).contains(&s) => {
            ApiError(StatusCode::from_u16(s).unwrap_or(StatusCode::BAD_REQUEST), format!("The control plane says: {m}"))
        }
        (s, m) => ApiError(
            StatusCode::BAD_GATEWAY,
            format!("The control plane answered {s}: {}", m.unwrap_or_else(|| text.chars().take(300).collect())),
        ),
    }
}

/// A few words on what a successful action did, for the audit row.
fn summary(v: &Value) -> String {
    let n = |k: &str| v.get(k).and_then(Value::as_f64);
    let mut parts = Vec::new();
    if let Some(w) = v.get("writer").and_then(Value::as_str) {
        parts.push(format!("writer {w}"));
    }
    if let Some(h) = v.get("host").and_then(Value::as_str) {
        parts.push(format!("on {h}"));
    }
    if v.get("already_running").and_then(Value::as_bool) == Some(true) {
        parts.push("already running".into());
    }
    if let Some(slots) = v.get("slots").and_then(Value::as_array) {
        parts.push(format!("{} writer(s)", slots.len()));
    }
    if let Some(s) = n("writable_after_s") {
        parts.push(format!("writable after {s:.1} s"));
    }
    if let Some(s) = n("took_s") {
        parts.push(format!("took {s:.1} s"));
    }
    if parts.is_empty() { "ok".into() } else { format!("ok: {}", parts.join(", ")) }
}

struct Target<'a> {
    /// The audit row's action: database_stop, writer_restart, cluster_start, session_cancel, ...
    action: String,
    /// The audit row's target: installation/name.
    label: String,
    /// What must be typed to confirm (stop, restart), if anything.
    confirm_name: Option<&'a str>,
    /// What the action does, for the confirmation message ("stop", "restart").
    verb: &'static str,
    reason_required: bool,
    /// The control plane's path.
    path: String,
    timeout: Duration,
}

async fn refused(app: &App, p: &Principal, t: &Target<'_>, request: &Value, msg: String) -> ApiResult<Json<Value>> {
    app.audit.append(Entry { result: format!("refused: {msg}"), request: request.clone(), ..p.entry(&t.action, &t.label) }).await?;
    Err(bad(msg))
}

async fn run(app: &App, p: &Principal, inst: &cplane::Installation, t: Target<'_>, body: ActionBody) -> ApiResult<Json<Value>> {
    let reason = body.reason.as_deref().map(str::trim).filter(|r| !r.is_empty()).map(str::to_string);
    let request = json!({ "confirm": body.confirm, "reason": reason });
    if let Some(name) = t.confirm_name {
        if body.confirm.as_deref().map(str::trim) != Some(name) {
            let msg = format!("To {} it, type {name} in confirm.", t.verb);
            return refused(app, p, &t, &request, msg).await;
        }
    }
    if t.reason_required && reason.is_none() {
        let msg = format!("A reason is needed to {} it; the control plane's events show it.", t.verb);
        return refused(app, p, &t, &request, msg).await;
    }
    if reason.as_ref().is_some_and(|r| r.chars().count() > 200) {
        return refused(app, p, &t, &request, "The reason is too long (200 characters at most).".into()).await;
    }
    let said = format!("{}: {}", p.user.user_id, reason.as_deref().unwrap_or("from Synod Manager"));
    let answer = cplane::request(
        app,
        reqwest::Method::POST,
        &inst.front_door,
        &inst.admin_token,
        &t.path,
        Some(&json!({ "reason": said })),
        t.timeout,
    )
    .await;
    let result = match answer {
        Err(e) => Err(ApiError(StatusCode::BAD_GATEWAY, format!("The control plane did not answer: {e:#}. It may still be working on it; see Events."))),
        Ok((s, text)) if (200..300).contains(&s) => Ok(serde_json::from_str::<Value>(&text).unwrap_or(Value::Null)),
        Ok((s, text)) => Err(from_cplane(s, &text)),
    };
    let row = match &result {
        Ok(v) => summary(v),
        Err(e) => format!("failed: {}", e.1),
    };
    app.audit.append(Entry { result: row, request, ..p.entry(&t.action, &t.label) }).await?;
    // the console shows the new state at once rather than at the next refresh
    let (a, i) = (app.clone(), inst.clone());
    tokio::spawn(async move { crate::fleet::refresh_one(&a, &i).await });
    result.map(Json)
}

pub(super) async fn database_action(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path((inst, db, action)): Path<(String, String, String)>,
    body: Option<Json<ActionBody>>,
) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    let v = verb(&action)?;
    p.admin()?;
    if !valid_ident(&db) {
        return Err(bad("No such database name."));
    }
    let i = installation_or_404(&app, &inst).await?;
    if v == "stop" && app.cfg.repository_dbname().as_deref() == Some(db.as_str()) {
        let msg = format!(
            "{db} is Synod Manager's own repository: stopped, it would stop the manager, which then couldn't start it again. \
             Use the control plane's API on the installation if you mean to."
        );
        app.audit.append(Entry { result: format!("refused: {msg}"), ..p.entry("database_stop", &format!("{inst}/{db}")) }).await?;
        return Err(ApiError(StatusCode::CONFLICT, msg));
    }
    let t = Target {
        action: format!("database_{v}"),
        label: format!("{inst}/{db}"),
        confirm_name: (v != "start").then_some(db.as_str()),
        verb: v,
        reason_required: v == "stop",
        path: format!("/v1/databases/{db}/{v}"),
        timeout: ONE_TIMEOUT,
    };
    run(&app, &p, &i, t, body.map(|b| b.0).unwrap_or_default()).await
}

pub(super) async fn writer_action(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path((inst, cluster, slot, action)): Path<(String, String, String, String)>,
    body: Option<Json<ActionBody>>,
) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    let v = verb(&action)?;
    p.admin()?;
    if !valid_ident(&cluster) || !valid_ident(&slot) {
        return Err(bad("No such cluster or writer."));
    }
    let i = installation_or_404(&app, &inst).await?;
    let letter = slot.strip_prefix(&format!("{cluster}-")).unwrap_or(&slot).to_string();
    let slot_name = format!("{cluster}-{letter}");
    let t = Target {
        action: format!("writer_{v}"),
        label: format!("{inst}/{slot_name}"),
        confirm_name: (v != "start").then_some(slot_name.as_str()),
        verb: v,
        reason_required: v == "stop",
        path: format!("/v1/clusters/{cluster}/slots/{letter}/{v}"),
        timeout: ONE_TIMEOUT,
    };
    run(&app, &p, &i, t, body.map(|b| b.0).unwrap_or_default()).await
}

pub(super) async fn cluster_action(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path((inst, cluster, action)): Path<(String, String, String)>,
    body: Option<Json<ActionBody>>,
) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    let v = verb(&action)?;
    p.admin()?;
    if !valid_ident(&cluster) {
        return Err(bad("No such cluster name."));
    }
    let i = installation_or_404(&app, &inst).await?;
    let t = Target {
        action: format!("cluster_{v}"),
        label: format!("{inst}/{cluster}"),
        confirm_name: (v != "start").then_some(cluster.as_str()),
        verb: v,
        reason_required: v == "stop",
        path: format!("/v1/clusters/{cluster}/{v}"),
        timeout: CLUSTER_TIMEOUT,
    };
    run(&app, &p, &i, t, body.map(|b| b.0).unwrap_or_default()).await
}

/// Sessions on every writer: Viewers too (the console's Sessions page).
async fn sessions(app: &App, p: &Principal, inst: &str, path: String) -> ApiResult<Json<Value>> {
    p.ready()?;
    let i = installation_or_404(app, inst).await?;
    match cplane::request(app, reqwest::Method::GET, &i.front_door, &i.admin_token, &path, None, SESSIONS_TIMEOUT).await {
        Err(e) => Err(ApiError(StatusCode::BAD_GATEWAY, format!("The control plane did not answer: {e:#}"))),
        Ok((s, text)) if (200..300).contains(&s) => {
            let mut v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            v["installation"] = json!(inst);
            v["taken_at"] = json!(chrono::Utc::now());
            Ok(Json(v))
        }
        Ok((s, text)) => Err(from_cplane(s, &text)),
    }
}

pub(super) async fn cluster_sessions(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path((inst, cluster)): Path<(String, String)>,
    Query(q): Query<SessionsQuery>,
) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    if !valid_ident(&cluster) {
        return Err(bad("No such cluster name."));
    }
    sessions(&app, &p, &inst, format!("/v1/clusters/{cluster}/sessions?all={}", q.all)).await
}

pub(super) async fn database_sessions(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path((inst, db)): Path<(String, String)>,
    Query(q): Query<SessionsQuery>,
) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    if !valid_ident(&db) {
        return Err(bad("No such database name."));
    }
    sessions(&app, &p, &inst, format!("/v1/databases/{db}/sessions?all={}", q.all)).await
}

fn kill_verb(action: &str) -> ApiResult<&'static str> {
    match action {
        "cancel" => Ok("cancel"),
        "terminate" => Ok("terminate"),
        _ => Err(ApiError(StatusCode::NOT_FOUND, "No such endpoint.".into())),
    }
}

async fn kill(app: &App, p: &Principal, inst: &str, label: String, path: String, verb: &'static str, body: ActionBody) -> ApiResult<Json<Value>> {
    p.admin()?;
    let i = installation_or_404(app, inst).await?;
    // no typed confirmation: the console asks once, as session tools do
    let t = Target {
        action: format!("session_{verb}"),
        label,
        confirm_name: None,
        verb,
        reason_required: false,
        path,
        timeout: Duration::from_secs(30),
    };
    run(app, p, &i, t, body).await
}

pub(super) async fn kill_cluster_session(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path((inst, cluster, slot, pid, action)): Path<(String, String, String, i32, String)>,
    body: Option<Json<ActionBody>>,
) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    let v = kill_verb(&action)?;
    if !valid_ident(&cluster) || !valid_ident(&slot) || pid <= 0 {
        return Err(bad("No such session."));
    }
    let letter = slot.strip_prefix(&format!("{cluster}-")).unwrap_or(&slot).to_string();
    let label = format!("{inst}/{cluster}-{letter} pid {pid}");
    let path = format!("/v1/clusters/{cluster}/sessions/{letter}/{pid}/{v}");
    kill(&app, &p, &inst, label, path, v, body.map(|b| b.0).unwrap_or_default()).await
}

pub(super) async fn kill_database_session(
    State(app): State<App>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    headers: HeaderMap,
    Path((inst, db, pid, action)): Path<(String, String, i32, String)>,
    body: Option<Json<ActionBody>>,
) -> ApiResult<Json<Value>> {
    let p = who(&app, &headers, &method, addr).await?;
    let v = kill_verb(&action)?;
    if !valid_ident(&db) || pid <= 0 {
        return Err(bad("No such session."));
    }
    let label = format!("{inst}/{db} pid {pid}");
    let path = format!("/v1/databases/{db}/sessions/{pid}/{v}");
    kill(&app, &p, &inst, label, path, v, body.map(|b| b.0).unwrap_or_default()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idents() {
        assert!(valid_ident("rac1"));
        assert!(valid_ident("rac1-b"));
        assert!(valid_ident("my_db"));
        assert!(!valid_ident(""));
        assert!(!valid_ident("a/b"));
        assert!(!valid_ident("a?b"));
        assert!(!valid_ident(".."));
        assert!(!valid_ident(&"x".repeat(64)));
    }

    #[test]
    fn cplane_errors() {
        let e = from_cplane(404, "");
        assert_eq!(e.0, StatusCode::CONFLICT);
        assert!(e.1.contains("API level 2"));
        let e = from_cplane(409, r#"{"error":"rac1-b: another operation is in progress"}"#);
        assert_eq!(e.0, StatusCode::CONFLICT);
        assert!(e.1.ends_with("another operation is in progress"));
        let e = from_cplane(401, r#"{"error":"bad or missing token"}"#);
        assert_eq!(e.0, StatusCode::BAD_GATEWAY);
        let e = from_cplane(500, r#"{"error":"rac1-b: restart failed: no live hosts"}"#);
        assert_eq!(e.0, StatusCode::BAD_GATEWAY);
        assert!(e.1.contains("no live hosts"));
        let e = from_cplane(502, "upstream gone");
        assert!(e.1.contains("upstream gone"));
    }

    #[test]
    fn summaries() {
        assert_eq!(summary(&json!({"writer": "rac1-b-g2", "host": "c1", "writable_after_s": 1.54, "took_s": 1.6})),
                   "ok: writer rac1-b-g2, on c1, writable after 1.5 s, took 1.6 s");
        assert_eq!(summary(&json!({"slots": [{}, {}, {}], "took_s": 5.9})), "ok: 3 writer(s), took 5.9 s");
        assert_eq!(summary(&json!({"already_running": true, "writer": "w"})), "ok: writer w, already running");
        assert_eq!(summary(&json!({})), "ok");
    }

    #[test]
    fn verbs() {
        assert_eq!(verb("restart").ok(), Some("restart"));
        assert!(verb("drop").is_err());
        assert_eq!(kill_verb("terminate").ok(), Some("terminate"));
        assert!(kill_verb("stop").is_err());
    }
}
