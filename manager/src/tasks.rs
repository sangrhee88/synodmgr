//! Background work: copying every installation's control plane events (every 5 s), and keeping the
//! metrics store's scrape configuration in step with the installations and their hosts (every
//! 60 s). Sessions past their end are removed too, and a backup is made every night when
//! `[backup] dir` is set.

use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::{Value, json};
use tracing::warn;

use crate::App;
use crate::cplane::{self, Installation};
use crate::crypto::write_private;

pub fn spawn_all(app: App) {
    if let Some(dir) = app.cfg.backup.dir.clone() {
        let a = app.clone();
        tokio::spawn(async move { nightly_backups(a, dir).await });
    }
    let a = app.clone();
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(5));
        loop {
            t.tick().await;
            if let Err(e) = copy_events(&a).await {
                warn!("events: {e:#}");
            }
        }
    });
    let a = app.clone();
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(60));
        loop {
            t.tick().await;
            if let Err(e) = write_scrape_config(&a).await {
                warn!("scrape configuration: {e:#}");
            }
            if let Err(e) = prune_sessions(&a).await {
                warn!("sessions: {e:#}");
            }
        }
    });
}

/// The control plane's event times: "YYYY-MM-DD HH:MM:SS.mmm" (UTC) or RFC 3339.
pub fn parse_event_time(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Some(t.with_timezone(&Utc));
    }
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f").ok().map(|n| n.and_utc())
}

pub async fn copy_events(app: &App) -> Result<()> {
    for inst in cplane::installations(app).await? {
        if let Err(e) = copy_events_of(app, &inst).await {
            warn!(installation = %inst.name, "events: {e:#}");
        }
    }
    Ok(())
}

pub async fn copy_events_of(app: &App, inst: &Installation) -> Result<usize> {
    let mut copied = 0;
    loop {
        let after: i64 = {
            let c = app.db.get().await?;
            c.query_one("SELECT coalesce(max(id), 0) FROM events WHERE installation = $1", &[&inst.id]).await?.get(0)
        };
        let v = cplane::get_json(app, &inst.front_door, &inst.admin_token, &format!("/v1/events?after={after}&limit=1000"))
            .await?;
        let list = v.as_array().cloned().unwrap_or_default();
        if list.is_empty() {
            return Ok(copied);
        }
        let mut c = app.db.get().await?;
        let tx = c.transaction().await?;
        for e in &list {
            let id = e.get("id").and_then(Value::as_i64).context("event without id")?;
            let at = e.get("at").and_then(Value::as_str).and_then(parse_event_time).unwrap_or_else(Utc::now);
            let database = e.get("database").and_then(Value::as_str);
            let kind = e.get("kind").and_then(Value::as_str).unwrap_or("");
            let detail = e.get("detail").and_then(Value::as_str).unwrap_or("");
            tx.execute(
                "INSERT INTO events (installation, id, at, database, kind, detail) VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT DO NOTHING",
                &[&inst.id, &id, &at, &database, &kind, &detail],
            )
            .await?;
        }
        tx.commit().await?;
        copied += list.len();
        if list.len() < 1000 {
            return Ok(copied);
        }
    }
}

/// host:port of a URL.
fn host_port(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let hp = rest.split('/').next()?;
    if hp.is_empty() { None } else { Some(hp.to_string()) }
}

/// The metrics store's scrape configuration (Prometheus format, which VictoriaMetrics reads with
/// -promscrape.config and re-reads every 30 s): per installation, its control plane front door
/// and every host agent (both want the metrics token), plus the installation's static targets
/// (`synod-install targets`: storage servers, node exporters). Every target carries the
/// installation's name as a label.
pub fn scrape_config(insts: &[(Installation, Vec<String>)], token_dir: &std::path::Path) -> String {
    let mut jobs = Vec::new();
    for (inst, agents) in insts {
        let token_file = token_dir.join(format!("{}.metrics_token", inst.name));
        let labels = json!({ "installation": inst.name });
        if inst.has_metrics_token {
            if let Some(fd) = host_port(&inst.front_door) {
                jobs.push(json!({
                    "job_name": format!("{}-cplane", inst.name),
                    "scrape_interval": "15s",
                    "bearer_token_file": token_file,
                    "static_configs": [{ "targets": [fd], "labels": labels }],
                }));
            }
            if !agents.is_empty() {
                jobs.push(json!({
                    "job_name": format!("{}-agent", inst.name),
                    "scrape_interval": "15s",
                    "scrape_timeout": "12s",
                    "bearer_token_file": token_file,
                    "static_configs": [{ "targets": agents, "labels": labels }],
                }));
            }
        }
        for g in inst.extra_targets.as_array().into_iter().flatten() {
            let job = g.pointer("/labels/job").and_then(Value::as_str).unwrap_or("extra");
            if job == "synod_cplane" || job == "synod_agent" {
                continue; // from the control plane above
            }
            let targets: Vec<&str> = g.get("targets").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).collect();
            if targets.is_empty() {
                continue;
            }
            let mut j = json!({
                "job_name": format!("{}-{}", inst.name, job),
                "scrape_interval": "15s",
                "static_configs": [{ "targets": targets, "labels": labels }],
            });
            if let Some(p) = g.pointer("/labels/__metrics_path__").and_then(Value::as_str) {
                j["metrics_path"] = json!(p);
            }
            jobs.push(j);
        }
    }
    // JSON is YAML: Prometheus and VictoriaMetrics read it as such
    serde_json::to_string_pretty(&json!({ "global": { "scrape_interval": "15s" }, "scrape_configs": jobs })).unwrap()
}

pub async fn write_scrape_config(app: &App) -> Result<()> {
    let insts = cplane::installations(app).await?;
    let token_dir = app.cfg.data_dir.join("tokens");
    let mut with_agents = Vec::new();
    for inst in insts {
        let agents = match cplane::get_json(app, &inst.front_door, &inst.admin_token, "/v1/hosts").await {
            Ok(v) => v
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|h| h.get("agent_url").and_then(Value::as_str).and_then(host_port))
                .collect(),
            Err(e) => {
                warn!(installation = %inst.name, "hosts: {e:#}");
                Vec::new()
            }
        };
        if inst.has_metrics_token {
            write_private(&token_dir.join(format!("{}.metrics_token", inst.name)), inst.metrics_token.as_bytes())?;
        }
        with_agents.push((inst, agents));
    }
    let text = scrape_config(&with_agents, &token_dir);
    let path = app.cfg.data_dir.join("scrape.yml");
    if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
        write_private(&path, text.as_bytes())?;
    }
    Ok(())
}

async fn prune_sessions(app: &App) -> Result<()> {
    let c = app.db.get().await?;
    c.execute(
        "DELETE FROM sessions WHERE expires_at < now()
            OR (kind = 'web' AND last_seen < now() - make_interval(mins => $1::int))",
        &[&(app.cfg.sessions.idle_minutes as i32)],
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_backup_time() {
        use chrono::TimeZone;
        let now = chrono::Local.with_ymd_and_hms(2026, 11, 2, 1, 0, 0).earliest().unwrap();
        let t = next_at(now, 2, 30);
        assert_eq!((t.date_naive(), t.format("%H:%M").to_string()), (now.date_naive(), "02:30".into()));
        let now = chrono::Local.with_ymd_and_hms(2026, 11, 2, 3, 0, 0).earliest().unwrap();
        let t = next_at(now, 2, 30);
        assert_eq!(t.date_naive(), now.date_naive().succ_opt().unwrap());
    }

    fn inst(name: &str, token: bool, extra: Value) -> Installation {
        Installation {
            id: 1,
            name: name.into(),
            front_door: "http://10.0.0.5:4200".into(),
            admin_token: "a".into(),
            metrics_token: if token { "m".into() } else { String::new() },
            has_metrics_token: token,
            has_ca_cert: false,
            ca_cert: String::new(),
            extra_targets: extra,
        }
    }

    #[test]
    fn event_times() {
        assert_eq!(parse_event_time("2026-11-02 08:08:57.620").unwrap().to_rfc3339(), "2026-11-02T08:08:57.620+00:00");
        assert!(parse_event_time("2026-11-02T08:08:57Z").is_some());
        assert!(parse_event_time("yesterday").is_none());
    }

    #[test]
    fn scrape_jobs() {
        let extra = json!([
            {"targets": ["10.0.0.5:4201"], "labels": {"job": "synod_cplane"}},
            {"targets": ["10.0.0.7:9898"], "labels": {"job": "synod_pageserver", "__metrics_path__": "/metrics"}},
            {"targets": [], "labels": {"job": "node"}}
        ]);
        let cfg = scrape_config(
            &[(inst("prod", true, extra), vec!["10.0.0.8:3300".into(), "10.0.0.9:3300".into()])],
            std::path::Path::new("/var/lib/synodmgr/tokens"),
        );
        let v: Value = serde_json::from_str(&cfg).unwrap();
        let jobs = v["scrape_configs"].as_array().unwrap();
        let names: Vec<&str> = jobs.iter().map(|j| j["job_name"].as_str().unwrap()).collect();
        assert_eq!(names, ["prod-cplane", "prod-agent", "prod-synod_pageserver"]);
        assert_eq!(jobs[0]["static_configs"][0]["targets"][0], "10.0.0.5:4200");
        assert_eq!(jobs[1]["bearer_token_file"], "/var/lib/synodmgr/tokens/prod.metrics_token");
        assert_eq!(jobs[1]["static_configs"][0]["labels"]["installation"], "prod");
        assert!(jobs[2].get("bearer_token_file").is_none());
        // without a metrics token: only the static targets
        let cfg = scrape_config(&[(inst("dev", false, json!([])), vec!["h:1".into()])], std::path::Path::new("/t"));
        assert_eq!(serde_json::from_str::<Value>(&cfg).unwrap()["scrape_configs"].as_array().unwrap().len(), 0);
        assert_eq!(host_port("http://10.0.0.8:3300/x"), Some("10.0.0.8:3300".into()));
    }
}

/// The next time the clock in this machine's zone shows `h:m`.
pub fn next_at(now: DateTime<chrono::Local>, h: u32, m: u32) -> DateTime<chrono::Local> {
    use chrono::TimeZone;
    let mut day = now.date_naive();
    loop {
        let t = day.and_hms_opt(h, m, 0).expect("valid time");
        // a time skipped by a clock change: the next day's
        if let Some(t) = chrono::Local.from_local_datetime(&t).earliest() {
            if t > now {
                return t;
            }
        }
        day = day.succ_opt().expect("a next day");
    }
}

async fn nightly_backups(app: App, dir: std::path::PathBuf) {
    let (h, m) = app.cfg.backup.time_of_day().unwrap_or((2, 30));
    loop {
        let now = chrono::Local::now();
        let at = next_at(now, h, m);
        tracing::info!("next backup at {at} in {}", dir.display());
        tokio::time::sleep((at - now).to_std().unwrap_or(Duration::from_secs(60))).await;
        backup_now(&app, &dir, "system").await;
    }
}

/// Makes a backup and removes the old ones; recorded in the audit log either way.
pub async fn backup_now(app: &App, dir: &std::path::Path, actor: &str) -> Option<crate::backup::Made> {
    let cfg = app.cfg.clone();
    let d = dir.to_path_buf();
    let keep = cfg.backup.keep_days;
    let res = tokio::task::spawn_blocking(move || -> Result<(crate::backup::Made, usize)> {
        let key = crate::backup::key_from_env()?;
        let made = crate::backup::make(&cfg, &d, &key)?;
        let removed = crate::backup::prune(&d, keep)?;
        Ok((made, removed.len()))
    })
    .await
    .map_err(anyhow::Error::from)
    .and_then(|r| r);
    let (target, result, request, made) = match res {
        Ok((m, removed)) => {
            tracing::info!("backup {} ({} MB, {:.1} s); {removed} old ones removed", m.path.display(), m.bytes / 1_000_000, m.seconds);
            let name = m.path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let req = json!({ "bytes": m.bytes, "seconds": (m.seconds * 10.0).round() / 10.0, "metrics": m.metrics, "removed_old": removed });
            (name, "ok".to_string(), req, Some(m))
        }
        Err(e) => {
            warn!("backup: {e:#}");
            (dir.display().to_string(), format!("failed: {e:#}"), json!({}), None)
        }
    };
    let entry = crate::audit::Entry {
        actor: actor.into(),
        address: "localhost".into(),
        action: "backup".into(),
        target,
        request,
        result,
        ..Default::default()
    };
    if let Err(e) = app.audit.append(entry).await {
        warn!("backup: recording it in the audit log: {e:#}");
    }
    made
}
