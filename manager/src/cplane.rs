//! The Synod installations the manager watches, and the control plane API it reads them through
//! (cplane API level 1: `/v1/version`, `/v1/clusters`, `/v1/events?after=`, `/v1/hosts`, `/metrics`;
//! level 2 adds operator actions and sessions, see api/actions.rs).

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::Value;

use crate::App;

#[derive(Debug, Clone, Serialize)]
pub struct Installation {
    pub id: i64,
    pub name: String,
    pub front_door: String,
    #[serde(skip)]
    pub admin_token: String,
    #[serde(skip)]
    pub metrics_token: String,
    pub has_metrics_token: bool,
    pub has_ca_cert: bool,
    #[serde(skip)]
    pub ca_cert: String,
    pub extra_targets: Value,
}

pub fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 40 && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

pub async fn installations(app: &App) -> Result<Vec<Installation>> {
    let c = app.db.get().await?;
    let rows = c
        .query(
            "SELECT id, name, front_door, admin_token, metrics_token, ca_cert, extra_targets FROM installations ORDER BY name",
            &[],
        )
        .await?;
    rows.iter()
        .map(|r| {
            let metrics_token = app.secrets.open(r.get(4))?;
            let ca_cert: String = r.get(5);
            Ok(Installation {
                id: r.get(0),
                name: r.get(1),
                front_door: r.get(2),
                admin_token: app.secrets.open(r.get(3))?,
                has_metrics_token: !metrics_token.is_empty(),
                metrics_token,
                has_ca_cert: !ca_cert.is_empty(),
                ca_cert,
                extra_targets: r.get(6),
            })
        })
        .collect()
}

pub async fn installation(app: &App, name: &str) -> Result<Option<Installation>> {
    Ok(installations(app).await?.into_iter().find(|i| i.name == name))
}

/// host:port of a URL.
pub fn host_port(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let hp = rest.split('/').next()?;
    if hp.is_empty() { None } else { Some(hp.to_string()) }
}

fn url(front_door: &str, path: &str) -> String {
    format!("{}{}", front_door.trim_end_matches('/'), path)
}

/// GET a control plane JSON endpoint with the installation's admin token.
pub async fn get_json(app: &App, front_door: &str, token: &str, path: &str) -> Result<Value> {
    let r = app.http.get(url(front_door, path)).bearer_auth(token).send().await.with_context(|| format!("GET {path}"))?;
    let status = r.status();
    let text = r.text().await?;
    if !status.is_success() {
        bail!("GET {path}: {status}: {}", text.chars().take(300).collect::<String>());
    }
    serde_json::from_str(&text).with_context(|| format!("GET {path}: not JSON"))
}

/// Any control plane call with the installation's admin token and its own timeout (operator
/// actions take minutes): (status, body). Only a failure to get an answer is an error.
pub async fn request(
    app: &App,
    method: reqwest::Method,
    front_door: &str,
    token: &str,
    path: &str,
    body: Option<&Value>,
    timeout: std::time::Duration,
) -> Result<(u16, String)> {
    let mut req = app.http.request(method.clone(), url(front_door, path)).bearer_auth(token).timeout(timeout);
    if let Some(b) = body {
        req = req.json(b);
    }
    let r = req.send().await.with_context(|| format!("{method} {path}"))?;
    let status = r.status().as_u16();
    Ok((status, r.text().await?))
}

/// GET text (the control plane's /metrics) with a token.
pub async fn get_text(app: &App, front_door: &str, token: &str, path: &str) -> Result<String> {
    let r = app.http.get(url(front_door, path)).bearer_auth(token).send().await.with_context(|| format!("GET {path}"))?;
    let status = r.status();
    let text = r.text().await?;
    if !status.is_success() {
        bail!("GET {path}: {status}");
    }
    Ok(text)
}

/// The installation answers with API level 1 or later (checked when one is added).
pub async fn check(app: &App, front_door: &str, admin_token: &str) -> Result<Value> {
    let v = get_json(app, front_door, admin_token, "/v1/version").await?;
    let level = v.get("api_level").and_then(Value::as_i64).unwrap_or(0);
    if level < 1 {
        bail!("the control plane at {front_door} has API level {level}; the manager needs 1 or later (Synod with the manager endpoints)");
    }
    Ok(v)
}

/// Samples of one metric family from Prometheus text: (labels, value).
pub fn samples(text: &str, name: &str) -> Vec<(Vec<(String, String)>, f64)> {
    let mut out = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix(name) else { continue };
        let (labels, value) = if let Some(r) = rest.strip_prefix('{') {
            let Some((l, v)) = r.split_once('}') else { continue };
            (l, v)
        } else if rest.starts_with(' ') {
            ("", rest)
        } else {
            continue;
        };
        let Ok(v) = value.trim().parse::<f64>() else { continue };
        let labels = labels
            .split(',')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.trim().to_string(), v.trim().trim_matches('"').to_string()))
            .collect();
        out.push((labels, v));
    }
    out
}

/// The cluster's newest restore point age, from the control plane's /metrics.
pub fn restore_point_ages(metrics: &str) -> std::collections::BTreeMap<String, f64> {
    samples(metrics, "synod_restore_point_age_seconds")
        .into_iter()
        .filter_map(|(l, v)| l.into_iter().find(|(k, _)| k == "cluster").map(|(_, c)| (c, v)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_samples() {
        let t = "# HELP synod_restore_point_age_seconds x\n# TYPE synod_restore_point_age_seconds gauge\n\
                 synod_restore_point_age_seconds{cluster=\"bank\"} 31.5\n\
                 synod_restore_point_age_seconds{cluster=\"rac2\"} 2\n\
                 synod_restore_point_age_seconds_other 9\nsynod_clusters 2\n";
        let a = restore_point_ages(t);
        assert_eq!(a.get("bank"), Some(&31.5));
        assert_eq!(a.get("rac2"), Some(&2.0));
        assert_eq!(a.len(), 2);
        assert_eq!(samples(t, "synod_clusters"), vec![(vec![], 2.0)]);
        assert!(valid_name("prod-1"));
        assert!(!valid_name("Prod"));
        assert_eq!(url("http://h:4200/", "/v1/x"), "http://h:4200/v1/x");
    }
}
