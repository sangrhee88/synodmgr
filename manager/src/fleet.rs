//! The fleet: what every installation's control plane says (its leader, clusters, hosts, and each
//! cluster's newest restore point), kept in memory on each manager machine and refreshed in the
//! background every `EVERY`, `AT_ONCE` installations at a time, each given `TIMEOUT`. The console
//! reads this copy, so a page costs no control plane calls; each entry says how old it is.
//!
//! An installation whose last refresh failed is retried every `RETRY_FAILING` in a lane of its
//! own (`FAILING_AT_ONCE`, not waited for), so control planes that don't answer never slow the
//! refresh of those that do.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tokio::sync::{RwLock, Semaphore};

use crate::App;
use crate::cplane::{self, Installation};

pub const EVERY: Duration = Duration::from_secs(10);
pub const AT_ONCE: usize = 16;
pub const TIMEOUT: Duration = Duration::from_secs(8);
pub const RETRY_FAILING: Duration = Duration::from_secs(30);
pub const FAILING_AT_ONCE: usize = 4;

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub name: String,
    pub front_door: String,
    pub leader: Result<Value, String>,
    pub clusters: Result<Value, String>,
    pub hosts: Result<Value, String>,
    /// The last hosts list the control plane gave (kept through a failed refresh, so a passing
    /// error doesn't drop host agents from the scrape list).
    pub last_hosts: Option<Value>,
    pub at: DateTime<Utc>,
    pub took_ms: u64,
}

impl Snapshot {
    pub fn errors(&self) -> Vec<String> {
        [&self.leader, &self.clusters, &self.hosts].iter().filter_map(|r| r.as_ref().err().cloned()).collect()
    }

    pub fn to_json(&self) -> Value {
        let age = (Utc::now() - self.at).num_milliseconds() as f64 / 1000.0;
        json!({
            "installation": self.name,
            "front_door": self.front_door,
            "control_plane": self.leader.as_ref().ok(),
            "clusters": self.clusters.as_ref().ok(),
            "hosts": self.hosts.as_ref().ok(),
            "errors": self.errors(),
            "as_of": self.at,
            "age_s": (age * 10.0).round() / 10.0,
            "took_ms": self.took_ms,
        })
    }

    /// host:port of every host agent (for the scrape list).
    pub fn agents(&self) -> Vec<String> {
        self.last_hosts
            .as_ref()
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|h| h.get("agent_url").and_then(Value::as_str).and_then(cplane::host_port))
            .collect()
    }
}

pub struct Fleet {
    entries: RwLock<HashMap<i64, Snapshot>>,
    /// Installations being refreshed now (one refresh each at a time).
    busy: std::sync::Mutex<std::collections::HashSet<i64>>,
    failing_lane: Arc<Semaphore>,
}

impl Default for Fleet {
    fn default() -> Self {
        Self { entries: RwLock::default(), busy: Default::default(), failing_lane: Arc::new(Semaphore::new(FAILING_AT_ONCE)) }
    }
}

/// Marks an installation busy while it is refreshed.
struct Busy<'a>(&'a Fleet, i64);
impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.busy.lock().expect("busy set").remove(&self.1);
    }
}

impl Fleet {
    pub async fn get(&self, id: i64) -> Option<Snapshot> {
        self.entries.read().await.get(&id).cloned()
    }

    pub async fn all(&self) -> HashMap<i64, Snapshot> {
        self.entries.read().await.clone()
    }

    pub async fn remove_missing(&self, keep: &[i64]) {
        self.entries.write().await.retain(|id, _| keep.contains(id));
    }

    async fn put(&self, id: i64, mut s: Snapshot) {
        let mut e = self.entries.write().await;
        if s.last_hosts.is_none() {
            s.last_hosts = e.get(&id).and_then(|o| o.last_hosts.clone());
        }
        e.insert(id, s);
    }
}

/// One installation, now.
pub async fn fetch(app: &App, inst: &Installation) -> Snapshot {
    let t0 = Instant::now();
    let (fd, tok) = (inst.front_door.as_str(), inst.admin_token.as_str());
    let work = async {
        let (leader, clusters, hosts, metrics) = tokio::join!(
            cplane::get_json(app, fd, tok, "/v1/leader"),
            cplane::get_json(app, fd, tok, "/v1/clusters"),
            cplane::get_json(app, fd, tok, "/v1/hosts"),
            async {
                if inst.has_metrics_token {
                    cplane::get_text(app, fd, &inst.metrics_token, "/metrics").await.ok()
                } else {
                    None
                }
            },
        );
        (leader, clusters, hosts, metrics)
    };
    let e = |r: Result<Value>| r.map_err(|e| format!("{e:#}"));
    let (leader, mut clusters, hosts) = match tokio::time::timeout(TIMEOUT, work).await {
        Ok((l, c, h, m)) => {
            let mut c = e(c);
            if let (Ok(Value::Array(list)), Some(text)) = (&mut c, m) {
                let ages: BTreeMap<String, f64> = cplane::restore_point_ages(&text);
                for cl in list.iter_mut() {
                    let name = cl.get("name").and_then(Value::as_str).unwrap_or("").to_string();
                    cl["restore_point_age_s"] = json!(ages.get(&name));
                }
            }
            (e(l), c, e(h))
        }
        Err(_) => {
            let t = format!("no answer within {} s", TIMEOUT.as_secs());
            (Err(t.clone()), Err(t.clone()), Err(t))
        }
    };
    if matches!(&clusters, Ok(v) if !v.is_array()) {
        clusters = Err("the control plane's cluster list is not a list".into());
    }
    Snapshot {
        name: inst.name.clone(),
        front_door: inst.front_door.clone(),
        last_hosts: hosts.as_ref().ok().cloned(),
        leader,
        clusters,
        hosts,
        at: Utc::now(),
        took_ms: t0.elapsed().as_millis() as u64,
    }
}

/// Refreshes one installation's entry (nothing if it is being refreshed already).
pub async fn refresh_one(app: &App, inst: &Installation) {
    if !app.fleet.busy.lock().expect("busy set").insert(inst.id) {
        return;
    }
    let _b = Busy(&app.fleet, inst.id);
    let s = fetch(app, inst).await;
    app.fleet.put(inst.id, s).await;
}

/// Refreshes every installation whose control plane answered last time, `AT_ONCE` at a time,
/// and waits for them; starts the failing ones due a retry in their own lane without waiting;
/// forgets removed installations. How long the answering ones took.
pub async fn refresh_all(app: &App) -> Result<Duration> {
    let t0 = Instant::now();
    let insts = cplane::installations(app).await?;
    let ids: Vec<i64> = insts.iter().map(|i| i.id).collect();
    let known = app.fleet.all().await;
    let limit = Arc::new(Semaphore::new(AT_ONCE));
    let mut set = tokio::task::JoinSet::new();
    for inst in insts {
        let a = app.clone();
        match known.get(&inst.id) {
            Some(s) if !s.errors().is_empty() => {
                if (Utc::now() - s.at).to_std().unwrap_or_default() >= RETRY_FAILING {
                    let lane = app.fleet.failing_lane.clone();
                    tokio::spawn(async move {
                        let _p = lane.acquire_owned().await;
                        refresh_one(&a, &inst).await;
                    });
                }
            }
            _ => {
                let l = limit.clone();
                set.spawn(async move {
                    let _p = l.acquire_owned().await;
                    refresh_one(&a, &inst).await;
                });
            }
        }
    }
    while set.join_next().await.is_some() {}
    app.fleet.remove_missing(&ids).await;
    Ok(t0.elapsed())
}

/// The fleet as the API gives it, in installation order; an installation not fetched yet (just
/// added on the other manager machine) is fetched now.
pub async fn view(app: &App, only: Option<&str>) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for inst in cplane::installations(app).await? {
        if only.is_some_and(|n| n != inst.name) {
            continue;
        }
        if app.fleet.get(inst.id).await.is_none() {
            refresh_one(app, &inst).await;
        }
        match app.fleet.get(inst.id).await {
            Some(s) => out.push(s.to_json()),
            // being fetched by the background refresh this moment
            None => out.push(json!({ "installation": inst.name, "front_door": inst.front_door,
                                     "errors": ["not fetched yet; try again in a moment"] })),
        }
    }
    Ok(out)
}
