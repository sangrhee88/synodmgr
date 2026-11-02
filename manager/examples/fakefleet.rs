//! A simulated fleet for load tests: N installations, each a control plane (its own port) with
//! K clusters of three writers and H host agents (their own ports), events at a steady rate, and
//! metrics of a chosen size. Some installations can be slow (every answer late, but within the
//! manager's timeout) and some can stop answering after a while (requests hang).
//!
//!     cargo run --release --example fakefleet -- --installations 300 --stats-port 23999
//!
//! GET http://127.0.0.1:<stats-port>/stats: requests served by kind, and each installation's
//! newest event id.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Parser, Clone)]
struct Args {
    #[arg(long, default_value_t = 300)]
    installations: usize,
    /// Clusters per installation (three writers each).
    #[arg(long, default_value_t = 3)]
    clusters: usize,
    /// Host agents per installation.
    #[arg(long, default_value_t = 3)]
    hosts: usize,
    #[arg(long, default_value_t = 24000)]
    cplane_base: u16,
    #[arg(long, default_value_t = 25000)]
    agent_base: u16,
    #[arg(long, default_value_t = 23999)]
    stats_port: u16,
    /// Series in each control plane's /metrics (besides the restore point ages).
    #[arg(long, default_value_t = 100)]
    cplane_series: usize,
    /// Series in each host agent's /metrics.
    #[arg(long, default_value_t = 100)]
    agent_series: usize,
    /// One event per installation every this many seconds.
    #[arg(long, default_value_t = 10.0)]
    event_every: f64,
    /// The first this many installations answer 3 s late.
    #[arg(long, default_value_t = 0)]
    slow: usize,
    /// The last this many installations stop answering (requests hang) after --dead-after s.
    #[arg(long, default_value_t = 0)]
    dead: usize,
    #[arg(long, default_value_t = 60.0)]
    dead_after: f64,
}

struct Counters {
    leader: AtomicU64,
    clusters: AtomicU64,
    hosts: AtomicU64,
    events: AtomicU64,
    cplane_metrics: AtomicU64,
    agent_metrics: AtomicU64,
    other: AtomicU64,
}

struct World {
    a: Args,
    start: Instant,
    n: Counters,
}

impl World {
    fn newest_event(&self, i: usize) -> u64 {
        // installations start their clocks a little apart
        let t = self.start.elapsed().as_secs_f64() + (i % 10) as f64 * 0.1;
        (t / self.a.event_every) as u64 + 1
    }
    fn dead(&self, i: usize) -> bool {
        i >= self.a.installations - self.a.dead && self.start.elapsed().as_secs_f64() > self.a.dead_after
    }
    fn slow(&self, i: usize) -> bool {
        i < self.a.slow
    }
}

#[derive(Clone)]
struct Inst {
    w: Arc<World>,
    i: usize,
}

async fn behave(s: &Inst) {
    if s.w.dead(s.i) {
        // as a machine that's gone: the request never gets an answer
        std::future::pending::<()>().await;
    }
    if s.w.slow(s.i) {
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

fn authed(h: &HeaderMap) -> bool {
    h.get("authorization").and_then(|v| v.to_str().ok()).is_some_and(|v| v.starts_with("Bearer "))
}

async fn version(State(s): State<Inst>, h: HeaderMap) -> Response {
    behave(&s).await;
    s.w.n.other.fetch_add(1, Ordering::Relaxed);
    if !authed(&h) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(json!({ "api_level": 1, "instance": "cp1", "leader": true, "version": "0.1.0-fake" })).into_response()
}

async fn leader(State(s): State<Inst>) -> Response {
    behave(&s).await;
    s.w.n.leader.fetch_add(1, Ordering::Relaxed);
    Json(json!({ "api_level": 1, "instance": "cp1", "leader": true, "leader_for_s": s.w.start.elapsed().as_secs_f64(),
                 "lease": { "epoch": 1, "expires_in_s": 2.5, "holder": "cp1" }, "version": "0.1.0-fake" }))
    .into_response()
}

async fn clusters(State(s): State<Inst>) -> Response {
    behave(&s).await;
    s.w.n.clusters.fetch_add(1, Ordering::Relaxed);
    let list: Vec<Value> = (0..s.w.a.clusters)
        .map(|k| {
            let name = format!("c{k}");
            let slots: Vec<Value> = ["a", "b", "c"]
                .iter()
                .enumerate()
                .map(|(j, l)| json!({ "slot": format!("{name}-{l}"),
                    "writer": { "compute_id": format!("{name}-{l}-g1-0000"), "host": format!("h{}", j % s.w.a.hosts.max(1)), "state": "running" } }))
                .collect();
            json!({ "name": name, "all_shared": true, "membership": "peer", "on_writer_failure": "restart",
                    "pg_dbname": name, "logical_replication": false, "slots": slots })
        })
        .collect();
    Json(json!(list)).into_response()
}

async fn hosts(State(s): State<Inst>) -> Response {
    behave(&s).await;
    s.w.n.hosts.fetch_add(1, Ordering::Relaxed);
    let a = &s.w.a;
    let list: Vec<Value> = (0..a.hosts)
        .map(|j| {
            let port = a.agent_base as usize + s.i * a.hosts + j;
            json!({ "host_id": format!("h{j}"), "address": "127.0.0.1", "agent_url": format!("http://127.0.0.1:{port}"),
                    "heartbeat_age_s": 0.3, "computes": [] })
        })
        .collect();
    Json(json!(list)).into_response()
}

#[derive(Deserialize)]
struct EventsQ {
    after: Option<u64>,
    limit: Option<u64>,
}

async fn events(State(s): State<Inst>, Query(q): Query<EventsQ>) -> Response {
    behave(&s).await;
    s.w.n.events.fetch_add(1, Ordering::Relaxed);
    let newest = s.w.newest_event(s.i);
    let after = q.after.unwrap_or(0);
    let last = newest.min(after + q.limit.unwrap_or(50));
    let now = chrono::Utc::now();
    let list: Vec<Value> = (after + 1..=last)
        .map(|id| {
            let age = (newest - id) as f64 * s.w.a.event_every;
            json!({ "id": id, "at": (now - chrono::Duration::milliseconds((age * 1000.0) as i64)).to_rfc3339(),
                    "database": format!("c{}-a", id as usize % s.w.a.clusters.max(1)), "kind": "fake_tick",
                    "detail": format!("event {id} of fake installation {}", s.i) })
        })
        .collect();
    Json(json!(list)).into_response()
}

async fn cplane_metrics(State(s): State<Inst>) -> Response {
    behave(&s).await;
    s.w.n.cplane_metrics.fetch_add(1, Ordering::Relaxed);
    let t = s.w.start.elapsed().as_secs_f64();
    let mut out = String::from("# TYPE synod_restore_point_age_seconds gauge\n");
    for k in 0..s.w.a.clusters {
        out.push_str(&format!("synod_restore_point_age_seconds{{cluster=\"c{k}\"}} {:.1}\n", t % 60.0));
    }
    out.push_str("# TYPE fake_cplane_value gauge\n");
    for n in 0..s.w.a.cplane_series {
        out.push_str(&format!("fake_cplane_value{{n=\"{n}\"}} {}\n", (t as usize + n) % 1000));
    }
    out.into_response()
}

async fn agent_metrics(State(s): State<Inst>) -> Response {
    behave(&s).await;
    s.w.n.agent_metrics.fetch_add(1, Ordering::Relaxed);
    let t = s.w.start.elapsed().as_secs_f64();
    let mut out = String::from("# TYPE synod_fake_writer_counter counter\n");
    for n in 0..s.w.a.agent_series {
        out.push_str(&format!("synod_fake_writer_counter{{slot=\"c{}-a\",n=\"{n}\"}} {}\n", n % 3, (t * 10.0) as u64 + n as u64));
    }
    out.into_response()
}

async fn stats(State(w): State<Arc<World>>) -> Json<Value> {
    let c = &w.n;
    let newest: Vec<u64> = (0..w.a.installations).map(|i| w.newest_event(i)).collect();
    Json(json!({
        "uptime_s": w.start.elapsed().as_secs_f64(),
        "requests": { "leader": c.leader.load(Ordering::Relaxed), "clusters": c.clusters.load(Ordering::Relaxed),
                      "hosts": c.hosts.load(Ordering::Relaxed), "events": c.events.load(Ordering::Relaxed),
                      "cplane_metrics": c.cplane_metrics.load(Ordering::Relaxed),
                      "agent_metrics": c.agent_metrics.load(Ordering::Relaxed), "other": c.other.load(Ordering::Relaxed) },
        "newest_event": newest,
        "dead_now": (0..w.a.installations).filter(|&i| w.dead(i)).count(),
    }))
}

async fn serve(port: u16, r: Router) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let l = tokio::net::TcpListener::bind(addr).await.unwrap_or_else(|e| panic!("port {port}: {e}"));
    axum::serve(l, r).await.unwrap();
}

#[tokio::main]
async fn main() {
    let a = Args::parse();
    let w = Arc::new(World {
        a: a.clone(),
        start: Instant::now(),
        n: Counters {
            leader: AtomicU64::new(0),
            clusters: AtomicU64::new(0),
            hosts: AtomicU64::new(0),
            events: AtomicU64::new(0),
            cplane_metrics: AtomicU64::new(0),
            agent_metrics: AtomicU64::new(0),
            other: AtomicU64::new(0),
        },
    });
    for i in 0..a.installations {
        let st = Inst { w: w.clone(), i };
        let cp = Router::new()
            .route("/v1/version", get(version))
            .route("/v1/leader", get(leader))
            .route("/v1/clusters", get(clusters))
            .route("/v1/hosts", get(hosts))
            .route("/v1/events", get(events))
            .route("/metrics", get(cplane_metrics))
            .with_state(st.clone());
        tokio::spawn(serve(a.cplane_base + i as u16, cp));
        for j in 0..a.hosts {
            let ag = Router::new().route("/metrics", get(agent_metrics)).with_state(st.clone());
            tokio::spawn(serve(a.agent_base + (i * a.hosts + j) as u16, ag));
        }
    }
    let r = Router::new().route("/stats", get(stats)).with_state(w.clone());
    eprintln!(
        "fakefleet: {} installations ({} clusters, {} hosts each) on ports {}.. and {}..; stats on {}",
        a.installations, a.clusters, a.hosts, a.cplane_base, a.agent_base, a.stats_port
    );
    serve(a.stats_port, r).await;
}
