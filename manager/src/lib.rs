//! Synod Manager: one service the customer runs next to their Synod installations, with the API
//! the web console and the `synodmgr` CLI share (design: `docs/design.md`).

pub mod api;
pub mod audit;
pub mod auth;
pub mod backup;
pub mod config;
pub mod cplane;
pub mod crypto;
pub mod db;
pub mod fleet;
pub mod lease;
pub mod passwords;
pub mod tasks;
pub mod users;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct AppState {
    pub cfg: config::Config,
    pub db: db::Db,
    pub secrets: crypto::SecretBox,
    pub audit: audit::Audit,
    pub throttle: auth::Throttle,
    /// Password hashes checked at once (Argon2id takes 19 MiB each): a burst of sign-ins waits
    /// here instead of using up the machine's memory.
    pub hashing: tokio::sync::Semaphore,
    pub http: reqwest::Client,
    /// This process, as a lease holder: host, address and a random part (a restart is a new holder).
    pub instance: String,
    /// Whether this machine holds the background lease (it copies events and removes old sessions).
    pub leader: AtomicBool,
    /// What every installation's control plane said last (refreshed in the background).
    pub fleet: fleet::Fleet,
}

pub type App = Arc<AppState>;

impl AppState {
    pub fn new(cfg: config::Config) -> anyhow::Result<App> {
        let db = db::pool(&cfg.database_url, cfg.database_ca.as_deref())?;
        let secrets = crypto::SecretBox::load_or_create(&cfg.key_file)?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent(concat!("synod-manager/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let audit = audit::Audit::new(db.clone(), secrets.audit_key(), Some(cfg.data_dir.join("audit-anchor")));
        let host = std::fs::read_to_string("/proc/sys/kernel/hostname").map(|s| s.trim().to_string()).unwrap_or_default();
        let instance = format!("{host}/{}/{}", cfg.listen, &crypto::new_token()[..8]);
        Ok(Arc::new(AppState {
            cfg,
            db,
            secrets,
            audit,
            throttle: auth::Throttle::default(),
            hashing: tokio::sync::Semaphore::new(4),
            http,
            instance,
            leader: AtomicBool::new(false),
            fleet: fleet::Fleet::default(),
        }))
    }
}
