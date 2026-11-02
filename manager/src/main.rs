//! `synod-manager --config /etc/synodmgr/manager.toml`: the API (and, from step 4, the console),
//! the background copies of events and the metrics store's scrape configuration.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use synod_manager::{AppState, api, config::Config, db, tasks};
use tracing::info;

#[derive(Parser)]
#[command(version, about = "Synod Manager: the API and console for Synod installations")]
struct Args {
    #[arg(long, env = "SYNODMGR_CONFIG", default_value = "/etc/synodmgr/manager.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        // colors only on a terminal: the service's log is a file
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let a = Args::parse();
    let cfg = Config::load(&a.config)?;
    let app = AppState::new(cfg.clone())?;
    db::migrate_when_reachable(&app.db, std::time::Duration::from_secs(300)).await?;
    if !synod_manager::users::any_admin(&app.db).await? {
        tracing::warn!("no administrator yet: on this machine, run `synodmgr-admin init-admin` (the installer does)");
    }
    tasks::spawn_all(app.clone());
    // a clean stop gives the background lease up, so the other manager machine takes over at once
    let a = app.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let (mut term, mut int) = (signal(SignalKind::terminate()).expect("SIGTERM"), signal(SignalKind::interrupt()).expect("SIGINT"));
        tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
        if a.leader.load(std::sync::atomic::Ordering::SeqCst) {
            let r = tokio::time::timeout(std::time::Duration::from_secs(2),
                synod_manager::lease::release(&a.db, synod_manager::lease::BACKGROUND, &a.instance)).await;
            info!("stopping: background lease given up ({})", if matches!(r, Ok(Ok(()))) { "ok" } else { "not reachable" });
        }
        std::process::exit(0);
    });
    let router = api::router(app.clone()).into_make_service_with_connect_info::<SocketAddr>();
    match (&cfg.tls_cert, &cfg.tls_key) {
        (Some(cert), Some(key)) => {
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .with_context(|| format!("TLS certificate {} / key {}", cert.display(), key.display()))?;
            info!("synod-manager {} on https://{}", synod_manager::VERSION, cfg.listen);
            axum_server::bind_rustls(cfg.listen, tls).serve(router).await?;
        }
        _ => {
            info!("synod-manager {} on http://{} (plain HTTP, loopback only)", synod_manager::VERSION, cfg.listen);
            let l = tokio::net::TcpListener::bind(cfg.listen).await?;
            axum::serve(l, router).await?;
        }
    }
    Ok(())
}
