//! `synodmgr-admin`, run as root on the manager machine (it reads the manager's configuration and
//! key file directly, so it works when nobody can sign in):
//!
//!   synodmgr-admin init-admin --out FILE     the first administrator, `admin`, with a one-time
//!                                            password written to FILE (mode 600); nothing if an
//!                                            administrator exists
//!   synodmgr-admin reset-password USER_ID    a new one-time password, printed; the account is
//!                                            unlocked, enabled and signed out everywhere
//!   synodmgr-admin verify-audit              checks the audit log's chain
//!   synodmgr-admin add-installation --name N --front-door URL [--ca-cert FILE] [--targets FILE]
//!                                            adds (or updates) an installation; its tokens come
//!                                            from SYNODMGR_ADMIN_TOKEN and SYNODMGR_METRICS_TOKEN
//!                                            (the installer passes the control plane's)
//!
//! Every change is recorded in the audit log with the actor "root".

use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use serde_json::json;
use synod_manager::audit::{Audit, Entry};
use synod_manager::config::Config;
use synod_manager::users::{self, Role};
use synod_manager::{crypto, db, passwords};

#[derive(Parser)]
#[command(version, about = "Synod Manager administration on the manager machine")]
struct Args {
    #[arg(long, env = "SYNODMGR_CONFIG", default_value = "/etc/synodmgr/manager.toml")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// The first administrator ("admin") with a one-time password in FILE.
    InitAdmin {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "admin")]
        user_id: String,
    },
    /// A new one-time password for USER_ID.
    ResetPassword { user_id: String },
    /// Check the audit log's hash chain.
    VerifyAudit,
    /// Add or update an installation (tokens from SYNODMGR_ADMIN_TOKEN, SYNODMGR_METRICS_TOKEN).
    AddInstallation {
        #[arg(long)]
        name: String,
        #[arg(long)]
        front_door: String,
        /// The cluster CA certificate (PEM).
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        /// `synod-install INVENTORY targets` output (JSON).
        #[arg(long)]
        targets: Option<PathBuf>,
    },
}

fn root(action: &str, target: &str, result: &str) -> Entry {
    Entry { actor: "root".into(), address: "localhost".into(), action: action.into(), target: target.into(), result: result.into(), ..Default::default() }
}

#[tokio::main]
async fn main() -> Result<()> {
    let a = Args::parse();
    let cfg = Config::load(&a.config)?;
    let pool = db::pool(&cfg.database_url)?;
    db::migrate(&pool).await?;
    let sb = crypto::SecretBox::load_or_create(&cfg.key_file)?;
    let audit = Audit::new(pool.clone(), sb.audit_key(), Some(cfg.data_dir.join("audit-anchor")));
    match a.cmd {
        Cmd::InitAdmin { out, user_id } => {
            if users::any_admin(&pool).await? {
                println!("an administrator exists already: nothing to do");
                return Ok(());
            }
            let pw = crypto::one_time_password();
            let hash = passwords::hash(&pw);
            if !users::create(&pool, &user_id, "Administrator", Role::Admin, &hash, true).await? {
                bail!("user {user_id} exists but is not an administrator");
            }
            crypto::write_private(&out, format!("{pw}\n").as_bytes())?;
            audit.append(Entry { request: json!({ "password_file": out }), ..root("user_add", &user_id, "ok: first administrator") }).await?;
            println!("administrator {user_id}: one-time password in {} (it must be changed at first sign-in)", out.display());
        }
        Cmd::ResetPassword { user_id } => {
            let Some(u) = users::by_user_id(&pool, &user_id).await? else {
                bail!("no user {user_id}");
            };
            let pw = crypto::one_time_password();
            users::set_password(&pool, u.id, &passwords::hash(&pw), true).await?;
            users::update(&pool, u.id, None, None, Some(false)).await?;
            let c = pool.get().await?;
            let ended = c.execute("DELETE FROM sessions WHERE user_ref = $1", &[&u.id]).await?;
            audit.append(Entry { request: json!({ "sessions_ended": ended }), ..root("password_reset", &user_id, "ok") }).await?;
            println!("{user_id}: one-time password {pw}\n(the account is unlocked and enabled; the password must be changed at the next sign-in)");
        }
        Cmd::AddInstallation { name, front_door, ca_cert, targets } => {
            if !synod_manager::cplane::valid_name(&name) {
                bail!("name: 1 to 40 lowercase letters, digits or '-'");
            }
            let admin = std::env::var("SYNODMGR_ADMIN_TOKEN").unwrap_or_default();
            if admin.is_empty() {
                bail!("SYNODMGR_ADMIN_TOKEN is not set (the control plane's admin token)");
            }
            let metrics = std::env::var("SYNODMGR_METRICS_TOKEN").unwrap_or_default();
            let ca = match &ca_cert { Some(p) => std::fs::read_to_string(p)?, None => String::new() };
            let extra: serde_json::Value = match &targets {
                Some(p) => serde_json::from_str(&std::fs::read_to_string(p)?)?,
                None => json!([]),
            };
            let c = pool.get().await?;
            let existed: bool = c.query_one("SELECT EXISTS (SELECT 1 FROM installations WHERE name = $1)", &[&name]).await?.get(0);
            c.execute(
                "INSERT INTO installations (name, front_door, admin_token, metrics_token, ca_cert, extra_targets)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (name) DO UPDATE SET front_door = EXCLUDED.front_door, admin_token = EXCLUDED.admin_token,
                     metrics_token = EXCLUDED.metrics_token, ca_cert = EXCLUDED.ca_cert, extra_targets = EXCLUDED.extra_targets",
                &[&name, &front_door.trim_end_matches('/'), &sb.seal(&admin)?, &sb.seal(&metrics)?, &ca, &extra],
            )
            .await?;
            let action = if existed { "installation_update" } else { "installation_add" };
            audit.append(Entry { request: json!({ "front_door": front_door, "metrics_token": !metrics.is_empty(),
                "ca_cert": !ca.is_empty(), "targets": extra.as_array().map(|a| a.len()) }), ..root(action, &name, "ok") }).await?;
            println!("installation {name}: {} ({front_door})", if existed { "updated" } else { "added" });
        }
        Cmd::VerifyAudit => {
            let v = audit.verify().await?;
            match (v.intact, v.first_bad_row, v.missing_from) {
                (true, _, _) => println!("audit log intact: {} rows", v.rows),
                (_, Some(id), _) => bail!("audit log broken at row {id}: a row was changed or removed"),
                (_, _, Some(id)) => bail!("audit log broken: rows from {id} on were removed"),
                _ => bail!("audit log broken"),
            }
        }
    }
    Ok(())
}
