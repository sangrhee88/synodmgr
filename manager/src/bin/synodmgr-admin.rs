//! `synodmgr-admin`, run as root on the manager machine (it reads the manager's configuration and
//! key file directly, so it works when nobody can sign in):
//!
//!   synodmgr-admin init-admin --out FILE     the first administrator, `admin`, with a one-time
//!                                            password written to FILE (mode 600); nothing if an
//!                                            administrator exists
//!   synodmgr-admin reset-password USER_ID    a new one-time password, printed; the account is
//!                                            unlocked, enabled and signed out everywhere
//!   synodmgr-admin verify-audit              checks the audit log's chain
//!
//! Every change is recorded in the audit log with the actor "root".

use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use serde_json::json;
use synod_manager::audit::{self, Entry};
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
            audit::append(&pool, Entry { request: json!({ "password_file": out }), ..root("user_add", &user_id, "ok: first administrator") }).await?;
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
            audit::append(&pool, Entry { request: json!({ "sessions_ended": ended }), ..root("password_reset", &user_id, "ok") }).await?;
            println!("{user_id}: one-time password {pw}\n(the account is unlocked and enabled; the password must be changed at the next sign-in)");
        }
        Cmd::VerifyAudit => {
            let (rows, broken) = audit::verify(&pool).await?;
            match broken {
                None => println!("audit log intact: {rows} rows"),
                Some(id) => bail!("audit log broken at row {id} (of {rows}): a row was removed or changed"),
            }
        }
    }
    Ok(())
}
