//! The manager's own state database: a pool and the schema (applied at every start, idempotent).

use std::path::Path;

use anyhow::{Context, Result, bail};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres::NoTls;

pub type Db = Pool;

/// The repository's pool. With `ca`, every connection is TLS, the server's certificate checked
/// against that CA and the host it was reached at (the writer's own certificate, from the
/// cluster CA); a writer that fails over is reached again on the pool's next connection.
pub fn pool(url: &str, ca: Option<&Path>) -> Result<Db> {
    let mut cfg: tokio_postgres::Config = url.parse().context("database_url")?;
    let rc = ManagerConfig { recycling_method: RecyclingMethod::Fast };
    let mgr = match ca {
        None => Manager::from_config(cfg, NoTls, rc),
        Some(ca) => {
            let mut roots = rustls::RootCertStore::empty();
            let pem = std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?;
            for c in rustls_pemfile::certs(&mut pem.as_slice()) {
                roots.add(c?)?;
            }
            if roots.is_empty() {
                bail!("{}: no certificate", ca.display());
            }
            let tls = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
            cfg.ssl_mode(tokio_postgres::config::SslMode::Require);
            Manager::from_config(cfg, tokio_postgres_rustls::MakeRustlsConnect::new(tls), rc)
        }
    };
    Ok(Pool::builder(mgr).max_size(16).build()?)
}

/// Every row carries an installation where it belongs to one, so a Synod-hosted manager can serve
/// many customers later (design: packaging).
pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS installations (
    id            bigserial PRIMARY KEY,
    name          text NOT NULL UNIQUE,
    front_door    text NOT NULL,              -- the control plane's front door, e.g. http://10.0.0.5:4200
    admin_token   text NOT NULL,              -- encrypted (crypto.rs)
    metrics_token text NOT NULL DEFAULT '',   -- encrypted; '' = none
    ca_cert       text NOT NULL DEFAULT '',   -- the cluster CA (PEM), for the writers' TLS
    extra_targets jsonb NOT NULL DEFAULT '[]',-- `synod-install targets` groups: storage, node exporters
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id               bigserial PRIMARY KEY,
    user_id          text NOT NULL UNIQUE,     -- what people type to sign in
    name             text NOT NULL DEFAULT '',
    role             text NOT NULL CHECK (role IN ('admin', 'viewer')),
    password_hash    text NOT NULL,            -- Argon2id, PHC string
    must_change      boolean NOT NULL DEFAULT true,
    disabled         boolean NOT NULL DEFAULT false,
    failed_count     integer NOT NULL DEFAULT 0,
    locked_until     timestamptz,
    password_set_at  timestamptz NOT NULL DEFAULT now(),
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_sign_in     timestamptz
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  bytea PRIMARY KEY,             -- sha256 of the token; the token itself is never stored
    user_ref    bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind        text NOT NULL CHECK (kind IN ('web', 'cli')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    address     text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_ref);

-- One append-only row per action and sign-in. Each row's hash is an HMAC (keyed outside the
-- database) over the previous row's hash and its own fields, and the newest row is also recorded
-- on the manager machine, so a removed or edited row shows (audit.rs verifies the chain).
CREATE TABLE IF NOT EXISTS audit (
    id         bigserial PRIMARY KEY,
    at         timestamptz NOT NULL,
    actor      text NOT NULL,                  -- a user ID, 'system', or 'root' (synodmgr-admin)
    address    text NOT NULL DEFAULT '',
    action     text NOT NULL,
    target     text NOT NULL DEFAULT '',
    request    text NOT NULL DEFAULT '{}',     -- JSON, with secrets removed (text: hashed byte for byte)
    result     text NOT NULL,
    events     text NOT NULL DEFAULT '',       -- control plane event ids it caused
    prev_hash  bytea NOT NULL,
    hash       bytea NOT NULL
);
CREATE OR REPLACE FUNCTION audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'the audit log is append-only';
END $$;
DROP TRIGGER IF EXISTS audit_append_only ON audit;
CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON audit
    FOR EACH STATEMENT EXECUTE FUNCTION audit_append_only();

-- A password change raises the version; a session opened with an older version is no longer valid
-- (a sign-in under way while the password changed can't leave a session behind).
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_version integer NOT NULL DEFAULT 1;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS password_version integer NOT NULL DEFAULT 1;

-- The control planes' events, copied every 5 s (cplane GET /v1/events?after=).
CREATE TABLE IF NOT EXISTS events (
    installation bigint NOT NULL REFERENCES installations(id) ON DELETE CASCADE,
    id           bigint NOT NULL,
    at           timestamptz NOT NULL,
    database     text,
    kind         text NOT NULL,
    detail       text NOT NULL,
    PRIMARY KEY (installation, id)
);
CREATE INDEX IF NOT EXISTS events_at ON events (at DESC);
"#;

pub async fn migrate(db: &Db) -> Result<()> {
    let c = db.get().await?;
    // one migrating manager at a time
    c.batch_execute("SELECT pg_advisory_lock(7302001)").await?;
    let r = c.batch_execute(SCHEMA).await;
    c.batch_execute("SELECT pg_advisory_unlock(7302001)").await?;
    r.context("applying the schema")?;
    Ok(())
}

/// The error means the repository can't be reached right now (no connection, the connection
/// dropped, or the server is shutting down or starting): a writer failover, not a fault here.
pub fn unavailable(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        if let Some(p) = c.downcast_ref::<deadpool_postgres::PoolError>() {
            return match p {
                deadpool_postgres::PoolError::Backend(e) => pg_unavailable(e),
                deadpool_postgres::PoolError::Timeout(_) | deadpool_postgres::PoolError::Closed => true,
                _ => false,
            };
        }
        c.downcast_ref::<tokio_postgres::Error>().is_some_and(pg_unavailable)
    })
}

fn pg_unavailable(e: &tokio_postgres::Error) -> bool {
    if e.is_closed() {
        return true;
    }
    match e.code() {
        // connection exceptions (08...), and admin/crash shutdown or "cannot connect now" (57P01-03)
        Some(c) => c.code().starts_with("08") || matches!(c.code(), "57P01" | "57P02" | "57P03"),
        // no SQLSTATE: unreachable only if connecting or talking to the server failed (not, say,
        // a column that didn't convert, which is a fault here)
        None => {
            let s = e.to_string();
            ["error connecting to server", "error communicating with the server", "error performing TLS handshake", "timeout"]
                .iter()
                .any(|p| s.starts_with(p))
                || std::error::Error::source(e).is_some_and(|x| x.is::<std::io::Error>())
        }
    }
}
