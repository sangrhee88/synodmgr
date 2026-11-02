//! Leases in the repository: with two manager machines, both serve the API and scrape, but the
//! background work that writes to the repository (copying events, removing old sessions) is done
//! by whichever holds the lease. A lease lasts `TTL` from its last renewal, by the database's
//! clock; the holder renews it every `RENEW`, so the other machine takes over within `TTL` of a
//! failure (at once after a clean stop, which gives it up).

use std::time::Duration;

use anyhow::Result;

use crate::db::Db;

pub const BACKGROUND: &str = "background";
pub const TTL: Duration = Duration::from_secs(15);
pub const RENEW: Duration = Duration::from_secs(5);

/// Takes or renews the lease `name` for `holder`; true if `holder` has it now.
pub async fn hold(db: &Db, name: &str, holder: &str, ttl: Duration) -> Result<bool> {
    let c = db.get().await?;
    let secs = ttl.as_secs_f64();
    let row = c
        .query_opt(
            "INSERT INTO leases (name, holder, until) VALUES ($1, $2, now() + make_interval(secs => $3))
             ON CONFLICT (name) DO UPDATE SET holder = EXCLUDED.holder, until = EXCLUDED.until
                 WHERE leases.holder = EXCLUDED.holder OR leases.until < now()
             RETURNING holder",
            &[&name, &holder, &secs],
        )
        .await?;
    Ok(row.is_some())
}

/// Gives the lease up (if `holder` has it), so the other machine takes over at once.
pub async fn release(db: &Db, name: &str, holder: &str) -> Result<()> {
    let c = db.get().await?;
    c.execute("DELETE FROM leases WHERE name = $1 AND holder = $2", &[&name, &holder]).await?;
    Ok(())
}

/// Who holds the lease and for how much longer (seconds), if anyone.
pub async fn holder(db: &Db, name: &str) -> Result<Option<(String, f64)>> {
    let c = db.get().await?;
    Ok(c.query_opt(
        "SELECT holder, extract(epoch FROM until - now())::float8 FROM leases WHERE name = $1 AND until > now()",
        &[&name],
    )
    .await?
    .map(|r| (r.get(0), r.get(1))))
}
