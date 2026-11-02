//! The audit log: one append-only row per action and sign-in. Each row's hash is an HMAC, keyed
//! from the manager's key file (not in the database), over the previous row's hash and its own
//! fields; and after every append the manager machine records the newest row's id and hash in a
//! file (the anchor). So editing a row, recomputing the chain, or removing the newest rows shows,
//! even to someone with full access to the database.

use std::path::PathBuf;

use anyhow::Result;
use chrono::{DateTime, SubsecRound, Utc};
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;

use crate::crypto::write_private;
use crate::db::Db;

#[derive(Debug, Clone, Default)]
pub struct Entry {
    pub actor: String,
    pub address: String,
    pub action: String,
    pub target: String,
    pub request: Value,
    pub result: String,
    pub events: String,
}

#[derive(Debug, Serialize)]
pub struct Row {
    pub id: i64,
    pub at: DateTime<Utc>,
    pub actor: String,
    pub address: String,
    pub action: String,
    pub target: String,
    pub request: Value,
    pub result: String,
    pub events: String,
    #[serde(serialize_with = "hex_ser")]
    pub hash: Vec<u8>,
}

fn hex_ser<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(v))
}

/// The hash of a row: HMAC-SHA256 over the previous hash and the row's fields, each length-prefixed.
pub fn row_hash(key: &[u8], prev: &[u8], at: &DateTime<Utc>, e: &Entry, request: &str) -> Vec<u8> {
    let mut h = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    h.update(prev);
    let at = at.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
    for f in [&at, &e.actor, &e.address, &e.action, &e.target, &request.to_string(), &e.result, &e.events] {
        h.update(&(f.len() as u64).to_be_bytes());
        h.update(f.as_bytes());
    }
    h.finalize().into_bytes().to_vec()
}

/// Removes secrets from a request before it is logged.
pub fn redact(mut v: Value) -> Value {
    if let Value::Object(m) = &mut v {
        for (k, val) in m.iter_mut() {
            let lk = k.to_lowercase();
            if lk.contains("password") || lk.contains("token") || lk.contains("secret") {
                *val = Value::String("(removed)".into());
            } else {
                *val = redact(val.take());
            }
        }
    }
    v
}

/// What `verify` found.
#[derive(Debug, Serialize, PartialEq)]
pub struct Verdict {
    pub rows: i64,
    pub intact: bool,
    /// The first row that doesn't match its hash or the previous row's.
    pub first_bad_row: Option<i64>,
    /// The anchor names a row the table no longer has (rows removed at the end).
    pub missing_from: Option<i64>,
}

#[derive(Clone)]
pub struct Audit {
    db: Db,
    key: [u8; 32],
    /// Where the newest row's id and hash are recorded on this machine (None: not kept).
    anchor: Option<PathBuf>,
}

impl Audit {
    pub fn new(db: Db, key: [u8; 32], anchor: Option<PathBuf>) -> Self {
        Self { db, key, anchor }
    }

    /// Appends a row (one at a time, under an advisory lock) and records it as the anchor.
    pub async fn append(&self, mut e: Entry) -> Result<i64> {
        e.request = redact(e.request);
        let mut c = self.db.get().await?;
        let tx = c.transaction().await?;
        tx.batch_execute("SELECT pg_advisory_xact_lock(7302002)").await?;
        let prev: Vec<u8> = tx
            .query_opt("SELECT hash FROM audit ORDER BY id DESC LIMIT 1", &[])
            .await?
            .map(|r| r.get(0))
            .unwrap_or_else(|| vec![0u8; 32]);
        // microseconds, as Postgres keeps them
        let at = Utc::now().trunc_subsecs(6);
        let req = e.request.to_string();
        let hash = row_hash(&self.key, &prev, &at, &e, &req);
        let id: i64 = tx
            .query_one(
                "INSERT INTO audit (at, actor, address, action, target, request, result, events, prev_hash, hash)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id",
                &[&at, &e.actor, &e.address, &e.action, &e.target, &req, &e.result, &e.events, &prev, &hash],
            )
            .await?
            .get(0);
        tx.commit().await?;
        if let Some(p) = &self.anchor {
            // the newest anchor wins: a concurrent append may write after us with a higher id
            let newer = read_anchor(p).map(|(aid, _)| aid > id).unwrap_or(false);
            if !newer {
                write_private(p, format!("{id} {}\n", hex::encode(&hash)).as_bytes())?;
            }
        }
        Ok(id)
    }

    /// Checks the whole chain, 10,000 rows at a time, and the anchor.
    pub async fn verify(&self) -> Result<Verdict> {
        let c = self.db.get().await?;
        let anchor = self.anchor.as_ref().and_then(|p| read_anchor(p));
        let mut prev = vec![0u8; 32];
        let (mut after, mut n, mut last_id) = (0i64, 0i64, 0i64);
        let mut anchor_ok = anchor.is_none();
        loop {
            let rows = c
                .query(
                    "SELECT id, at, actor, address, action, target, request, result, events, prev_hash, hash FROM audit
                     WHERE id > $1 ORDER BY id LIMIT 10000",
                    &[&after],
                )
                .await?;
            if rows.is_empty() {
                break;
            }
            for r in &rows {
                let id: i64 = r.get(0);
                let at: DateTime<Utc> = r.get(1);
                let req: String = r.get(6);
                let e = Entry {
                    actor: r.get(2),
                    address: r.get(3),
                    action: r.get(4),
                    target: r.get(5),
                    request: Value::Null,
                    result: r.get(7),
                    events: r.get(8),
                };
                let stored_prev: Vec<u8> = r.get(9);
                let stored: Vec<u8> = r.get(10);
                n += 1;
                if stored_prev != prev || row_hash(&self.key, &prev, &at, &e, &req) != stored {
                    return Ok(Verdict { rows: n, intact: false, first_bad_row: Some(id), missing_from: None });
                }
                if let Some((aid, ahash)) = &anchor {
                    if id == *aid {
                        if stored != *ahash {
                            return Ok(Verdict { rows: n, intact: false, first_bad_row: Some(id), missing_from: None });
                        }
                        anchor_ok = true;
                    }
                }
                prev = stored;
                last_id = id;
            }
            after = last_id;
        }
        if !anchor_ok {
            let from = anchor.map(|(aid, _)| aid);
            return Ok(Verdict { rows: n, intact: false, first_bad_row: None, missing_from: from });
        }
        Ok(Verdict { rows: n, intact: true, first_bad_row: None, missing_from: None })
    }

    pub async fn list(&self, after: i64, limit: i64) -> Result<Vec<Row>> {
        let c = self.db.get().await?;
        let rows = c
            .query(
                "SELECT id, at, actor, address, action, target, request, result, events, hash FROM audit
                 WHERE id > $1 ORDER BY id LIMIT $2",
                &[&after, &limit.clamp(1, 10_000)],
            )
            .await?;
        Ok(rows
            .iter()
            .map(|r| Row {
                id: r.get(0),
                at: r.get(1),
                actor: r.get(2),
                address: r.get(3),
                action: r.get(4),
                target: r.get(5),
                request: serde_json::from_str(r.get::<_, &str>(6)).unwrap_or(Value::Null),
                result: r.get(7),
                events: r.get(8),
                hash: r.get(9),
            })
            .collect())
    }
}

fn read_anchor(p: &std::path::Path) -> Option<(i64, Vec<u8>)> {
    let s = std::fs::read_to_string(p).ok()?;
    let (id, h) = s.trim().split_once(' ')?;
    Some((id.parse().ok()?, hex::decode(h).ok()?))
}

/// CSV, one row per line, with a header. A field a spreadsheet would run as a formula (starting
/// with = + - @, a tab or a carriage return) is prefixed with a quote mark.
pub fn csv(rows: &[Row]) -> String {
    fn q(s: &str) -> String {
        let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{s}") } else { s.to_string() };
        if s.contains([',', '"', '\n', '\r']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s }
    }
    let mut out = String::from("id,at,actor,address,action,target,request,result,events,hash\n");
    for r in rows {
        let at = r.at.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
        let fields = [
            r.id.to_string(),
            at,
            q(&r.actor),
            q(&r.address),
            q(&r.action),
            q(&r.target),
            q(&r.request.to_string()),
            q(&r.result),
            q(&r.events),
            hex::encode(&r.hash),
        ];
        out.push_str(&fields.join(","));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts() {
        let v = redact(json!({"user_id": "ann", "password": "x", "new_password": "y",
                              "inst": {"admin_token": "t", "name": "prod"}, "list": [1]}));
        assert_eq!(v, json!({"user_id": "ann", "password": "(removed)", "new_password": "(removed)",
                             "inst": {"admin_token": "(removed)", "name": "prod"}, "list": [1]}));
    }

    #[test]
    fn hash_covers_every_field_and_the_key() {
        let at = Utc::now().trunc_subsecs(6);
        let k = [3u8; 32];
        let e = Entry { actor: "ann".into(), action: "sign_in".into(), result: "ok".into(), ..Default::default() };
        let h = row_hash(&k, &[0; 32], &at, &e, "{}");
        assert_eq!(h, row_hash(&k, &[0; 32], &at, &e, "{}"));
        assert_ne!(h, row_hash(&[4u8; 32], &[0; 32], &at, &e, "{}"), "another key, another hash");
        assert_ne!(h, row_hash(&k, &[1; 32], &at, &e, "{}"));
        assert_ne!(h, row_hash(&k, &[0; 32], &at, &e, "{\"a\":1}"));
        let mut e2 = e.clone();
        e2.result = "denied".into();
        assert_ne!(h, row_hash(&k, &[0; 32], &at, &e2, "{}"));
        // fields can't shift into each other
        let a = Entry { actor: "ab".into(), action: "c".into(), ..Default::default() };
        let b = Entry { actor: "a".into(), action: "bc".into(), ..Default::default() };
        assert_ne!(row_hash(&k, &[0; 32], &at, &a, "{}"), row_hash(&k, &[0; 32], &at, &b, "{}"));
    }

    #[test]
    fn csv_quotes_and_formulas() {
        let r = |actor: &str, target: &str| Row {
            id: 1,
            at: Utc::now(),
            actor: actor.into(),
            address: "10.0.0.1".into(),
            action: "user_add".into(),
            target: target.into(),
            request: json!({}),
            result: "ok".into(),
            events: String::new(),
            hash: vec![0xab],
        };
        let s = csv(&[r("ann", "bob, the \"admin\"")]);
        assert!(s.lines().nth(1).unwrap().contains("\"bob, the \"\"admin\"\"\""));
        assert!(s.ends_with(",ab\n"));
        let s = csv(&[r("=HYPERLINK(\"http://x\")", "@SUM(1)")]);
        let line = s.lines().nth(1).unwrap();
        assert!(line.contains("\"'=HYPERLINK(\"\"http://x\"\")\"") && line.contains(",'@SUM(1),"), "{line}");
    }
}
