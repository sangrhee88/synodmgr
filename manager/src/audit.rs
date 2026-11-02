//! The audit log: one append-only row per action and sign-in, each hashed together with the
//! previous row's hash, so removing or editing a row breaks the chain from that row on.

use anyhow::Result;
use chrono::{DateTime, SubsecRound, Utc};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

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

/// The hash of a row: sha256 over the previous hash and the row's fields, each length-prefixed.
pub fn row_hash(prev: &[u8], at: &DateTime<Utc>, e: &Entry, request: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(prev);
    let at = at.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
    let req = request.to_string();
    for f in [&at, &e.actor, &e.address, &e.action, &e.target, &req, &e.result, &e.events] {
        h.update((f.len() as u64).to_be_bytes());
        h.update(f.as_bytes());
    }
    h.finalize().to_vec()
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

/// Appends a row (rows are appended one at a time, under an advisory lock).
pub async fn append(db: &Db, mut e: Entry) -> Result<i64> {
    e.request = redact(e.request);
    let mut c = db.get().await?;
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
    let hash = row_hash(&prev, &at, &e, &req);
    let id: i64 = tx
        .query_one(
            "INSERT INTO audit (at, actor, address, action, target, request, result, events, prev_hash, hash)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id",
            &[&at, &e.actor, &e.address, &e.action, &e.target, &req, &e.result, &e.events, &prev, &hash],
        )
        .await?
        .get(0);
    tx.commit().await?;
    Ok(id)
}

/// Checks the whole chain: None if intact, else the first row id that doesn't match.
pub async fn verify(db: &Db) -> Result<(i64, Option<i64>)> {
    let c = db.get().await?;
    let rows = c
        .query(
            "SELECT id, at, actor, address, action, target, request, result, events, prev_hash, hash FROM audit ORDER BY id",
            &[],
        )
        .await?;
    let mut prev = vec![0u8; 32];
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
        if stored_prev != prev || row_hash(&prev, &at, &e, &req) != stored {
            return Ok((rows.len() as i64, Some(id)));
        }
        prev = stored;
    }
    Ok((rows.len() as i64, None))
}

pub async fn list(db: &Db, after: i64, limit: i64) -> Result<Vec<Row>> {
    let c = db.get().await?;
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

/// CSV, one row per line, with a header.
pub fn csv(rows: &[Row]) -> String {
    fn q(s: &str) -> String {
        if s.contains([',', '"', '\n', '\r']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_string() }
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
    fn hash_covers_every_field() {
        let at = Utc::now().trunc_subsecs(6);
        let e = Entry { actor: "ann".into(), action: "sign_in".into(), result: "ok".into(), ..Default::default() };
        let h = row_hash(&[0; 32], &at, &e, "{}");
        assert_eq!(h, row_hash(&[0; 32], &at, &e, "{}"));
        assert_ne!(h, row_hash(&[1; 32], &at, &e, "{}"));
        assert_ne!(h, row_hash(&[0; 32], &at, &e, "{\"a\":1}"));
        let mut e2 = e.clone();
        e2.result = "denied".into();
        assert_ne!(h, row_hash(&[0; 32], &at, &e2, "{}"));
        // fields can't shift into each other
        let a = Entry { actor: "ab".into(), action: "c".into(), ..Default::default() };
        let b = Entry { actor: "a".into(), action: "bc".into(), ..Default::default() };
        assert_ne!(row_hash(&[0; 32], &at, &a, "{}"), row_hash(&[0; 32], &at, &b, "{}"));
    }

    #[test]
    fn csv_quotes() {
        let r = Row {
            id: 1,
            at: Utc::now(),
            actor: "ann".into(),
            address: "10.0.0.1".into(),
            action: "user_add".into(),
            target: "bob, the \"admin\"".into(),
            request: json!({}),
            result: "ok".into(),
            events: String::new(),
            hash: vec![0xab],
        };
        let s = csv(&[r]);
        assert!(s.lines().nth(1).unwrap().contains("\"bob, the \"\"admin\"\"\""));
        assert!(s.ends_with(",ab\n"));
    }
}
