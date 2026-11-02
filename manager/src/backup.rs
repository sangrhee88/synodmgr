//! Backups of the manager: everything needed to bring it back on the same machine or a new one.
//!
//! A backup is one file, `synodmgr-backup-<UTC time>.smb`, holding a tar of:
//!
//! - `repository.dump`: the repository (users, sessions, installations and their sealed tokens,
//!   events, the audit log), from `pg_dump -Fc`;
//! - `metrics/`: the metrics store's data, from `vmbackup` (a snapshot, so consistent while it
//!   keeps scraping);
//! - `files/manager-secrets.key` (it unseals the installations' tokens and keys the audit chain)
//!   and `files/audit-anchor`;
//! - `manifest.json`: what's in it.
//!
//! The file is encrypted (AES-256-GCM in 1 MiB chunks, each bound to its position and to whether
//! it is the last, so a reordered or cut-off file doesn't decrypt) with a key derived from the
//! backup key, `SYNODMGR_BACKUP_KEY`, which the installer keeps with its other secrets: the
//! backup carries the manager's key file, so it must not be readable without it.
//!
//! The manager makes one every night (`[backup] at`, local time) and keeps `keep_days` of them;
//! `synodmgr-admin backup` makes one now and `synodmgr-admin restore FILE` brings one back
//! (with the manager and the metrics store stopped).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::config::Config;
use crate::crypto::write_private;

pub const KEY_ENV: &str = "SYNODMGR_BACKUP_KEY";
const MAGIC: &[u8; 16] = b"SYNODMGR-BACKUP\x01";
const HEADER_LEN: usize = 16 + 16 + 7;
const CHUNK: usize = 1 << 20;
pub const SUFFIX: &str = ".smb";
const PREFIX: &str = "synodmgr-backup-";

#[derive(Serialize, Deserialize, Debug)]
pub struct Manifest {
    pub format: u32,
    pub manager_version: String,
    pub created_at: DateTime<Utc>,
    pub host: String,
    pub repository: bool,
    pub metrics: bool,
    pub files: Vec<String>,
    /// The audit anchor when the backup began (the dump has this row and maybe newer ones).
    pub audit_anchor: Option<String>,
}

/// The backup key from the environment: at least 32 characters (the installer makes 64 hex).
pub fn key_from_env() -> Result<String> {
    let k = std::env::var(KEY_ENV).unwrap_or_default();
    if k.len() < 32 {
        bail!("{KEY_ENV} is not set or shorter than 32 characters (the installer keeps it with its secrets)");
    }
    Ok(k)
}

fn file_key(key: &str, salt: &[u8]) -> Aes256Gcm {
    let mut h = <Hmac<Sha256> as Mac>::new_from_slice(salt).expect("any length");
    h.update(b"synodmgr backup v1\0");
    h.update(key.as_bytes());
    Aes256Gcm::new_from_slice(&h.finalize().into_bytes()).expect("32 bytes")
}

fn nonce(prefix: &[u8], i: u32, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..7].copy_from_slice(prefix);
    n[7..11].copy_from_slice(&i.to_be_bytes());
    n[11] = last as u8;
    n
}

/// Encrypts everything `src` gives into `dst`.
pub fn encrypt(key: &str, mut src: impl Read, mut dst: impl Write) -> Result<u64> {
    let mut header = [0u8; HEADER_LEN];
    header[..16].copy_from_slice(MAGIC);
    rand::thread_rng().fill_bytes(&mut header[16..]);
    let cipher = file_key(key, &header[16..32]);
    dst.write_all(&header)?;
    let mut buf = vec![0u8; CHUNK];
    let mut next = vec![0u8; CHUNK];
    let mut n = read_full(&mut src, &mut buf)?;
    let (mut i, mut total) = (0u32, 0u64);
    loop {
        // look one chunk ahead to know whether this one is the last
        let m = if n == CHUNK { read_full(&mut src, &mut next)? } else { 0 };
        let last = m == 0;
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce(&header[32..], i, last)), Payload { msg: &buf[..n], aad: &header })
            .map_err(|_| anyhow::anyhow!("encrypting"))?;
        dst.write_all(&(ct.len() as u32).to_be_bytes())?;
        dst.write_all(&ct)?;
        total += n as u64;
        if last {
            break;
        }
        std::mem::swap(&mut buf, &mut next);
        n = m;
        i = i.checked_add(1).context("backup too large")?;
    }
    dst.flush()?;
    Ok(total)
}

/// Decrypts `src` into `dst`; fails on a wrong key, a changed byte, or a file cut short.
pub fn decrypt(key: &str, mut src: impl Read, mut dst: impl Write) -> Result<u64> {
    let mut header = [0u8; HEADER_LEN];
    src.read_exact(&mut header).context("not a Synod Manager backup (too short)")?;
    if &header[..16] != MAGIC {
        bail!("not a Synod Manager backup");
    }
    let cipher = file_key(key, &header[16..32]);
    let (mut i, mut total) = (0u32, 0u64);
    let mut cur = read_chunk(&mut src)?.context("backup cut short (no data)")?;
    loop {
        let next = read_chunk(&mut src)?;
        let last = next.is_none();
        let pt = cipher
            .decrypt(Nonce::from_slice(&nonce(&header[32..], i, last)), Payload { msg: &cur, aad: &header })
            .map_err(|_| {
                if i == 0 {
                    anyhow::anyhow!("can't decrypt the backup: wrong {KEY_ENV}, or the file was changed")
                } else {
                    anyhow::anyhow!("the backup is damaged or cut short (at {} MiB)", i)
                }
            })?;
        dst.write_all(&pt)?;
        total += pt.len() as u64;
        match next {
            None => break,
            Some(c) => cur = c,
        }
        i = i.checked_add(1).context("backup too large")?;
    }
    dst.flush()?;
    Ok(total)
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

fn read_chunk(r: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match read_full(r, &mut len)? {
        0 => return Ok(None),
        4 => {}
        _ => bail!("the backup is cut short"),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > CHUNK + 16 {
        bail!("the backup is damaged");
    }
    let mut c = vec![0u8; len];
    r.read_exact(&mut c).context("the backup is cut short")?;
    Ok(Some(c))
}

/// libpq's connection string for the repository (for pg_dump and pg_restore) and its password,
/// kept out of the command line.
fn libpq(cfg: &Config) -> Result<(String, Option<String>)> {
    let pc: tokio_postgres::Config = cfg.database_url.parse().context("database_url")?;
    let password = pc.get_password().map(|p| String::from_utf8_lossy(p).to_string());
    if cfg.database_url.contains("://") {
        bail!("database_url: use the key=value form for backups (the installer does)");
    }
    let mut parts: Vec<String> =
        cfg.database_url.split_whitespace().filter(|t| !t.starts_with("password=")).map(String::from).collect();
    if let Some(ca) = &cfg.database_ca {
        parts.retain(|t| !t.starts_with("sslmode=") && !t.starts_with("sslrootcert="));
        parts.push("sslmode=verify-full".into());
        parts.push(format!("sslrootcert={}", ca.display()));
    }
    Ok((parts.join(" "), password))
}

fn run(cmd: &mut Command, what: &str) -> Result<()> {
    let out = cmd.stdin(Stdio::null()).output().with_context(|| format!("{what}: can't run {:?}", cmd.get_program()))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let tail: Vec<&str> = err.lines().rev().take(8).collect();
        bail!("{what} failed ({}): {}", out.status, tail.into_iter().rev().collect::<Vec<_>>().join(" | "));
    }
    Ok(())
}

fn pg(cfg: &Config, prog: &str) -> PathBuf {
    cfg.backup.pg_bin.as_ref().map(|d| d.join(prog)).unwrap_or_else(|| prog.into())
}

fn vm(cfg: &Config, prog: &str) -> PathBuf {
    cfg.backup.vm_bin.as_ref().map(|d| d.join(prog)).unwrap_or_else(|| prog.into())
}

fn scratch(dir: &Path, what: &str) -> Result<PathBuf> {
    let mut r = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut r);
    let p = dir.join(format!(".{what}-{}", hex::encode(r)));
    std::fs::create_dir_all(&p)?;
    std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    Ok(p)
}

struct Cleanup(PathBuf);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What a backup made.
#[derive(Serialize, Debug)]
pub struct Made {
    pub path: PathBuf,
    pub bytes: u64,
    pub seconds: f64,
    pub metrics: bool,
}

/// Makes a backup in `dir` (blocking: run it off the async runtime).
pub fn make(cfg: &Config, dir: &Path, key: &str) -> Result<Made> {
    let t0 = std::time::Instant::now();
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let _lock = lock(dir)?;
    let work = scratch(dir, "backup")?;
    let _clean = Cleanup(work.clone());
    let files = work.join("files");
    std::fs::create_dir_all(&files)?;

    // the anchor first: the dump after it then has its row (and maybe newer ones)
    let anchor_path = cfg.data_dir.join("audit-anchor");
    let anchor = std::fs::read_to_string(&anchor_path).ok();
    let mut names = vec![];
    if let Some(a) = &anchor {
        std::fs::write(files.join("audit-anchor"), a)?;
        names.push("audit-anchor".to_string());
    }
    std::fs::copy(&cfg.key_file, files.join("manager-secrets.key"))
        .with_context(|| format!("reading {}", cfg.key_file.display()))?;
    names.push("manager-secrets.key".to_string());

    let (conn, password) = libpq(cfg)?;
    let mut c = Command::new(pg(cfg, "pg_dump"));
    c.args(["-Fc", "--no-owner", "--no-privileges", "-f"]).arg(work.join("repository.dump")).arg("-d").arg(&conn);
    if let Some(p) = &password {
        c.env("PGPASSWORD", p);
    }
    run(&mut c, "pg_dump (the repository)")?;

    let metrics = match &cfg.backup.metrics_data {
        Some(data) => {
            let mut c = Command::new(vm(cfg, "vmbackup"));
            c.arg(format!("-storageDataPath={}", data.display()))
                .arg(format!("-snapshot.createURL={}/snapshot/create", cfg.metrics_url.trim_end_matches('/')))
                .arg(format!("-dst=fs://{}", work.join("metrics").display()))
                .arg("-loggerLevel=ERROR");
            run(&mut c, "vmbackup (the metrics store)")?;
            true
        }
        None => false,
    };

    let manifest = Manifest {
        format: 1,
        manager_version: crate::VERSION.into(),
        created_at: Utc::now(),
        host: hostname(),
        repository: true,
        metrics,
        files: names,
        audit_anchor: anchor.map(|a| a.trim().to_string()),
    };
    std::fs::write(work.join("manifest.json"), serde_json::to_vec_pretty(&manifest)?)?;

    let name = format!("{PREFIX}{}{SUFFIX}", manifest.created_at.format("%Y%m%dT%H%M%SZ"));
    let path = dir.join(&name);
    let part = dir.join(format!(".{name}.part"));
    let mut tar = Command::new("tar")
        .arg("-C")
        .arg(&work)
        .args(["-cf", "-", "manifest.json", "repository.dump", "files"])
        .args(if metrics { vec!["metrics"] } else { vec![] })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running tar")?;
    let out = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&part)?
    };
    let mut w = std::io::BufWriter::new(out);
    let res = encrypt(key, tar.stdout.take().expect("piped"), &mut w);
    let st = tar.wait()?;
    if let Err(e) = res.and_then(|_| if st.success() { Ok(()) } else { bail!("tar failed ({st})") }) {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    w.into_inner().map_err(|e| e.into_error())?.sync_all()?;
    std::fs::rename(&part, &path)?;
    let bytes = std::fs::metadata(&path)?.len();
    Ok(Made { path, bytes, seconds: t0.elapsed().as_secs_f64(), metrics })
}

/// Removes this directory's backups older than `keep_days` (always keeping the newest).
pub fn prune(dir: &Path, keep_days: i64) -> Result<Vec<PathBuf>> {
    let mut all = list(dir)?;
    all.sort_by_key(|(_, t, _)| *t);
    let newest = all.last().map(|(p, _, _)| p.clone());
    let cutoff = Utc::now() - chrono::Duration::days(keep_days);
    let mut removed = vec![];
    for (p, t, _) in all {
        if t < cutoff && Some(&p) != newest.as_ref() {
            std::fs::remove_file(&p)?;
            removed.push(p);
        }
    }
    Ok(removed)
}

/// The backups in `dir`: path, time, size.
pub fn list(dir: &Path) -> Result<Vec<(PathBuf, DateTime<Utc>, u64)>> {
    let mut out = vec![];
    let Ok(rd) = std::fs::read_dir(dir) else { return Ok(out) };
    for e in rd {
        let e = e?;
        let name = e.file_name().to_string_lossy().to_string();
        let Some(ts) = name.strip_prefix(PREFIX).and_then(|s| s.strip_suffix(SUFFIX)) else { continue };
        let Ok(t) = chrono::NaiveDateTime::parse_from_str(ts, "%Y%m%dT%H%M%SZ") else { continue };
        out.push((e.path(), t.and_utc(), e.metadata()?.len()));
    }
    Ok(out)
}

/// What to bring back.
#[derive(Debug, Clone, Copy)]
pub struct Parts {
    pub repository: bool,
    pub metrics: bool,
    pub files: bool,
}

/// Brings a backup back (blocking). The manager and the metrics store must be stopped.
pub fn restore(cfg: &Config, file: &Path, key: &str, parts: Parts) -> Result<Manifest> {
    if std::net::TcpStream::connect_timeout(&cfg.listen, std::time::Duration::from_secs(1)).is_ok() {
        bail!("the manager is running ({}): stop it first", cfg.listen);
    }
    let work_root = cfg.data_dir.clone();
    let work = scratch(&work_root, "restore")?;
    let _clean = Cleanup(work.clone());
    let mut tar = Command::new("tar")
        .arg("-C")
        .arg(&work)
        .args(["--no-same-owner", "-xf", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running tar")?;
    let src = std::fs::File::open(file).with_context(|| format!("opening {}", file.display()))?;
    let res = decrypt(key, std::io::BufReader::new(src), tar.stdin.take().expect("piped"));
    let st = tar.wait()?;
    res?;
    if !st.success() {
        bail!("tar failed unpacking the backup ({st})");
    }
    let m: Manifest = serde_json::from_slice(&std::fs::read(work.join("manifest.json"))?).context("manifest.json")?;
    if m.format != 1 {
        bail!("backup format {} (this manager reads 1)", m.format);
    }

    if parts.metrics && m.metrics {
        let Some(data) = &cfg.backup.metrics_data else {
            bail!("[backup] metrics_data is not set: where should the metrics go?")
        };
        let probe = format!("{}/health", cfg.metrics_url.trim_end_matches('/'));
        if let Some(addr) = probe.strip_prefix("http://").and_then(|s| s.split('/').next()) {
            if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
                if std::net::TcpStream::connect_timeout(&sa, std::time::Duration::from_secs(1)).is_ok() {
                    bail!("the metrics store is running ({addr}): stop it first");
                }
            }
        }
        std::fs::create_dir_all(data)?;
        let mut c = Command::new(vm(cfg, "vmrestore"));
        c.arg(format!("-src=fs://{}", work.join("metrics").display()))
            .arg(format!("-storageDataPath={}", data.display()))
            .arg("-loggerLevel=ERROR");
        run(&mut c, "vmrestore (the metrics store)")?;
    }
    if parts.repository && m.repository {
        let (conn, password) = libpq(cfg)?;
        let mut c = Command::new(pg(cfg, "pg_restore"));
        c.args(["--clean", "--if-exists", "--no-owner", "--no-privileges", "--single-transaction", "--exit-on-error", "-d"])
            .arg(&conn)
            .arg(work.join("repository.dump"));
        if let Some(p) = &password {
            c.env("PGPASSWORD", p);
        }
        run(&mut c, "pg_restore (the repository)")?;
    }
    if parts.files {
        let key_file = work.join("files/manager-secrets.key");
        write_private(&cfg.key_file, &std::fs::read(&key_file).context("the backup has no key file")?)?;
        let anchor = work.join("files/audit-anchor");
        if anchor.exists() {
            write_private(&cfg.data_dir.join("audit-anchor"), &std::fs::read(anchor)?)?;
        }
    }
    Ok(m)
}

/// One backup at a time in a directory.
fn lock(dir: &Path) -> Result<std::fs::File> {
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join(".lock"))?;
    if f.try_lock().is_err() {
        bail!("another backup is running in {}", dir.display());
    }
    Ok(f)
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname").map(|s| s.trim().to_string()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(n: usize) {
        let key = "k".repeat(40);
        let data: Vec<u8> = (0..n).map(|i| (i * 7 % 251) as u8).collect();
        let mut enc = vec![];
        encrypt(&key, &data[..], &mut enc).unwrap();
        let mut dec = vec![];
        decrypt(&key, &enc[..], &mut dec).unwrap();
        assert_eq!(dec, data, "{n} bytes");
    }

    #[test]
    fn encrypts_any_size() {
        for n in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK] {
            roundtrip(n);
        }
    }

    #[test]
    fn refuses_wrong_key_changes_and_cuts() {
        let key = "k".repeat(40);
        let data = vec![5u8; 2 * CHUNK + 10];
        let mut enc = vec![];
        encrypt(&key, &data[..], &mut enc).unwrap();
        let e = decrypt(&"x".repeat(40), &enc[..], std::io::sink()).unwrap_err().to_string();
        assert!(e.contains("wrong"), "{e}");
        let mut bad = enc.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 1;
        assert!(decrypt(&key, &bad[..], std::io::sink()).is_err(), "a changed byte");
        // cut at a chunk boundary: the new last chunk wasn't encrypted as the last
        let first = HEADER_LEN + 4 + CHUNK + 16;
        assert!(decrypt(&key, &enc[..first], std::io::sink()).is_err(), "cut at a chunk boundary");
        assert!(decrypt(&key, &enc[..enc.len() - 1], std::io::sink()).is_err(), "cut short");
        // chunks swapped
        let second = first + 4 + CHUNK + 16;
        let mut sw = enc[..HEADER_LEN].to_vec();
        sw.extend_from_slice(&enc[first..second]);
        sw.extend_from_slice(&enc[HEADER_LEN..first]);
        sw.extend_from_slice(&enc[second..]);
        assert!(decrypt(&key, &sw[..], std::io::sink()).is_err(), "chunks swapped");
    }

    #[test]
    fn prunes_old_keeps_newest() {
        let d = tempfile::tempdir().unwrap();
        let mk = |days: i64| {
            let t = Utc::now() - chrono::Duration::days(days);
            let p = d.path().join(format!("{PREFIX}{}{SUFFIX}", t.format("%Y%m%dT%H%M%SZ")));
            std::fs::write(&p, b"x").unwrap();
            p
        };
        let (a, b, c) = (mk(10), mk(8), mk(1));
        std::fs::write(d.path().join("other.txt"), b"x").unwrap();
        let removed = prune(d.path(), 7).unwrap();
        assert_eq!(removed.len(), 2);
        assert!(!a.exists() && !b.exists() && c.exists());
        // all old: the newest stays
        let d2 = tempfile::tempdir().unwrap();
        let p = d2.path().join(format!("{PREFIX}20200101T000000Z{SUFFIX}"));
        std::fs::write(&p, b"x").unwrap();
        assert!(prune(d2.path(), 7).unwrap().is_empty() && p.exists());
    }
}
