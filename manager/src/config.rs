//! The manager's configuration file (TOML), written by `synod-install` on the manager machine.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where the API and console listen, e.g. "0.0.0.0:8443".
    pub listen: SocketAddr,
    /// The manager's repository (key=value or URL form): a one-writer Synod database, which the
    /// installer creates in the installation and names here.
    pub database_url: String,
    /// The cluster CA (PEM): set, the repository is reached over TLS only, its certificate checked
    /// against this CA and the host name (verify-full).
    #[serde(default)]
    pub database_ca: Option<PathBuf>,
    /// TLS certificate chain and key (PEM). The console is served over HTTPS only.
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Tests and development only: plain HTTP, allowed on a loopback address alone.
    #[serde(default)]
    pub plain_http_on_loopback: bool,
    /// 32 random bytes that encrypt the installations' tokens (mode 600, the service's own).
    pub key_file: PathBuf,
    /// Where the manager writes the metrics store's scrape configuration and token files.
    pub data_dir: PathBuf,
    /// The metrics store (VictoriaMetrics), e.g. "http://127.0.0.1:8428".
    #[serde(default = "default_metrics_url")]
    pub metrics_url: String,
    #[serde(default)]
    pub sessions: SessionConfig,
    #[serde(default)]
    pub passwords: PasswordConfig,
    #[serde(default)]
    pub backup: BackupConfig,
    #[serde(default)]
    pub scrape: ScrapeConfig,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields, default)]
pub struct ScrapeConfig {
    /// Keep every histogram of the storage servers (page servers, log servers, storage
    /// controller). Off: only the page server's read latency histogram; the others are about
    /// half of a page server's series and nothing in the console uses them.
    pub storage_histograms: bool,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct BackupConfig {
    /// Where the nightly backups go (unset: none). Better on other storage than this machine's
    /// own disk (a mounted share), so they outlive it.
    pub dir: Option<PathBuf>,
    /// Backups older than this are removed (the newest always stays).
    pub keep_days: i64,
    /// When, in this machine's local time ("HH:MM").
    pub at: String,
    /// Where pg_dump and pg_restore are (unset: on PATH).
    pub pg_bin: Option<PathBuf>,
    /// Where vmbackup and vmrestore are (unset: on PATH).
    pub vm_bin: Option<PathBuf>,
    /// The metrics store's -storageDataPath (unset: metrics aren't backed up).
    pub metrics_data: Option<PathBuf>,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self { dir: None, keep_days: 7, at: "02:30".into(), pg_bin: None, vm_bin: None, metrics_data: None }
    }
}

impl BackupConfig {
    /// `at` as (hour, minute).
    pub fn time_of_day(&self) -> Result<(u32, u32)> {
        let (h, m) = self.at.split_once(':').context("backup.at: HH:MM")?;
        let (h, m): (u32, u32) = (h.parse().context("backup.at: HH:MM")?, m.parse().context("backup.at: HH:MM")?);
        if h > 23 || m > 59 {
            bail!("backup.at: HH:MM");
        }
        Ok((h, m))
    }
}

fn default_metrics_url() -> String {
    "http://127.0.0.1:8428".into()
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct SessionConfig {
    /// A console session ends after this long without a request.
    pub idle_minutes: i64,
    /// Any session (console or `synodmgr login`) ends this long after sign-in.
    pub max_hours: i64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self { idle_minutes: 30, max_hours: 12 }
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct PasswordConfig {
    pub min_length: usize,
    pub max_length: usize,
    /// Failures in a row before an account waits.
    pub lockout_failures: i32,
    pub lockout_minutes: i64,
    /// 0: passwords never expire (NIST SP 800-63B); a customer's policy may set a number.
    pub expire_days: i64,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self { min_length: 15, max_length: 128, lockout_failures: 10, lockout_minutes: 15, expire_days: 0 }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let c: Config = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        c.check()?;
        Ok(c)
    }

    pub fn check(&self) -> Result<()> {
        match (&self.tls_cert, &self.tls_key) {
            (Some(_), Some(_)) => {}
            (None, None) if self.plain_http_on_loopback => {
                if !self.listen.ip().is_loopback() {
                    bail!("plain_http_on_loopback: listen on a loopback address (127.0.0.1), not {}", self.listen);
                }
            }
            _ => bail!("tls_cert and tls_key are both needed: the console is served over HTTPS only"),
        }
        if self.passwords.min_length < 8 || self.passwords.max_length < self.passwords.min_length {
            bail!("passwords: min_length at least 8, max_length at least min_length");
        }
        if self.sessions.idle_minutes < 1 || self.sessions.max_hours < 1 {
            bail!("sessions: idle_minutes and max_hours at least 1");
        }
        self.backup.time_of_day()?;
        if self.backup.keep_days < 1 {
            bail!("backup.keep_days: at least 1");
        }
        Ok(())
    }

    pub fn https(&self) -> bool {
        self.tls_cert.is_some()
    }

    /// The manager's own repository database's name (a one-writer Synod database, usually
    /// synodmgr): the console and API won't stop it, since a stopped repository stops the manager.
    pub fn repository_dbname(&self) -> Option<String> {
        let cfg: tokio_postgres::Config = self.database_url.parse().ok()?;
        cfg.get_dbname().map(str::to_string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Config> {
        let c: Config = toml::from_str(s)?;
        c.check()?;
        Ok(c)
    }

    #[test]
    fn https_required_off_loopback() {
        let base = r#"database_url = "host=/tmp"
key_file = "/k"
data_dir = "/d"
"#;
        assert!(parse(&format!("listen = \"0.0.0.0:8443\"\n{base}")).is_err());
        assert!(parse(&format!("listen = \"0.0.0.0:8443\"\nplain_http_on_loopback = true\n{base}")).is_err());
        let c = parse(&format!("listen = \"127.0.0.1:8443\"\nplain_http_on_loopback = true\n{base}")).unwrap();
        assert!(!c.https());
        assert_eq!(c.sessions.idle_minutes, 30);
        assert_eq!(c.passwords.min_length, 15);
        let c = parse(&format!("listen = \"0.0.0.0:8443\"\ntls_cert = \"/c\"\ntls_key = \"/k\"\n{base}")).unwrap();
        assert!(c.https());
    }
}
