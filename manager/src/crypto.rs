//! Secrets at rest (the installations' control plane tokens): AES-256-GCM with a key file that only
//! the manager's service account can read. Tokens for sign-in sessions: random, stored as hashes.

use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rand::RngCore;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct SecretBox {
    cipher: Aes256Gcm,
}

impl SecretBox {
    pub fn from_key(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            bail!("the key must be 32 bytes, not {}", key.len());
        }
        Ok(Self { cipher: Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("{e}"))? })
    }

    /// Reads the key file, creating it (32 random bytes, mode 600) if it isn't there.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if !path.exists() {
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            write_private(path, &key)?;
        }
        let key = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        Self::from_key(&key)
    }

    /// base64(nonce || ciphertext)
    pub fn seal(&self, plain: &str) -> Result<String> {
        if plain.is_empty() {
            return Ok(String::new());
        }
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ct = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plain.as_bytes())
            .map_err(|_| anyhow!("encrypting"))?;
        let mut out = nonce.to_vec();
        out.extend(ct);
        Ok(STANDARD.encode(out))
    }

    pub fn open(&self, sealed: &str) -> Result<String> {
        if sealed.is_empty() {
            return Ok(String::new());
        }
        let raw = STANDARD.decode(sealed).context("not base64")?;
        if raw.len() < 13 {
            bail!("sealed value too short");
        }
        let (nonce, ct) = raw.split_at(12);
        let plain = self
            .cipher
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| anyhow!("decrypting: wrong key, or the value was changed"))?;
        Ok(String::from_utf8(plain)?)
    }
}

/// A file only its owner can read and write.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("writing {}", tmp.display()))?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// A new session or API token: 32 random bytes, URL-safe base64.
pub fn new_token() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// A one-time password for a new or reset account: 20 characters from an alphabet without
/// look-alikes (about 115 bits).
pub fn one_time_password() -> String {
    const A: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..20).map(|_| A[(rng.next_u32() as usize) % A.len()] as char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open() {
        let b = SecretBox::from_key(&[7u8; 32]).unwrap();
        let s = b.seal("token-1").unwrap();
        assert_ne!(s, "token-1");
        assert_eq!(b.open(&s).unwrap(), "token-1");
        assert_ne!(b.seal("token-1").unwrap(), s, "a new nonce each time");
        assert_eq!(b.open("").unwrap(), "");
        let other = SecretBox::from_key(&[8u8; 32]).unwrap();
        assert!(other.open(&s).is_err());
        let mut raw = STANDARD.decode(&s).unwrap();
        raw[20] ^= 1;
        assert!(b.open(&STANDARD.encode(raw)).is_err(), "a changed value is refused");
    }

    #[test]
    fn key_file_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("k");
        let a = SecretBox::load_or_create(&p).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        let b = SecretBox::load_or_create(&p).unwrap();
        assert_eq!(b.open(&a.seal("x").unwrap()).unwrap(), "x");
    }

    #[test]
    fn tokens() {
        assert_ne!(new_token(), new_token());
        assert_eq!(new_token().len(), 43);
        assert_eq!(token_hash("a").len(), 32);
        let p = one_time_password();
        assert_eq!(p.len(), 20);
        assert!(!p.contains('0') && !p.contains('O') && !p.contains('l'));
    }
}
