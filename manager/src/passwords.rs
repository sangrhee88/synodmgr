//! Passwords: Argon2id hashes and the rules (NIST SP 800-63B Revision 4): 15 to 128 characters, any
//! characters, not the user ID, not easy to guess (common and breached passwords, keyboard runs,
//! repeats: zxcvbn's lists and patterns), no composition rules, no scheduled changes.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::config::PasswordConfig;

/// Argon2id with OWASP's recommended minimum (19 MiB, 2 passes, 1 lane).
fn argon2() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(19 * 1024, 2, 1, None).expect("argon2 params"))
}

pub fn hash(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    argon2().hash_password(password.as_bytes(), &salt).expect("argon2 hash").to_string()
}

pub fn verify(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(h) => argon2().verify_password(password.as_bytes(), &h).is_ok(),
        Err(_) => false,
    }
}

/// A hash of no password anyone has: unknown user IDs are checked against it, so a wrong user ID
/// takes as long as a wrong password.
pub fn dummy_hash() -> &'static str {
    static H: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    H.get_or_init(|| hash(&crate::crypto::new_token()))
}

/// Why a new password is refused, in words for the person choosing it; None if it is fine.
pub fn check(password: &str, user_id: &str, name: &str, cfg: &PasswordConfig) -> Option<String> {
    let n = password.chars().count();
    if n < cfg.min_length {
        return Some(format!("Use at least {} characters (a few words with spaces work well).", cfg.min_length));
    }
    if n > cfg.max_length {
        return Some(format!("Use at most {} characters.", cfg.max_length));
    }
    let lower = password.to_lowercase();
    if !user_id.is_empty() && lower.contains(&user_id.to_lowercase()) {
        return Some("Don't put your user ID in your password.".into());
    }
    let mut inputs: Vec<&str> = vec![user_id, "synod", "synodmgr", "manager", "oracle", "postgres"];
    inputs.extend(name.split_whitespace());
    let est = zxcvbn::zxcvbn(password, &inputs);
    // score 3: about 10^8 guesses or more
    if (est.score() as u8) < 3 {
        return Some("This password is too easy to guess: it is a common password, a pattern or a repeat. Pick something less predictable.".into());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes() {
        let h = hash("correct horse battery staple");
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify("correct horse battery staple", &h));
        assert!(!verify("correct horse battery stapler", &h));
        assert!(!verify("x", "not a hash"));
        assert_ne!(hash("same"), hash("same"), "salted");
        assert!(!verify("", dummy_hash()));
    }

    #[test]
    fn rules() {
        let c = PasswordConfig::default();
        assert!(check("short pass", "ann", "", &c).unwrap().contains("at least 15"));
        assert!(check(&"x".repeat(129), "ann", "", &c).unwrap().contains("at most 128"));
        assert!(check("my name is annlee and more", "annlee", "", &c).unwrap().contains("user ID"));
        assert!(check("passwordpassword", "ann", "", &c).unwrap().contains("too easy"));
        assert!(check("123456789012345678", "ann", "", &c).unwrap().contains("too easy"));
        assert!(check("qwertyuiopasdfghjkl", "ann", "", &c).unwrap().contains("too easy"));
        assert!(check("aaaaaaaaaaaaaaaaaaaa", "ann", "", &c).unwrap().contains("too easy"));
        // long, unpredictable: fine, with or without symbols or capitals
        assert_eq!(check("lantern orbit cactus mellow", "ann", "", &c), None);
        assert_eq!(check("Tq8#vW2!pLm9zR4x", "ann", "", &c), None);
        assert_eq!(check("빨간 우산을 쓴 고양이가 걷는다", "ann", "", &c), None, "any characters");
    }
}
