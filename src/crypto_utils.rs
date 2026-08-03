//! Password hashing — port of strix `src/crypto-utils.ts`.
//!
//! scrypt with the same parameters: stored format `scrypt$<b64 salt>$<b64 dk>`
//! (N = `SCRYPT_COST`/16384, r = 8, p = 1, 32-byte salt, 64-byte key), compared
//! constant-time. A legacy plaintext fallback matches strix's pre-hash accounts.
//!
//! These are CPU-bound; call them from a blocking context
//! (`tokio::task::spawn_blocking`) so they don't stall the async runtime.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use scrypt::{scrypt, Params};

const R: u32 = 8;
const P: u32 = 1;
const KEYLEN: usize = 64;
const SALT_LEN: usize = 32;

/// scrypt `log2(N)`. `SCRYPT_COST` must be a power of two ≥ 2; default N = 16384
/// (log2 = 14). Complement lowers it for speed.
fn scrypt_log_n() -> u8 {
    match std::env::var("SCRYPT_COST")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
    {
        Some(n) if n >= 2 && n.is_power_of_two() => n.trailing_zeros() as u8,
        _ => 14,
    }
}

/// Hash a password into the `scrypt$salt$dk` format.
pub fn hash_password(password: &str) -> String {
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).expect("OS RNG unavailable");
    let params = Params::new(scrypt_log_n(), R, P, KEYLEN).expect("valid scrypt params");
    let mut dk = vec![0u8; KEYLEN];
    scrypt(password.as_bytes(), &salt, &params, &mut dk).expect("scrypt");
    format!("scrypt${}${}", STANDARD.encode(salt), STANDARD.encode(dk))
}

/// Verify a password against a stored hash (or legacy plaintext).
pub fn verify_password(password: &str, hash: &str) -> bool {
    let parts: Vec<&str> = hash.split('$').collect();
    if parts.len() != 3 || parts[0] != "scrypt" {
        // Legacy plaintext comparison for old accounts.
        return password == hash;
    }
    let (Ok(salt), Ok(stored)) = (STANDARD.decode(parts[1]), STANDARD.decode(parts[2])) else {
        return false;
    };
    let Ok(params) = Params::new(scrypt_log_n(), R, P, stored.len()) else {
        return false;
    };
    let mut dk = vec![0u8; stored.len()];
    if scrypt(password.as_bytes(), &salt, &params, &mut dk).is_err() {
        return false;
    }
    constant_time_eq(&dk, &stored)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_roundtrip() {
        // Use a low cost for test speed.
        std::env::set_var("SCRYPT_COST", "2");
        let h = hash_password("hunter2");
        assert!(h.starts_with("scrypt$"));
        assert!(verify_password("hunter2", &h));
        assert!(!verify_password("wrong", &h));
    }
}
