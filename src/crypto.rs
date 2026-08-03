//! Token / ID generators — port of strix `src/crypto.ts`.
//!
//! All use the OS RNG and unpadded base64url, matching Node's
//! `randomBytes(n).toString("base64url")`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).expect("OS RNG unavailable");
    buf
}

/// Access/refresh token: 32 random bytes, base64url.
pub fn generate_token() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes(32))
}

/// UIAA session id: 16 random bytes, base64url.
pub fn generate_session_id() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes(16))
}

/// Device id: 8 random bytes, base64url, uppercased.
pub fn generate_device_id() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes(8)).to_uppercase()
}

/// Room id: `!<18 random bytes base64url>:<server_name>`.
pub fn generate_room_id(server_name: &str) -> String {
    format!(
        "!{}:{server_name}",
        URL_SAFE_NO_PAD.encode(random_bytes(18))
    )
}

/// Media id: 18 random bytes, base64url.
pub fn generate_media_id() -> String {
    URL_SAFE_NO_PAD.encode(random_bytes(18))
}
