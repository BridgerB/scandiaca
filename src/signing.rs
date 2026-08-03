//! Signing & federation crypto — port of strix `src/signing.ts`.
//!
//! strix uses `node:crypto` with fixed DER prefixes to get at raw Ed25519 key
//! bytes. `ed25519-dalek` works on the raw 32-byte keys directly, so the DER
//! dance is unnecessary — but the *outputs* are byte-identical:
//! - signatures and public keys use **unpadded standard** base64 (`+/`, no `=`),
//! - the key-ID tag uses **base64url** (first 6 chars of the raw public key),
//! - event IDs (in [`crate::events`]) use base64url.
//!
//! Validated against `tests/fixtures/phase1.json` (seed = 32×`0x01` →
//! `publicKeyBase64 = iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w`, derived
//! key-id `ed25519:iojj3X`).

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey as DalekSigningKey, Verifier, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::events::{compute_content_hash, redact_event};

/// A loaded server signing key.
#[derive(Clone)]
pub struct SigningKey {
    /// `algorithm:identifier`, e.g. `ed25519:abc123` or `ed25519:auto`.
    pub key_id: String,
    /// The Ed25519 secret signing key (wraps the 32-byte seed).
    pub signing: DalekSigningKey,
    /// The corresponding public key.
    pub verifying: VerifyingKey,
    /// Unpadded **standard** base64 of the raw 32-byte public key.
    pub public_key_base64: String,
    /// Raw 32-byte Ed25519 seed (for persistence).
    pub seed: [u8; 32],
}

impl SigningKey {
    /// The Ed25519 algorithm name (always `"ed25519"`).
    pub fn algorithm(&self) -> &'static str {
        "ed25519"
    }
}

/// Unpadded standard base64 encode (matches strix `unpaddedBase64`).
pub fn unpadded_base64(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

/// Decode unpadded standard base64 (matches strix `unpaddedBase64Decode`, which
/// re-pads before decoding; the `NO_PAD` engine accepts the unpadded input).
pub fn unpadded_base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD_NO_PAD.decode(s)
}

/// Build a [`SigningKey`] from a 32-byte seed and an explicit key ID
/// (mirrors strix `importSigningKey`).
pub fn import_signing_key(key_id: impl Into<String>, seed: [u8; 32]) -> SigningKey {
    let signing = DalekSigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    let public_key_base64 = unpadded_base64(verifying.as_bytes());
    SigningKey {
        key_id: key_id.into(),
        signing,
        verifying,
        public_key_base64,
        seed,
    }
}

/// Generate a fresh random signing key (mirrors strix `generateSigningKey`):
/// key ID = `ed25519:` + the first 6 **base64url** chars of the raw public key.
pub fn generate_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("OS RNG unavailable");
    let signing = DalekSigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    let key_tag: String = URL_SAFE_NO_PAD
        .encode(verifying.as_bytes())
        .chars()
        .take(6)
        .collect();
    let key_id = format!("ed25519:{key_tag}");
    let public_key_base64 = unpadded_base64(verifying.as_bytes());
    SigningKey {
        key_id,
        signing,
        verifying,
        public_key_base64,
        seed,
    }
}

/// Compute the key-ID tag (`ed25519:` + first 6 base64url chars of the public
/// key) for a given key. Exposed so the import path can derive it too.
pub fn derive_key_id(verifying: &VerifyingKey) -> String {
    let tag: String = URL_SAFE_NO_PAD
        .encode(verifying.as_bytes())
        .chars()
        .take(6)
        .collect();
    format!("ed25519:{tag}")
}

// ---------------------------------------------------------------------------
// JSON signing (mirrors strix `signJson` / `verifyJsonSignature`)
// ---------------------------------------------------------------------------

/// Sign a JSON object, returning a copy with the signature merged into
/// `signatures[server_name][key_id]`. The signature is computed over the
/// canonical JSON of the object with `signatures` and `unsigned` removed; any
/// pre-existing `signatures`/`unsigned` on the input are preserved in the
/// returned object (additive), matching strix.
pub fn sign_json(obj: &Value, server_name: &str, key: &SigningKey) -> Value {
    let mut for_signing = obj.clone();
    if let Value::Object(m) = &mut for_signing {
        m.remove("signatures");
        m.remove("unsigned");
    }
    let canonical = crate::canonical_json::canonical_json(&for_signing);
    let sig = key.signing.sign(canonical.as_bytes());
    let sig_b64 = unpadded_base64(&sig.to_bytes());

    let mut result = obj.clone();
    insert_signature(&mut result, server_name, &key.key_id, &sig_b64);
    result
}

/// Verify a server signature on a JSON object (mirrors strix
/// `verifyJsonSignature`). Returns `false` on any missing field or decode error.
pub fn verify_json_signature(
    obj: &Value,
    server_name: &str,
    key_id: &str,
    public_key_base64: &str,
) -> bool {
    let mut for_verifying = obj.clone();
    if let Value::Object(m) = &mut for_verifying {
        m.remove("signatures");
        m.remove("unsigned");
    }
    let canonical = crate::canonical_json::canonical_json(&for_verifying);

    let Some(sig_b64) = obj
        .get("signatures")
        .and_then(|s| s.get(server_name))
        .and_then(|s| s.get(key_id))
        .and_then(Value::as_str)
    else {
        return false;
    };

    verify_raw(canonical.as_bytes(), sig_b64, public_key_base64)
}

// ---------------------------------------------------------------------------
// Event signing (mirrors strix `signEvent` / `verifyEventSignature`)
// ---------------------------------------------------------------------------

/// Sign an event: compute its content hash, redact (per room version), strip
/// `unsigned`/`signatures`, canonicalize, sign, and return the event (with the
/// content hash added) carrying the new signature. Signatures are over the
/// **redacted** form, so events stay verifiable after redaction.
pub fn sign_event(
    event: &Value,
    server_name: &str,
    key: &SigningKey,
    room_version: Option<&str>,
) -> Value {
    let content_hash = compute_content_hash(event);
    let mut with_hash = event.clone();
    if let Value::Object(m) = &mut with_hash {
        let mut h = Map::new();
        h.insert("sha256".to_string(), Value::String(content_hash));
        m.insert("hashes".to_string(), Value::Object(h));
    }

    let redacted = redact_event(&with_hash, room_version);
    let mut for_signing = redacted;
    if let Value::Object(m) = &mut for_signing {
        m.remove("unsigned");
        m.remove("signatures");
    }
    let canonical = crate::canonical_json::canonical_json(&for_signing);
    let sig = key.signing.sign(canonical.as_bytes());
    let sig_b64 = unpadded_base64(&sig.to_bytes());

    insert_signature(&mut with_hash, server_name, &key.key_id, &sig_b64);
    with_hash
}

/// Compute an event's reference-hash event ID **and** sign it in one pass,
/// sharing the single redacted-canonical form both need. `event` must already
/// carry its content hash (`hashes.sha256`). Byte-identical to calling
/// [`crate::events::compute_event_id`] then [`sign_event`], but avoids their
/// duplicate content-hash / redaction / canonicalization work — the send hot
/// path's dominant cost. When `key` is `None`, only the event ID is computed.
pub fn finalize_event_id_and_sign(
    event: &mut Value,
    server_name: &str,
    key: Option<&SigningKey>,
    room_version: Option<&str>,
) -> String {
    // The redacted, unsigned canonical form is exactly what both the reference
    // hash (event ID) and the signature are computed over — build it once.
    let mut for_ref = redact_event(event, room_version);
    if let Value::Object(m) = &mut for_ref {
        m.remove("unsigned");
        m.remove("signatures");
    }
    let canonical = crate::canonical_json::canonical_json(&for_ref);
    let bytes = canonical.as_bytes();

    let event_id = format!("${}", URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)));

    if let Some(key) = key {
        let sig = key.signing.sign(bytes);
        insert_signature(event, server_name, &key.key_id, &unpadded_base64(&sig.to_bytes()));
    }
    event_id
}

/// Verify an event signature against the sender domain's key (mirrors strix
/// `verifyEventSignature`): redact, strip `unsigned`/`signatures`, canonicalize,
/// verify.
pub fn verify_event_signature(
    event: &Value,
    server_name: &str,
    key_id: &str,
    public_key_base64: &str,
    room_version: Option<&str>,
) -> bool {
    let redacted = redact_event(event, room_version);
    let mut for_verifying = redacted;
    if let Value::Object(m) = &mut for_verifying {
        m.remove("unsigned");
        m.remove("signatures");
    }
    let canonical = crate::canonical_json::canonical_json(&for_verifying);

    let Some(sig_b64) = event
        .get("signatures")
        .and_then(|s| s.get(server_name))
        .and_then(|s| s.get(key_id))
        .and_then(Value::as_str)
    else {
        return false;
    };

    verify_raw(canonical.as_bytes(), sig_b64, public_key_base64)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Merge a signature into `obj.signatures[server_name][key_id]`, creating the
/// nested objects as needed and preserving any existing entries.
fn insert_signature(obj: &mut Value, server_name: &str, key_id: &str, sig_b64: &str) {
    let Value::Object(root) = obj else {
        return;
    };
    let signatures = root
        .entry("signatures")
        .or_insert_with(|| Value::Object(Map::new()));
    if !signatures.is_object() {
        *signatures = Value::Object(Map::new());
    }
    let server = signatures
        .as_object_mut()
        .unwrap()
        .entry(server_name)
        .or_insert_with(|| Value::Object(Map::new()));
    if !server.is_object() {
        *server = Value::Object(Map::new());
    }
    server
        .as_object_mut()
        .unwrap()
        .insert(key_id.to_string(), Value::String(sig_b64.to_string()));
}

/// Verify a raw Ed25519 signature given the message, the unpadded-standard-base64
/// signature, and the unpadded-standard-base64 public key.
fn verify_raw(message: &[u8], sig_b64: &str, public_key_base64: &str) -> bool {
    let Ok(sig_bytes) = unpadded_base64_decode(sig_b64) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_arr);

    let Ok(pub_bytes) = unpadded_base64_decode(public_key_base64) else {
        return false;
    };
    let Ok(pub_arr) = <[u8; 32]>::try_from(pub_bytes.as_slice()) else {
        return false;
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&pub_arr) else {
        return false;
    };

    // Use non-strict verification to match Node's `crypto.verify` acceptance.
    verifying.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SigningKey {
        import_signing_key("ed25519:test", [1u8; 32])
    }

    #[test]
    fn import_matches_fixture_public_key() {
        let key = test_key();
        assert_eq!(
            key.public_key_base64,
            "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"
        );
        assert_eq!(derive_key_id(&key.verifying), "ed25519:iojj3X");
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let key = test_key();
        let obj = serde_json::json!({ "a": 1, "b": "x" });
        let signed = sign_json(&obj, "test.localhost", &key);
        assert!(verify_json_signature(
            &signed,
            "test.localhost",
            "ed25519:test",
            &key.public_key_base64
        ));
    }
}
