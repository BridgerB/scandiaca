//! End-to-end-encryption types — port of strix `src/types/e2ee.ts`.
//!
//! Only the storage-relevant subset is typed here; request/response shapes for
//! the CS-API handlers arrive in Phase 5. Polymorphic `string | OneTimeKey` and
//! the layered key-backup shapes are carried as [`serde_json::Value`] in storage
//! signatures to keep the trait tractable.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::identifiers::{DeviceId, UserId};
use super::json::JsonObject;

/// `server/user -> keyId -> signature`.
pub type Signatures = BTreeMap<String, BTreeMap<String, String>>;

/// A device's published identity/one-time key material.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceKeys {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub algorithms: Vec<String>,
    /// `"algorithm:device_id" -> key`.
    pub keys: BTreeMap<String, String>,
    pub signatures: Signatures,
}

/// A cross-signing key (master / self-signing / user-signing).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossSigningKey {
    pub user_id: UserId,
    pub usage: Vec<String>,
    pub keys: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Signatures>,
}

/// The three cross-signing keys for a user.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CrossSigningKeys {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub master_key: Option<CrossSigningKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_signing_key: Option<CrossSigningKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_signing_key: Option<CrossSigningKey>,
}

/// A single backed-up room key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBackupData {
    pub first_message_index: i64,
    pub forwarded_count: i64,
    pub is_verified: bool,
    pub session_data: JsonObject,
}
