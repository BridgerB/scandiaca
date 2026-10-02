//! Federation types — storage-relevant subset of strix `src/types/federation.ts`.
//!
//! The make/send-join, transaction, and query response shapes arrive with the
//! federation handlers in Phase 6; storage only needs [`ServerKeys`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::identifiers::{Base64, ServerName, Timestamp};

/// A remote server's published signing keys (`GET /_matrix/key/v2/server`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerKeys {
    pub server_name: ServerName,
    pub verify_keys: BTreeMap<String, VerifyKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_verify_keys: Option<BTreeMap<String, OldVerifyKey>>,
    pub signatures: BTreeMap<String, BTreeMap<String, Base64>>,
    pub valid_until_ts: Timestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyKey {
    pub key: Base64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OldVerifyKey {
    pub key: Base64,
    pub expired_ts: Timestamp,
}
