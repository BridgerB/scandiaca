//! Internal representations — port of strix `src/types/internal.ts`.
//!
//! Phase 2 needs [`RoomState`]; the account/session/media records arrive with
//! the storage layer (Phase 3).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::identifiers::{
    AccessToken, Base64, DeviceId, EventId, RefreshToken, RoomId, ServerName, Timestamp, UserId,
};
use super::room_versions::RoomVersion;

/// Current-state map: `"event_type\x1fstate_key"` → event (a PDU as raw JSON).
///
/// A `BTreeMap` gives deterministic iteration; State Resolution is designed to
/// be order-independent, but determinism keeps tests and any incidental ordering
/// reproducible. Events are stored as [`Value`] so unknown federation fields
/// round-trip losslessly and re-hashing stays byte-exact.
pub type StateEvents = BTreeMap<String, Value>;

/// Internal representation of a room.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RoomState {
    pub room_id: RoomId,
    pub room_version: RoomVersion,
    pub state_events: StateEvents,
    pub depth: i64,
    pub forward_extremities: Vec<EventId>,
    /// Memoized `"type\x1fstate_key"` → event ID for the current state events.
    /// Computing an event ID is expensive (redact + canonical JSON + SHA-256) and
    /// `select_auth_events` needs several per event sent, for state that rarely
    /// changes — so cache them at write time. Derived data: an empty/missing map
    /// (e.g. from an older snapshot or a transient `RoomState`) just means callers
    /// fall back to recomputing, so it never affects correctness.
    #[serde(default)]
    pub state_event_ids: BTreeMap<String, String>,
}

/// Account kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountType {
    User,
    Guest,
    Admin,
    Appservice,
}

/// Internal user account record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserAccount {
    pub user_id: UserId,
    pub localpart: String,
    pub server_name: ServerName,
    pub password_hash: String,
    pub account_type: AccountType,
    pub is_deactivated: bool,
    pub created_at: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub displayname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
}

/// Internal device session (the device record; the access token lives on
/// `StoredSession`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceSession {
    pub device_id: DeviceId,
    pub user_id: UserId,
    pub access_token_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_ts: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

/// A device session plus the tokens that authenticate it (strix `StoredSession`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredSession {
    pub device_id: DeviceId,
    pub user_id: UserId,
    pub access_token_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_ts: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    pub access_token: AccessToken,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<RefreshToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
}

/// Internal representation of stored media.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredMedia {
    pub media_id: String,
    pub origin: ServerName,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<UserId>,
    pub content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_name: Option<String>,
    pub file_size: i64,
    pub content_hash: Base64,
    pub created_at: Timestamp,
    pub quarantined: bool,
}
