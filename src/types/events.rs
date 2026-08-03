//! Event I/O types — port of strix `src/types/events.ts`.
//!
//! The engine represents PDUs as raw [`serde_json::Value`] (see
//! [`crate::types::internal::StateEvents`]); these typed structs are the
//! *projections* handed to clients (`ClientEvent`) and embedded in invites
//! (`StrippedStateEvent`). The federation PDU itself is intentionally not a
//! struct, to avoid dropping unknown fields on round-trip.

use serde::{Deserialize, Serialize};

use super::identifiers::{EventId, RoomId, Timestamp, UserId};
use super::json::{JsonObject, JsonValue};

/// Event as returned to clients via the Client-Server API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientEvent {
    pub content: JsonObject,
    pub event_id: EventId,
    pub origin_server_ts: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_id: Option<RoomId>,
    pub sender: UserId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_key: Option<String>,
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacts: Option<EventId>,
}

/// Minimal state event (used in invites, knocks, room summaries).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StrippedStateEvent {
    pub content: JsonObject,
    pub sender: UserId,
    pub state_key: String,
    #[serde(rename = "type")]
    pub event_type: String,
}

/// Ephemeral Data Unit — non-persistent federation event (typing, presence,
/// receipts, device-list updates, to-device).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Edu {
    pub edu_type: String,
    pub content: JsonObject,
}

/// A to-device message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToDeviceEvent {
    pub content: JsonObject,
    pub sender: UserId,
    #[serde(rename = "type")]
    pub event_type: String,
}
