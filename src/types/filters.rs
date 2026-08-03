//! Sync/room event filter types — port of strix `src/types/filters.ts`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A filter over individual events (`EventFilter` / `RoomEventFilter`). Only the
/// fields the port acts on are modeled explicitly; the rest ride along in
/// `extra` so a stored filter round-trips unchanged.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoomEventFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_types: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub senders: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_senders: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rooms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_rooms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contains_url: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lazy_load_members: Option<bool>,
}

/// Parse a `filter` query-string value (URL-decoded JSON) into a
/// [`RoomEventFilter`]. Malformed input is treated as no filter (strix
/// `parseRoomEventFilter`).
pub fn parse_room_event_filter(raw: Option<&str>) -> Option<RoomEventFilter> {
    let raw = raw?;
    let parsed: Value = serde_json::from_str(raw).ok()?;
    if !parsed.is_object() {
        return None;
    }
    serde_json::from_value(parsed).ok()
}
