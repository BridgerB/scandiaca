//! Client-Server API handlers — port of strix `src/handlers/`.
//!
//! Each handler is an axum function capturing dependencies through `State`
//! (strix's handler factories) and returning `MatrixResult<_>` so a thrown
//! `MatrixError` renders as a Matrix JSON error.

pub mod account;
pub mod account_data;
pub mod admin;
pub mod appservice;
pub mod auth;
pub mod cross_signing;
pub mod delayed_events;
pub mod devices;
pub mod directory;
pub mod discovery;
pub mod e2ee;
pub mod ephemeral;
pub mod federation;
pub mod filters;
pub mod key_backup;
pub mod logout;
pub mod media;
pub mod membership;
pub mod misc;
pub mod notifications;
pub mod presence;
pub mod profile;
pub mod push_rules;
pub mod pushers;
pub mod refresh;
pub mod relations;
pub mod room_events;
pub mod room_summary;
pub mod room_upgrade;
pub mod rooms;
pub mod search;
pub mod sliding_sync;
pub mod spaces;
pub mod sync;
pub mod thread_subscriptions;
pub mod user_directory;

use serde_json::Value;

/// Serialize a stored PDU to a client event.
pub fn client_event(event: &Value, event_id: &str) -> Value {
    serde_json::to_value(crate::events::pdu_to_client_event(event, event_id)).unwrap_or(Value::Null)
}

/// Client event without `room_id` (the form used inside `/sync`, where events are
/// already keyed by room).
pub fn client_event_no_room(event: &Value, event_id: &str) -> Value {
    let mut v = client_event(event, event_id);
    if let Some(o) = v.as_object_mut() {
        o.remove("room_id");
    }
    v
}
