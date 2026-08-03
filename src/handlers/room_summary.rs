//! Room summary (MSC3266) — port of strix `handlers/room-summary.ts`.

use axum::extract::{Path, State};
use axum::response::Json;
use serde_json::{json, Value};

use crate::errors::{not_found, MatrixResult};
use crate::events::get_membership;
use crate::server::{AppState, AuthCtx};
use crate::types::identifiers::{RoomAlias, RoomId};
use crate::types::internal::RoomState;

fn state_content<'a>(room: &'a RoomState, key: &str, field: &str) -> Option<&'a str> {
    room.state_events
        .get(key)
        .and_then(|e| e.get("content"))
        .and_then(|c| c.get(field))
        .and_then(Value::as_str)
}

/// `GET /_matrix/client/v1/room_summary/{roomIdOrAlias}` (and unstable alias).
pub async fn get_room_summary(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id_or_alias): Path<String>,
) -> MatrixResult<Json<Value>> {
    let room_id: RoomId = if room_id_or_alias.starts_with('#') {
        st.storage
            .get_room_by_alias(&RoomAlias::from(room_id_or_alias.as_str()))
            .await
            .ok_or_else(|| not_found("Room alias not found"))?
            .room_id
    } else {
        RoomId::from(room_id_or_alias.as_str())
    };

    let room = st.storage.get_room(&room_id).await.ok_or_else(|| not_found("Room not found"))?;
    let num_joined = room
        .state_events
        .iter()
        .filter(|(k, v)| {
            k.starts_with("m.room.member\u{1f}")
                && v.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("join")
        })
        .count();

    let mut body = json!({
        "room_id": room_id.as_str(),
        "num_joined_members": num_joined,
        "world_readable": state_content(&room, "m.room.history_visibility\u{1f}", "history_visibility") == Some("world_readable"),
        "guest_can_join": state_content(&room, "m.room.guest_access\u{1f}", "guest_access") == Some("can_join"),
    });
    for (field, key, sub) in [
        ("name", "m.room.name\u{1f}", "name"),
        ("topic", "m.room.topic\u{1f}", "topic"),
        ("avatar_url", "m.room.avatar\u{1f}", "url"),
        ("join_rule", "m.room.join_rules\u{1f}", "join_rule"),
        ("room_type", "m.room.create\u{1f}", "type"),
    ] {
        if let Some(v) = state_content(&room, key, sub) {
            body[field] = json!(v);
        }
    }
    if let Some(m) = get_membership(&room, auth.user_id.as_str()) {
        body["membership"] = json!(m);
    }
    Ok(Json(body))
}
