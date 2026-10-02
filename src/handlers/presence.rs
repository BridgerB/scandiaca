//! Presence — port of strix `handlers/presence.ts` (local path; federation
//! fan-out arrives with the federation phase).

use axum::extract::{Path, State};
use axum::response::Json;
use serde_json::{json, Value};

use crate::errors::{forbidden, MatrixResult};
use crate::server::{now_ms, AppState, AuthCtx};
use crate::types::ephemeral::PresenceState;
use crate::types::identifiers::UserId;

/// `GET /_matrix/client/v3/presence/{userId}/status`.
pub async fn get_presence(
    State(st): State<AppState>,
    _auth: AuthCtx,
    Path(user_id): Path<String>,
) -> Json<Value> {
    let uid = UserId::from(user_id.as_str());
    match st.storage.get_presence(&uid).await {
        None => Json(json!({ "presence": "offline" })),
        Some(data) => {
            let mut result = json!({ "presence": presence_str(&data.presence) });
            if let Some(msg) = &data.status_msg {
                result["status_msg"] = json!(msg);
            }
            if let Some(ts) = data.last_active_ts {
                result["last_active_ago"] = json!(now_ms() - ts);
            }
            Json(result)
        }
    }
}

/// `PUT /_matrix/client/v3/presence/{userId}/status`.
pub async fn put_presence(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(user_id): Path<String>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    if auth.user_id.as_str() != user_id {
        return Err(forbidden("Cannot set another user's presence"));
    }
    let uid = UserId::from(user_id.as_str());
    let presence = parse_presence(body.get("presence").and_then(Value::as_str));
    let status_msg = body.get("status_msg").and_then(Value::as_str);
    st.storage.set_presence(&uid, presence, status_msg).await;

    // Federate the presence update to every remote server sharing a room with
    // this user (Synapse wraps per-user updates in a top-level `push` array) —
    // TestRemotePresence.
    if let Some(fed) = &st.federation_client {
        let room_ids = st.storage.get_rooms_for_user(&uid).await;
        if !room_ids.is_empty() {
            let mut update = serde_json::Map::new();
            update.insert("user_id".to_string(), json!(user_id));
            update.insert("presence".to_string(), json!(presence_str(&presence)));
            if let Some(msg) = status_msg {
                update.insert("status_msg".to_string(), json!(msg));
            }
            update.insert("last_active_ago".to_string(), json!(0));
            crate::federation::outbound::fanout_edu_to_room_servers(
                &*st.storage,
                fed,
                &st.server_name,
                &room_ids,
                json!({ "edu_type": "m.presence", "content": { "push": [Value::Object(update)] } }),
            )
            .await;
        }
    }
    Ok(Json(json!({})))
}

fn parse_presence(s: Option<&str>) -> PresenceState {
    match s {
        Some("online") => PresenceState::Online,
        Some("unavailable") => PresenceState::Unavailable,
        _ => PresenceState::Offline,
    }
}

fn presence_str(p: &PresenceState) -> &'static str {
    match p {
        PresenceState::Online => "online",
        PresenceState::Unavailable => "unavailable",
        PresenceState::Offline => "offline",
    }
}
