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
