//! Sync filters — port of strix `handlers/filters.ts`.

use axum::extract::{Path, State};
use axum::response::Json;
use serde_json::{json, Map, Value};

use crate::errors::{bad_json, forbidden, not_found, MatrixResult};
use crate::server::{AppState, AuthCtx};
use crate::types::identifiers::UserId;

fn is_string_array(v: &Value) -> bool {
    v.as_array()
        .map(|a| a.iter().all(Value::is_string))
        .unwrap_or(false)
}

/// Validate a room event filter's list-typed fields (strix
/// `validateRoomEventFilter`).
fn validate_room_event_filter(filter: &Map<String, Value>, label: &str) -> MatrixResult<()> {
    const LIST_FIELDS: &[&str] = &[
        "rooms",
        "not_rooms",
        "senders",
        "not_senders",
        "types",
        "not_types",
    ];
    for field in LIST_FIELDS {
        let Some(value) = filter.get(*field) else {
            continue;
        };
        if !is_string_array(value) {
            return Err(bad_json(format!("'{label}.{field}' must be a list of strings")));
        }
        let arr = value.as_array().unwrap();
        if *field == "rooms" || *field == "not_rooms" {
            for id in arr {
                if !id.as_str().unwrap_or("").starts_with('!') {
                    return Err(bad_json(format!("'{label}.{field}' must contain room IDs")));
                }
            }
        }
        if *field == "senders" || *field == "not_senders" {
            for id in arr {
                if !id.as_str().unwrap_or("").starts_with('@') {
                    return Err(bad_json(format!("'{label}.{field}' must contain user IDs")));
                }
            }
        }
    }
    Ok(())
}

/// Validate the top-level filter object (strix `validateFilter`).
fn validate_filter(filter: &Map<String, Value>) -> MatrixResult<()> {
    for field in ["presence", "account_data", "room"] {
        if let Some(value) = filter.get(field) {
            if !value.is_object() {
                return Err(bad_json(format!("'{field}' must be an object")));
            }
        }
    }
    if let Some(presence) = filter.get("presence").and_then(Value::as_object) {
        validate_room_event_filter(presence, "presence")?;
    }
    if let Some(room) = filter.get("room").and_then(Value::as_object) {
        for field in ["state", "timeline", "ephemeral", "account_data"] {
            if let Some(value) = room.get(field) {
                if !value.is_object() {
                    return Err(bad_json(format!("'room.{field}' must be an object")));
                }
                validate_room_event_filter(value.as_object().unwrap(), &format!("room.{field}"))?;
            }
        }
    }
    Ok(())
}

/// `POST /_matrix/client/v3/user/{userId}/filter`.
pub async fn create_filter(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(user_id): Path<String>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    if auth.user_id.as_str() != user_id {
        return Err(forbidden("Cannot create filters for another user"));
    }
    let Some(filter) = body.as_object() else {
        return Err(bad_json("Filter must be a JSON object"));
    };
    validate_filter(filter)?;
    let uid = UserId::from(user_id.as_str());
    let filter_id = st.storage.create_filter(&uid, filter.clone()).await;
    Ok(Json(json!({ "filter_id": filter_id })))
}

/// `GET /_matrix/client/v3/user/{userId}/filter/{filterId}`.
pub async fn get_filter(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((user_id, filter_id)): Path<(String, String)>,
) -> MatrixResult<Json<Value>> {
    if auth.user_id.as_str() != user_id {
        return Err(forbidden("Cannot access another user's filters"));
    }
    let uid = UserId::from(user_id.as_str());
    match st.storage.get_filter(&uid, &filter_id).await {
        Some(filter) => Ok(Json(Value::Object(filter))),
        None => Err(not_found("Filter not found")),
    }
}
