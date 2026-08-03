//! Typing / receipts / read-markers / reports — ports of strix
//! `handlers/{typing,receipts,read-markers,report}.ts` (local paths; EDU
//! fan-out arrives with the federation phase).

use axum::extract::{Path, State};
use axum::response::Json;
use serde_json::{json, Map, Value};

use crate::errors::{bad_json, forbidden, not_found, MatrixResult};
use crate::room_ops::require_joined_room;
use crate::server::{now_ms, AppState, AuthCtx};
use crate::types::identifiers::{EventId, RoomId, UserId};

/// `PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId}`.
pub async fn put_typing(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((room_id, user_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    if auth.user_id.as_str() != user_id {
        return Err(forbidden("Cannot set typing for another user"));
    }
    let typing = body.get("typing").and_then(Value::as_bool).unwrap_or(false);
    let timeout = body.get("timeout").and_then(Value::as_i64);
    st.storage
        .set_typing(&RoomId::from(room_id.as_str()), &UserId::from(user_id.as_str()), typing, timeout)
        .await;
    Ok(Json(json!({})))
}

/// `POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}`.
pub async fn post_receipt(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((room_id, receipt_type, event_id)): Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    require_joined_room(&*st.storage, &rid, auth.user_id.as_str()).await?;
    let thread_id = body.get("thread_id").and_then(Value::as_str);
    st.storage
        .set_receipt(
            &rid,
            &auth.user_id,
            &EventId::from(event_id.as_str()),
            &receipt_type,
            now_ms(),
            thread_id,
        )
        .await;
    Ok(Json(json!({})))
}

/// `POST /_matrix/client/v3/rooms/{roomId}/read_markers`.
pub async fn post_read_markers(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    require_joined_room(&*st.storage, &rid, auth.user_id.as_str()).await?;

    let fully_read = body.get("m.fully_read").and_then(Value::as_str);
    let read = body.get("m.read").and_then(Value::as_str);
    let read_private = body.get("m.read.private").and_then(Value::as_str);

    for eid in [fully_read, read, read_private].into_iter().flatten() {
        if !eid.starts_with('$') {
            return Err(bad_json("Invalid event ID"));
        }
        let entry = st.storage.get_event(&EventId::from(eid)).await;
        if entry
            .as_ref()
            .and_then(|e| e.event.get("room_id").and_then(Value::as_str))
            != Some(&room_id)
        {
            return Err(not_found("Event not found in this room"));
        }
    }

    if let Some(fr) = fully_read {
        let mut content = Map::new();
        content.insert("event_id".to_string(), json!(fr));
        st.storage
            .set_room_account_data(&auth.user_id, &rid, "m.fully_read", content)
            .await;
    }
    let now = now_ms();
    if let Some(r) = read {
        st.storage
            .set_receipt(&rid, &auth.user_id, &EventId::from(r), "m.read", now, None)
            .await;
    }
    if let Some(rp) = read_private {
        st.storage
            .set_receipt(&rid, &auth.user_id, &EventId::from(rp), "m.read.private", now, None)
            .await;
    }
    Ok(Json(json!({})))
}

/// `POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}`.
pub async fn report_event(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((room_id, event_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    require_joined_room(&*st.storage, &rid, auth.user_id.as_str()).await?;
    let eid = EventId::from(event_id.as_str());
    let entry = st.storage.get_event(&eid).await;
    if entry
        .as_ref()
        .and_then(|e| e.event.get("room_id").and_then(Value::as_str))
        != Some(&room_id)
    {
        return Err(not_found("Event not found"));
    }
    st.storage
        .store_report(
            &auth.user_id,
            &rid,
            &eid,
            body.get("score").and_then(Value::as_i64),
            body.get("reason").and_then(Value::as_str),
        )
        .await;
    Ok(Json(json!({})))
}

/// `POST /_matrix/client/v3/rooms/{roomId}/report`.
pub async fn report_room(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    require_joined_room(&*st.storage, &rid, auth.user_id.as_str()).await?;
    st.storage
        .store_report(&auth.user_id, &rid, &EventId::from(""), None, body.get("reason").and_then(Value::as_str))
        .await;
    Ok(Json(json!({})))
}

/// `POST /_matrix/client/v3/users/{userId}/report`.
pub async fn report_user(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(user_id): Path<String>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let reason = match body.get("reason").and_then(Value::as_str) {
        Some(r) => format!("User report for {user_id}: {r}"),
        None => format!("User report for {user_id}"),
    };
    st.storage
        .store_report(&auth.user_id, &RoomId::from(""), &EventId::from(""), None, Some(&reason))
        .await;
    Ok(Json(json!({})))
}
