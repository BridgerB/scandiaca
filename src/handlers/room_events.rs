//! Send / state / messages handlers — port of strix `handlers/room-events.ts`
//! (local path). `putSendEvent` plus `get_all_state` / `get_messages` reads.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::response::Json;
use serde_json::{json, Value};

use super::client_event;
use crate::errors::{bad_json, forbidden, not_found, MatrixError, MatrixResult};
use crate::events::{
    build_event, check_event_auth, get_user_power_level, pdu_to_client_event, redact_event,
    select_auth_events, BuildEventParams,
};
use crate::relations::{bundle_aggregations, index_relation};
use crate::room_ops::{
    events_up_to, require_can_read_room, require_joined_room, send_state_event, state_as_of,
    EventContext,
};
use crate::server::{AppState, AuthCtx};
use crate::storage::Direction;
use crate::types::identifiers::{EventId, RoomId};

const MAX_EVENT_SIZE: usize = 65536;

/// `PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}`.
pub async fn put_send_event(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((room_id, event_type, txn_id)): Path<(String, String, String)>,
    Json(content): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let room_id: RoomId = room_id.into();
    let scoped_txn = format!("{room_id}\u{1f}{txn_id}");

    if let Some(existing) = st
        .storage
        .get_txn_event_id(&auth.user_id, &auth.device_id, &scoped_txn)
        .await
    {
        return Ok(Json(json!({ "event_id": existing.as_str() })));
    }
    if !content.is_object() {
        return Err(bad_json("Event content must be a JSON object"));
    }

    let room = require_joined_room(&*st.storage, &room_id, auth.user_id.as_str()).await?;
    let auth_events = select_auth_events(&event_type, None, &room, auth.user_id.as_str(), None);
    let prev_events: Vec<String> = room
        .forward_extremities
        .iter()
        .map(|e| e.to_string())
        .collect();

    let sn: &str = &st.server_name;
    let (mut event, event_id) = build_event(BuildEventParams {
        room_id: room_id.as_str(),
        sender: auth.user_id.as_str(),
        event_type: &event_type,
        content,
        state_key: None,
        depth: room.depth,
        prev_events,
        auth_events,
        redacts: None,
        unsigned: None,
        server_name: sn,
        signing_key: Some(st.signing_key.as_ref()),
        room_version: Some(&room.room_version),
        origin_server_ts: None,
    });

    // Size guard: the byte length is independent of key order, so use serde_json's
    // fast compact serializer rather than a second full canonicalization (which
    // sorts keys and allocates per number).
    if serde_json::to_vec(&event).map(|v| v.len()).unwrap_or(0) > MAX_EVENT_SIZE {
        return Err(MatrixError::new("M_TOO_LARGE", "Event is too large", 413));
    }
    check_event_auth(&event, &room)?;

    // Stamp the transaction id (unsigned is excluded from the hash/signature).
    if let Some(obj) = event.as_object_mut() {
        let unsigned = obj.entry("unsigned").or_insert_with(|| json!({}));
        if let Some(u) = unsigned.as_object_mut() {
            u.insert("transaction_id".to_string(), json!(txn_id));
        }
    }

    let eid = EventId::from(event_id.as_str());
    // Index relations and propagate/push while borrowing the event.
    index_relation(&*st.storage, &event, &eid).await;
    if let Some(fed) = &st.federation_client {
        crate::federation::outbound::fanout_event(&*st.storage, fed, &st.server_name, &room_id, &event).await;
    }
    crate::appservice::push::push_to_appservices(&event, event_id.as_str(), &st.registrations);

    // Store the event, advance the DAG head, and record txn idempotency in a
    // single write-lock (event moved in, not cloned).
    let txn_key = format!("{}|{}|{}", auth.user_id, auth.device_id, scoped_txn);
    st.storage
        .commit_timeline_event(event, &eid, &room_id, room.depth + 1, vec![eid.clone()], &txn_key)
        .await;

    Ok(Json(json!({ "event_id": event_id })))
}

/// `PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}` (empty state key)
/// and `.../state/{eventType}/{stateKey}`.
pub async fn put_state_event(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(params): Path<Vec<String>>,
    Json(content): Json<Value>,
) -> MatrixResult<Json<Value>> {
    // Path is [roomId, eventType] or [roomId, eventType, stateKey].
    let room_id = params.first().cloned().unwrap_or_default();
    let event_type = params.get(1).cloned().unwrap_or_default();
    let state_key = params.get(2).cloned().unwrap_or_default();

    if !content.is_object() {
        return Err(bad_json("Event content must be a JSON object"));
    }
    let rid = RoomId::from(room_id.as_str());
    let room = require_joined_room(&*st.storage, &rid, auth.user_id.as_str()).await?;

    let mut ctx = EventContext {
        depth: room.depth,
        prev_events: room.forward_extremities.iter().map(|e| e.as_str().to_string()).collect(),
        room_state: room,
    };
    let event_id = send_state_event(
        &*st.storage,
        &st.server_name,
        &mut ctx,
        auth.user_id.as_str(),
        &event_type,
        &state_key,
        content,
        Some(st.signing_key.as_ref()),
        None,
    )
    .await?;

    // Propagate the new state event to remote servers + matching appservices.
    let eid = EventId::from(event_id.as_str());
    if let Some(stored) = st.storage.get_event(&eid).await {
        if let Some(fed) = &st.federation_client {
            crate::federation::outbound::fanout_event(&*st.storage, fed, &st.server_name, &rid, &stored.event).await;
        }
        crate::appservice::push::push_to_appservices(&stored.event, event_id.as_str(), &st.registrations);
    }
    Ok(Json(json!({ "event_id": event_id })))
}

/// `GET /_matrix/client/v3/rooms/{roomId}/state/{eventType}` and
/// `.../state/{eventType}/{stateKey}` — returns the state event content, or the
/// full client event when `?format=event`.
pub async fn get_state_event(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(params): Path<Vec<String>>,
    Query(query): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let room_id = params.first().cloned().unwrap_or_default();
    let event_type = params.get(1).cloned().unwrap_or_default();
    let state_key = params.get(2).cloned().unwrap_or_default();

    let rid = RoomId::from(room_id.as_str());
    let read = require_can_read_room(&*st.storage, &rid, auth.user_id.as_str()).await?;

    // Departed readers (SPEC-216) see state as of their leave point.
    let found: Option<(Value, String)> = if let Some(pos) = read.leave_pos {
        let key = crate::events::make_state_key(&event_type, &state_key);
        state_as_of(&*st.storage, &rid, pos)
            .await
            .get(&key)
            .map(|(ev, id)| (ev.clone(), id.as_str().to_string()))
    } else {
        st.storage
            .get_state_event(&rid, &event_type, &state_key)
            .await
            .map(|rec| (rec.event, rec.event_id.as_str().to_string()))
    };
    match found {
        Some((event, event_id)) => {
            if query.get("format").map(String::as_str) == Some("event") {
                Ok(Json(client_event(&event, &event_id)))
            } else {
                Ok(Json(event.get("content").cloned().unwrap_or_else(|| json!({}))))
            }
        }
        None => Err(not_found("Event not found")),
    }
}

/// `GET /_matrix/client/v3/rooms/{roomId}/event/{eventId}`.
pub async fn get_event(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((room_id, event_id)): Path<(String, String)>,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    require_can_read_room(&*st.storage, &rid, auth.user_id.as_str()).await?;
    let entry = st.storage.get_event(&EventId::from(event_id.as_str())).await;
    let entry = match entry {
        Some(e) if !e.rejected && e.event.get("room_id").and_then(Value::as_str) == Some(&room_id) => e,
        _ => return Err(not_found("Event not found")),
    };
    let mut ce = client_event(&entry.event, entry.event_id.as_str());
    // Strip transaction_id from unsigned when the requester is not the sender.
    if ce.get("sender").and_then(Value::as_str) != Some(auth.user_id.as_str()) {
        if let Some(u) = ce.get_mut("unsigned").and_then(Value::as_object_mut) {
            u.remove("transaction_id");
        }
    }
    let mut events = [ce];
    bundle_aggregations(&*st.storage, &mut events, &auth.user_id).await;
    ce = events.into_iter().next().unwrap();
    Ok(Json(ce))
}

/// `GET /_matrix/client/v3/rooms/{roomId}/members`.
pub async fn get_members(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    let read = require_can_read_room(&*st.storage, &rid, auth.user_id.as_str()).await?;

    let membership = params.get("membership").map(String::as_str);
    let not_membership = params.get("not_membership").map(String::as_str);

    // Member events: as-of-leave for departed readers, else current.
    let members: Vec<(Value, String)> = if let Some(pos) = read.leave_pos {
        state_as_of(&*st.storage, &rid, pos)
            .await
            .into_iter()
            .filter(|(k, _)| k.starts_with("m.room.member\u{1f}"))
            .map(|(_, (ev, id))| (ev, id.as_str().to_string()))
            .collect()
    } else {
        st.storage
            .get_member_events(&rid)
            .await
            .into_iter()
            .map(|e| (e.event, e.event_id.as_str().to_string()))
            .collect()
    };
    let chunk: Vec<Value> = members
        .into_iter()
        .filter(|(ev, _)| {
            let m = ev.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str);
            membership.is_none_or(|f| m == Some(f)) && not_membership.is_none_or(|f| m != Some(f))
        })
        .map(|(ev, id)| client_event(&ev, &id))
        .collect();
    Ok(Json(json!({ "chunk": chunk })))
}

/// `GET /_matrix/client/v3/rooms/{roomId}/joined_members`.
pub async fn get_joined_members(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    require_joined_room(&*st.storage, &rid, auth.user_id.as_str()).await?;

    let mut joined = serde_json::Map::new();
    for entry in st.storage.get_member_events(&rid).await {
        let content = entry.event.get("content");
        if content.and_then(|c| c.get("membership")).and_then(Value::as_str) != Some("join") {
            continue;
        }
        let Some(user_id) = entry.event.get("state_key").and_then(Value::as_str) else {
            continue;
        };
        let profile = st.storage.get_profile(&user_id.into()).await;
        joined.insert(
            user_id.to_string(),
            json!({
                "display_name": profile.as_ref().and_then(|p| p.displayname.clone()),
                "avatar_url": profile.and_then(|p| p.avatar_url),
            }),
        );
    }
    Ok(Json(json!({ "joined": joined })))
}

/// `PUT /_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}`.
pub async fn redact(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((room_id, target_event_id, txn_id)): Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    let scoped_txn = format!("{room_id}\u{1f}{txn_id}");
    if let Some(existing) = st
        .storage
        .get_txn_event_id(&auth.user_id, &auth.device_id, &scoped_txn)
        .await
    {
        return Ok(Json(json!({ "event_id": existing.as_str() })));
    }

    let room = require_joined_room(&*st.storage, &rid, auth.user_id.as_str()).await?;

    let target = st.storage.get_event(&EventId::from(target_event_id.as_str())).await;
    let target_is_local = target
        .as_ref()
        .is_some_and(|t| t.event.get("room_id").and_then(Value::as_str) == Some(&room_id));

    // Power-level check: need redact PL unless redacting your own local event.
    let redact_pl = room
        .state_events
        .get("m.room.power_levels\u{1f}")
        .and_then(|e| e.get("content"))
        .and_then(|c| c.get("redact"))
        .and_then(Value::as_f64)
        .unwrap_or(50.0);
    let sender_pl = get_user_power_level(auth.user_id.as_str(), &room);
    let own_event = target
        .as_ref()
        .and_then(|t| t.event.get("sender").and_then(Value::as_str))
        == Some(auth.user_id.as_str());
    if sender_pl < redact_pl && (!target_is_local || !own_event) {
        return Err(forbidden("Insufficient power level to redact"));
    }

    let mut content = serde_json::Map::new();
    if let Some(reason) = body.get("reason").and_then(Value::as_str) {
        content.insert("reason".to_string(), json!(reason));
    }
    let auth_events = select_auth_events("m.room.redaction", None, &room, auth.user_id.as_str(), None);
    let (event, event_id) = build_event(BuildEventParams {
        room_id: room_id.as_str(),
        sender: auth.user_id.as_str(),
        event_type: "m.room.redaction",
        content: Value::Object(content),
        state_key: None,
        depth: room.depth,
        prev_events: room.forward_extremities.iter().map(|e| e.as_str().to_string()).collect(),
        auth_events,
        redacts: Some(&target_event_id),
        unsigned: None,
        server_name: &st.server_name,
        signing_key: Some(st.signing_key.as_ref()),
        room_version: Some(&room.room_version),
        origin_server_ts: None,
    });
    check_event_auth(&event, &room)?;
    let eid = EventId::from(event_id.as_str());
    st.storage.store_event(event.clone(), &eid).await;
    st.storage.update_room_dag(&rid, room.depth + 1, vec![eid.clone()]).await;

    // Apply the redaction to the target if we hold it locally.
    if let Some(mut t) = target {
        if target_is_local {
            let redacted = redact_event(&t.event, Some(&room.room_version));
            if let Some(obj) = t.event.as_object_mut() {
                obj.insert("content".to_string(), redacted.get("content").cloned().unwrap_or_else(|| json!({})));
                let mut unsigned = redacted.get("unsigned").and_then(Value::as_object).cloned().unwrap_or_default();
                unsigned.insert(
                    "redacted_because".to_string(),
                    pdu_to_client_event_value(&event, event_id.as_str()),
                );
                obj.insert("unsigned".to_string(), Value::Object(unsigned));
            }
            st.storage.update_event(&EventId::from(target_event_id.as_str()), t.event).await;
        }
    }

    st.storage.set_txn_event_id(&auth.user_id, &auth.device_id, &scoped_txn, &eid).await;
    Ok(Json(json!({ "event_id": event_id })))
}

/// Serialize a PDU to a client-event JSON value.
fn pdu_to_client_event_value(event: &Value, event_id: &str) -> Value {
    serde_json::to_value(pdu_to_client_event(event, event_id)).unwrap_or(Value::Null)
}

/// `GET /_matrix/client/v3/rooms/{roomId}/initialSync` (legacy).
pub async fn get_room_initial_sync(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    require_joined_room(&*st.storage, &rid, auth.user_id.as_str()).await?;
    let state: Vec<Value> = st
        .storage
        .get_all_state(&rid)
        .await
        .iter()
        .map(|e| client_event(&e.event, e.event_id.as_str()))
        .collect();
    let page = st.storage.get_events_by_room(&rid, 20, None, Direction::Backward).await;
    let mut chunk: Vec<Value> = page
        .events
        .iter()
        .map(|e| client_event(&e.event, e.event_id.as_str()))
        .collect();
    bundle_aggregations(&*st.storage, &mut chunk, &auth.user_id).await;
    Ok(Json(json!({
        "room_id": room_id,
        "state": state,
        "messages": { "chunk": chunk, "start": page.end.map(|e| e.to_string()).unwrap_or_else(|| "0".into()), "end": "0" },
        "membership": "join",
    })))
}

/// `GET /_matrix/client/v3/rooms/{roomId}/state`.
pub async fn get_all_state(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
) -> MatrixResult<Json<Value>> {
    let room_id: RoomId = room_id.into();
    let read = require_can_read_room(&*st.storage, &room_id, auth.user_id.as_str()).await?;
    let events: Vec<Value> = if let Some(pos) = read.leave_pos {
        // Departed reader: state as of their leave point (SPEC-216).
        state_as_of(&*st.storage, &room_id, pos)
            .await
            .into_values()
            .map(|(ev, id)| client_event(&ev, id.as_str()))
            .collect()
    } else {
        st.storage
            .get_all_state(&room_id)
            .await
            .iter()
            .map(|er| client_event(&er.event, er.event_id.as_str()))
            .collect()
    };
    Ok(Json(Value::Array(events)))
}

/// `GET /_matrix/client/v3/rooms/{roomId}/messages`.
pub async fn get_messages(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let room_id: RoomId = room_id.into();
    let read = require_can_read_room(&*st.storage, &room_id, auth.user_id.as_str()).await?;

    let forward = params.get("dir").map(String::as_str) == Some("f");
    let direction = if forward { Direction::Forward } else { Direction::Backward };
    let limit: usize = params
        .get("limit")
        .and_then(|l| l.parse().ok())
        .unwrap_or(10);
    let from: Option<i64> = params.get("from").and_then(|f| f.parse().ok());

    // Departed reader (SPEC-216): timeline clamped to the leave point.
    let (chunk, end): (Vec<Value>, Option<i64>) = if let Some(pos) = read.leave_pos {
        let mut clamped = events_up_to(&*st.storage, &room_id, pos).await;
        if forward {
            let from_pos = from.unwrap_or(0);
            clamped.retain(|e| e.stream_pos > from_pos);
        } else {
            let from_pos = from.unwrap_or(i64::MAX);
            clamped.retain(|e| e.stream_pos < from_pos);
            clamped.reverse();
        }
        let end = clamped.get(limit.saturating_sub(1)).or_else(|| clamped.last()).map(|e| e.stream_pos);
        let chunk = clamped
            .into_iter()
            .take(limit)
            .map(|e| client_event(&e.event, e.event_id.as_str()))
            .collect();
        (chunk, end)
    } else {
        let page = st.storage.get_events_by_room(&room_id, limit, from, direction).await;
        let chunk = page
            .events
            .iter()
            .map(|er| client_event(&er.event, er.event_id.as_str()))
            .collect();
        (chunk, page.end)
    };

    let start = from.map(|f| f.to_string()).unwrap_or_else(|| "0".to_string());
    Ok(Json(json!({
        "chunk": chunk,
        "start": start,
        "end": end.map(|e| e.to_string()),
    })))
}
