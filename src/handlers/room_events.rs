//! Send / state / messages handlers — port of strix `handlers/room-events.ts`
//! (local path). `putSendEvent` plus `get_all_state` / `get_messages` reads.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::response::Json;
use serde_json::{json, Value};

use super::client_event;
use crate::errors::{bad_json, forbidden, invalid_param, not_found, MatrixError, MatrixResult};
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

/// Per-event history-visibility check (strix `requireHistoryVisibleOr404`): under
/// `joined`/`invited` visibility, an event sent before the requester's join/invite
/// is hidden. Returns false when the event is NOT visible to the user.
async fn history_visible_to(st: &AppState, room_id: &RoomId, event_id: &str, user_id: &str) -> bool {
    let Some(room) = st.storage.get_room(room_id).await else { return false };
    let vis = room
        .state_events
        .get("m.room.history_visibility\u{1f}")
        .and_then(|e| e.get("content"))
        .and_then(|c| c.get("history_visibility"))
        .and_then(Value::as_str)
        .unwrap_or("shared")
        .to_string();
    if vis != "joined" && vis != "invited" {
        return true;
    }
    let all = st.storage.get_events_by_room_since(room_id, 0, 1_000_000).await;
    let mut membership: Option<String> = None;
    let mut active = "shared".to_string();
    for e in &all.events {
        let ev = &e.event;
        if ev.get("type").and_then(Value::as_str) == Some("m.room.history_visibility")
            && ev.get("state_key").and_then(Value::as_str) == Some("")
        {
            if let Some(v) = ev.get("content").and_then(|c| c.get("history_visibility")).and_then(Value::as_str) {
                active = v.to_string();
            }
        }
        if e.event_id.as_str() == event_id {
            if active == "joined" && membership.as_deref() != Some("join") {
                return false;
            }
            if active == "invited" && membership.as_deref() != Some("join") && membership.as_deref() != Some("invite") {
                return false;
            }
            return true;
        }
        if ev.get("type").and_then(Value::as_str) == Some("m.room.member")
            && ev.get("state_key").and_then(Value::as_str) == Some(user_id)
        {
            if let Some(m) = ev.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) {
                membership = Some(m.to_string());
            }
        }
    }
    true // event not in timeline → let the caller's lookup decide
}

/// An event's DAG depth (for topological ordering).
fn event_depth(event: &Value) -> i64 {
    event.get("depth").and_then(Value::as_i64).unwrap_or(0)
}

/// Synapse-style topological pagination token `t<depth>-<stream>` — stable as
/// backfill adds earlier events (strix `topoToken`).
fn topo_token(depth: i64, stream: i64) -> String {
    format!("t{depth}-{stream}")
}

/// Parse a `t<depth>-<stream>` token into `(depth, stream)`.
fn parse_topo_token(s: &str) -> Option<(i64, i64)> {
    let rest = s.strip_prefix('t')?;
    let (d, st) = rest.split_once('-')?;
    Some((d.parse().ok()?, st.parse().ok()?))
}

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
    // Propagate/push while borrowing the event (no storage dependency).
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

    // Index relations AFTER the event is committed: store_relation reads the
    // event's sender/type/stream position from storage, so indexing before the
    // commit would silently drop the relation (empty /relations + /threads).
    if let Some(stored) = st.storage.get_event(&eid).await {
        index_relation(&*st.storage, &stored.event, &eid).await;
    }

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
    // Spec caps state_key and type at 255 bytes; reject oversized ones so we never
    // build/federate an invalid event (TestOutboundFederationEventSizeGetMissingEvents).
    if state_key.len() > 255 {
        return Err(MatrixError::new("M_BAD_JSON", "State key too long", 400));
    }
    if event_type.len() > 255 {
        return Err(MatrixError::new("M_BAD_JSON", "Event type too long", 400));
    }
    let rid = RoomId::from(room_id.as_str());
    let room = require_joined_room(&*st.storage, &rid, auth.user_id.as_str()).await?;

    // m.room.canonical_alias: every alias (primary + alt_aliases) must be
    // well-formed (else M_INVALID_PARAM) and resolve to this room (else
    // M_BAD_ALIAS) — TestRoomCanonicalAlias.
    if event_type == "m.room.canonical_alias" {
        let mut candidates: Vec<String> = Vec::new();
        if let Some(a) = content.get("alias").and_then(Value::as_str) {
            candidates.push(a.to_string());
        }
        if let Some(alts) = content.get("alt_aliases").and_then(Value::as_array) {
            candidates.extend(alts.iter().filter_map(|a| a.as_str().map(String::from)));
        }
        for c in candidates {
            if !c.starts_with('#') || !c.contains(':') {
                return Err(invalid_param(format!("Invalid alias: {c}")));
            }
            let resolves = st
                .storage
                .get_room_by_alias(&crate::types::identifiers::RoomAlias::from(c.as_str()))
                .await
                .map(|r| r.room_id.as_str() == room_id)
                .unwrap_or(false);
            if !resolves {
                return Err(MatrixError::new("M_BAD_ALIAS", format!("Alias {c} does not point to this room"), 400));
            }
        }
    }

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

/// `GET /_matrix/client/v1/rooms/{roomId}/timestamp_to_event?ts=<ms>&dir=<f|b>`.
/// Returns the event closest to `ts` in the given direction (MSC3030 jump-to-date,
/// local resolution). `dir=f` picks the earliest event at/after `ts`; `dir=b` the
/// latest at/before.
pub async fn get_timestamp_to_event(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    require_joined_room(&*st.storage, &rid, auth.user_id.as_str()).await?;

    let ts: i64 = params
        .get("ts")
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| bad_json("Missing or invalid 'ts'"))?;
    let forward = match params.get("dir").map(String::as_str) {
        Some("f") => true,
        Some("b") => false,
        _ => return Err(bad_json("'dir' must be 'f' or 'b'")),
    };

    let all = st.storage.get_events_by_room_since(&rid, 0, 1_000_000).await;
    let mut best: Option<(String, i64)> = None;
    for e in &all.events {
        let ets = e.event.get("origin_server_ts").and_then(Value::as_i64).unwrap_or(0);
        let candidate = if forward { ets >= ts } else { ets <= ts };
        if !candidate {
            continue;
        }
        let better = match &best {
            None => true,
            Some((_, bts)) => {
                if forward {
                    ets < *bts
                } else {
                    ets > *bts
                }
            }
        };
        if better {
            best = Some((e.event_id.as_str().to_string(), ets));
        }
    }
    match best {
        Some((event_id, ets)) => Ok(Json(json!({ "event_id": event_id, "origin_server_ts": ets }))),
        None => Err(not_found("Unable to find event from timestamp in direction")),
    }
}

/// `GET /_matrix/client/v3/rooms/{roomId}/event/{eventId}`.
pub async fn get_event(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((room_id, event_id)): Path<(String, String)>,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    // A user who can't read the room gets 404 here (not 403) — a single-event
    // fetch must not reveal existence (TestFetchEventNonWorldReadable).
    require_can_read_room(&*st.storage, &rid, auth.user_id.as_str())
        .await
        .map_err(|_| not_found("Event not found"))?;
    // Per-event history-visibility: under joined/invited, events from before the
    // requester's join/invite are hidden as 404 (TestFetchHistoricalJoinedEventDenied).
    if !history_visible_to(&st, &rid, &event_id, auth.user_id.as_str()).await {
        return Err(not_found("Event not found"));
    }
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
    // `?at=<sync token>`: return membership as of that stream position. A departed
    // reader is always clamped to their leave point (SPEC-216), which takes
    // precedence over a client-supplied `at`.
    let at_pos: Option<i64> = params.get("at").and_then(|s| s.parse().ok());

    // Member events: as-of-leave for departed readers, as-of-`at` when requested,
    // else current.
    let members: Vec<(Value, String)> = if let Some(pos) = read.leave_pos.or(at_pos) {
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
    // /messages on a room the server doesn't know returns 403 (a client must not
    // be able to distinguish a non-existent room from one it can't see) —
    // TestFetchMessagesFromNonExistentRoom.
    if st.storage.get_room(&room_id).await.is_none() {
        return Err(forbidden("You are not a member of the room and weren't previously"));
    }
    let read = require_can_read_room(&*st.storage, &room_id, auth.user_id.as_str()).await?;

    let forward = params.get("dir").map(String::as_str) == Some("f");
    let limit: usize = params
        .get("limit")
        .and_then(|l| l.parse().ok())
        .unwrap_or(10);
    let from_str = params.get("from").cloned();
    // Token kinds: `t<depth>-<stream>` topological (stable across backfill), else a
    // plain stream position (also a /sync prev_batch).
    let topo_from = from_str.as_deref().and_then(parse_topo_token);
    let from: Option<i64> = from_str
        .as_deref()
        .filter(|_| topo_from.is_none())
        .and_then(|s| s.parse().ok());
    // The /messages filter is a RoomEventFilter directly; apply it to the
    // timeline events (TestRoomImageRoundtrip filters by type).
    let tl_filter: Option<crate::types::filters::RoomEventFilter> =
        params.get("filter").and_then(|f| serde_json::from_str(f).ok());
    // MSC3874: filter by relation type (org.matrix.msc3874.rel_types /
    // .not_rel_types) — not part of the standard RoomEventFilter.
    let filter_json: Option<Value> = params.get("filter").and_then(|f| serde_json::from_str(f).ok());
    let rel_types: Option<Vec<String>> = filter_json.as_ref().and_then(|f| {
        f.get("org.matrix.msc3874.rel_types").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
    });
    let not_rel_types: Option<Vec<String>> = filter_json.as_ref().and_then(|f| {
        f.get("org.matrix.msc3874.not_rel_types").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
    });
    let passes = |ev: &Value| -> bool {
        if !crate::event_filter::matches_room_event_filter(ev, tl_filter.as_ref()) {
            return false;
        }
        let rt = ev.get("content").and_then(|c| c.get("m.relates_to")).and_then(|r| r.get("rel_type")).and_then(Value::as_str);
        if let Some(want) = &rel_types {
            if !rt.map(|rt| want.iter().any(|w| w == rt)).unwrap_or(false) {
                return false;
            }
        }
        if let Some(not) = &not_rel_types {
            if rt.map(|rt| not.iter().any(|w| w == rt)).unwrap_or(false) {
                return false;
            }
        }
        true
    };

    // Decide whether to serve a DAG (topological) backward view: continuing a
    // topo token, or paginating back into a room with gappy/out-of-order federated
    // history. Departed readers stay on the clamped local path.
    let mut use_topo = false;
    if !forward && read.leave_pos.is_none() {
        if topo_from.is_some() {
            use_topo = true;
        } else if st.federation_client.is_some() {
            let remote = st
                .storage
                .get_servers_in_room(&room_id)
                .await
                .into_iter()
                .any(|s| s.as_str() != st.server_name.as_ref() && !s.as_str().is_empty());
            if remote {
                let all = st.storage.get_events_by_room_since(&room_id, 0, 1_000_000).await;
                let known: std::collections::HashSet<&str> =
                    all.events.iter().map(|e| e.event_id.as_str()).collect();
                let idx: HashMap<&str, usize> =
                    all.events.iter().enumerate().map(|(i, e)| (e.event_id.as_str(), i)).collect();
                let has_gap = all.events.iter().any(|e| {
                    e.event.get("prev_events").and_then(Value::as_array).into_iter().flatten().any(|p| {
                        p.as_str().map(|p| !known.contains(p)).unwrap_or(false)
                    })
                });
                let out_of_order = all.events.iter().enumerate().any(|(i, e)| {
                    e.event.get("prev_events").and_then(Value::as_array).into_iter().flatten().any(|p| {
                        p.as_str().and_then(|p| idx.get(p)).map(|pi| *pi > i).unwrap_or(false)
                    })
                });
                use_topo = has_gap || out_of_order;
            }
        }
    }

    let (chunk, end): (Vec<Value>, Option<String>) = if use_topo {
        // Backfill the gap (no-op when fully held), then serve a depth-ordered view
        // with topological pagination tokens.
        if let Some(fed) = &st.federation_client {
            let rv = st.storage.get_room(&room_id).await.map(|r| r.room_version);
            crate::federation::outbound::backfill_missing_history(
                &*st.storage, fed, &st.server_name, &room_id, rv.as_deref(),
            )
            .await;
        }
        let all = st.storage.get_events_by_room_since(&room_id, 0, 1_000_000).await;
        let mut ordered: Vec<&crate::storage::interface::StreamEventRecord> = all
            .events
            .iter()
            .filter(|e| passes(&e.event))
            .collect();
        ordered.sort_by(|a, b| (event_depth(&a.event), a.stream_pos).cmp(&(event_depth(&b.event), b.stream_pos)));

        let boundary: Option<(i64, i64)> = topo_from.or_else(|| {
            from.and_then(|f| ordered.iter().find(|e| e.stream_pos == f).map(|e| (event_depth(&e.event), e.stream_pos)))
        });
        let candidates: Vec<&&crate::storage::interface::StreamEventRecord> = match boundary {
            Some((bd, bs)) => ordered.iter().filter(|e| (event_depth(&e.event), e.stream_pos) < (bd, bs)).collect(),
            None => ordered.iter().collect(),
        };
        let start_i = candidates.len().saturating_sub(limit);
        let page_asc = &candidates[start_i..];
        let more = candidates.len() > page_asc.len();
        let end = page_asc.first().filter(|_| more).map(|e| topo_token(event_depth(&e.event), e.stream_pos));
        let chunk = page_asc.iter().rev().map(|e| client_event(&e.event, e.event_id.as_str())).collect();
        (chunk, end)
    } else if let Some(pos) = read.leave_pos {
        // Departed reader (SPEC-216): timeline clamped to the leave point.
        let mut clamped = events_up_to(&*st.storage, &room_id, pos).await;
        clamped.retain(|e| passes(&e.event));
        if forward {
            let from_pos = from.unwrap_or(0);
            clamped.retain(|e| e.stream_pos > from_pos);
        } else {
            let from_pos = from.unwrap_or(i64::MAX);
            clamped.retain(|e| e.stream_pos < from_pos);
            clamped.reverse();
        }
        let end = clamped.get(limit.saturating_sub(1)).or_else(|| clamped.last()).map(|e| e.stream_pos.to_string());
        let chunk = clamped.into_iter().take(limit).map(|e| client_event(&e.event, e.event_id.as_str())).collect();
        (chunk, end)
    } else {
        // Normal pagination: select by stream-position bound but ORDER
        // topologically (depth, then stream) so out-of-DAG-order arrivals scroll
        // back into their DAG position (TestNetworkPartitionOrdering).
        let all = st.storage.get_events_by_room_since(&room_id, 0, 1_000_000).await;
        let mut ordered: Vec<&crate::storage::interface::StreamEventRecord> = all
            .events
            .iter()
            .filter(|e| passes(&e.event))
            .collect();
        ordered.sort_by(|a, b| (event_depth(&a.event), a.stream_pos).cmp(&(event_depth(&b.event), b.stream_pos)));
        if forward {
            let lower = from.unwrap_or(i64::MIN);
            let page: Vec<_> = ordered.iter().filter(|e| e.stream_pos > lower).take(limit).collect();
            let end = page.last().map(|e| e.stream_pos.to_string());
            (page.iter().map(|e| client_event(&e.event, e.event_id.as_str())).collect(), end)
        } else {
            let upper = from.unwrap_or(i64::MAX);
            let eligible: Vec<_> = ordered.iter().filter(|e| e.stream_pos <= upper).collect();
            let start_i = eligible.len().saturating_sub(limit);
            let page = &eligible[start_i..];
            let end = page.first().map(|e| (e.stream_pos - 1).to_string());
            (page.iter().rev().map(|e| client_event(&e.event, e.event_id.as_str())).collect(), end)
        }
    };

    let start = from_str.clone().unwrap_or_else(|| "0".to_string());

    // Lazy-loading (?filter with lazy_load_members): include a `state` block with
    // the m.room.member event for each distinct sender in the chunk
    // (TestRoomMessagesLazyLoading).
    let lazy = params
        .get("filter")
        .and_then(|f| serde_json::from_str::<Value>(f).ok())
        .and_then(|f| f.get("lazy_load_members").and_then(Value::as_bool))
        .unwrap_or(false);
    let mut body = serde_json::Map::new();
    body.insert("chunk".to_string(), Value::Array(chunk.clone()));
    body.insert("start".to_string(), json!(start));
    body.insert("end".to_string(), json!(end));
    if lazy {
        let mut seen = std::collections::HashSet::new();
        let mut state = Vec::new();
        for ev in &chunk {
            if let Some(sender) = ev.get("sender").and_then(Value::as_str) {
                if seen.insert(sender.to_string()) {
                    if let Some(rec) = st.storage.get_state_event(&room_id, "m.room.member", sender).await {
                        state.push(client_event(&rec.event, rec.event_id.as_str()));
                    }
                }
            }
        }
        body.insert("state".to_string(), Value::Array(state));
    }
    Ok(Json(Value::Object(body)))
}
