//! `/sync` — port of strix `handlers/sync.ts`.
//!
//! Supports initial and incremental sync with long-poll. Fills join rooms
//! (timeline, state, per-room account data, ephemeral typing/receipts), invite
//! rooms (stripped invite_state), leave rooms, and top-level account data.
//! Sliding sync, gappy-state deltas, and E2EE device sections (Phase 3) remain
//! simplified.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::response::Json;
use serde_json::{json, Map, Value};

use super::client_event_no_room;
use crate::errors::MatrixResult;
use crate::push_rules::{evaluate_push_rules, get_or_init_rules, EvaluationContext};
use crate::server::{AppState, AuthCtx};
use crate::storage::Direction;
use crate::types::identifiers::RoomId;

const INITIAL_TIMELINE_LIMIT: usize = 20;
const INCREMENTAL_TIMELINE_LIMIT: usize = 50;

/// `GET /_matrix/client/v3/sync`.
pub async fn sync(
    State(st): State<AppState>,
    auth: AuthCtx,
    Query(params): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let since: Option<i64> = params.get("since").and_then(|s| s.parse().ok());
    let timeout: u64 = params.get("timeout").and_then(|s| s.parse().ok()).unwrap_or(0);
    let is_initial = since.is_none();
    let since_pos = since.unwrap_or(0);

    if !is_initial && timeout > 0 && st.storage.get_stream_position().await <= since_pos {
        st.storage.wait_for_events(since_pos, timeout).await;
    }

    let next_batch = st.storage.get_stream_position().await;
    let memberships = st.storage.get_rooms_for_user_with_membership(&auth.user_id).await;

    // Push rules + display name for unread-count evaluation (fetched once).
    let rules = get_or_init_rules(&*st.storage, &auth.user_id).await;
    let display_name = st.storage.get_profile(&auth.user_id).await.and_then(|p| p.displayname);

    let mut join = Map::new();
    let mut invite = Map::new();
    let mut leave = Map::new();

    for m in memberships {
        let room_id = m.room_id;
        match m.membership.as_str() {
            "join" => {
                join.insert(
                    room_id.to_string(),
                    build_join_room(&st, &auth, &room_id, is_initial, since_pos, &rules, display_name.as_deref()).await,
                );
            }
            "invite" => {
                let stripped = st.storage.get_stripped_state(&room_id).await;
                invite.insert(
                    room_id.to_string(),
                    json!({ "invite_state": { "events": stripped } }),
                );
            }
            // Report the leave with minimal state on initial sync so the client
            // can drop the room — unless the user has forgotten it, in which case
            // it must not appear in sync at all.
            "leave" | "ban" if is_initial => {
                let forgotten = st
                    .storage
                    .get_room_account_data(&auth.user_id, &room_id, "m.internal.forgotten")
                    .await
                    .and_then(|d| d.get("forgotten").and_then(|v| v.as_bool()))
                    == Some(true);
                if !forgotten {
                    let state: Vec<Value> = st
                        .storage
                        .get_all_state(&room_id)
                        .await
                        .iter()
                        .map(|er| client_event_no_room(&er.event, er.event_id.as_str()))
                        .collect();
                    leave.insert(
                        room_id.to_string(),
                        json!({
                            "timeline": { "events": [], "limited": false, "prev_batch": since_pos.to_string() },
                            "state": { "events": state },
                            "account_data": { "events": [] },
                        }),
                    );
                }
            }
            _ => {}
        }
    }

    // Top-level (global) account data.
    let global_ad: Vec<Value> = st
        .storage
        .get_all_global_account_data(&auth.user_id)
        .await
        .into_iter()
        .map(|e| json!({ "type": e.data_type, "content": Value::Object(e.content) }))
        .collect();

    // To-device messages for this device (drained after reading).
    let to_device: Vec<Value> = st
        .storage
        .get_to_device_messages(&auth.user_id, &auth.device_id)
        .await
        .into_iter()
        .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
        .collect();
    if !to_device.is_empty() {
        st.storage
            .clear_to_device_messages(&auth.user_id, &auth.device_id)
            .await;
    }

    // One-time-key counts for this device.
    let otk_counts = st
        .storage
        .get_one_time_key_counts(&auth.user_id, &auth.device_id)
        .await;

    // device_lists.changed: on incremental sync, users whose device list changed
    // in (since, next_batch] who share a joined room with us.
    let device_changed: Vec<String> = if is_initial {
        Vec::new()
    } else {
        let changed: std::collections::HashSet<String> = st
            .storage
            .get_changed_device_users(since_pos, next_batch)
            .await
            .into_iter()
            .map(|u| u.as_str().to_string())
            .collect();
        if changed.is_empty() {
            Vec::new()
        } else {
            let mut shared = std::collections::HashSet::new();
            for room_id in join.keys() {
                for m in st.storage.get_member_events(&RoomId::from(room_id.as_str())).await {
                    if m.event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("join") {
                        if let Some(sk) = m.event.get("state_key").and_then(Value::as_str) {
                            if changed.contains(sk) && sk != auth.user_id.as_str() {
                                shared.insert(sk.to_string());
                            }
                        }
                    }
                }
            }
            shared.into_iter().collect()
        }
    };

    Ok(Json(json!({
        "next_batch": next_batch.to_string(),
        "rooms": {
            "join": Value::Object(join),
            "invite": Value::Object(invite),
            "leave": Value::Object(leave),
            "knock": {},
        },
        "account_data": { "events": global_ad },
        "presence": { "events": [] },
        "device_lists": { "changed": device_changed, "left": [] },
        "device_one_time_keys_count": otk_counts,
        "to_device": { "events": to_device },
    })))
}

/// Build a single joined room's sync payload.
#[allow(clippy::too_many_arguments)]
async fn build_join_room(
    st: &AppState,
    auth: &AuthCtx,
    room_id: &RoomId,
    is_initial: bool,
    since_pos: i64,
    rules: &Value,
    display_name: Option<&str>,
) -> Value {
    let (timeline_events, limited): (Vec<Value>, bool) = if is_initial {
        let page = st
            .storage
            .get_events_by_room(room_id, INITIAL_TIMELINE_LIMIT, Some(0), Direction::Forward)
            .await;
        (
            page.events
                .iter()
                .map(|er| client_event_no_room(&er.event, er.event_id.as_str()))
                .collect(),
            false,
        )
    } else {
        let s = st
            .storage
            .get_events_by_room_since(room_id, since_pos, INCREMENTAL_TIMELINE_LIMIT)
            .await;
        (
            s.events
                .iter()
                .map(|er| client_event_no_room(&er.event, er.event_id.as_str()))
                .collect(),
            s.limited,
        )
    };

    // Full current state on initial sync; deltas are deferred.
    let state_events: Vec<Value> = if is_initial {
        st.storage
            .get_all_state(room_id)
            .await
            .iter()
            .map(|er| client_event_no_room(&er.event, er.event_id.as_str()))
            .collect()
    } else {
        Vec::new()
    };

    // Per-room account data.
    let room_ad: Vec<Value> = st
        .storage
        .get_all_room_account_data(&auth.user_id, room_id)
        .await
        .into_iter()
        .map(|e| json!({ "type": e.data_type, "content": Value::Object(e.content) }))
        .collect();

    let (notification_count, highlight_count) =
        unread_counts(st, auth, room_id, rules, display_name).await;

    json!({
        "timeline": {
            "events": timeline_events,
            "limited": limited,
            "prev_batch": since_pos.to_string(),
        },
        "state": { "events": state_events },
        "account_data": { "events": room_ad },
        "ephemeral": { "events": build_ephemeral(st, room_id).await },
        "unread_notifications": {
            "notification_count": notification_count,
            "highlight_count": highlight_count,
        },
    })
}

/// Count notifying/highlighting events after the user's read receipt in a room
/// (a bounded scan of recent timeline events; strix computes the same via push
/// rules over post-read events).
async fn unread_counts(
    st: &AppState,
    auth: &AuthCtx,
    room_id: &RoomId,
    rules: &Value,
    display_name: Option<&str>,
) -> (i64, i64) {
    // The user's read-receipt event id, if any (public or private).
    let read_event: Option<String> = st
        .storage
        .get_receipts(room_id)
        .await
        .into_iter()
        .find(|r| {
            r.user_id.as_str() == auth.user_id.as_str()
                && (r.receipt_type == "m.read" || r.receipt_type == "m.read.private")
        })
        .map(|r| r.event_id.as_str().to_string());

    let member_count = st
        .storage
        .get_member_events(room_id)
        .await
        .iter()
        .filter(|m| m.event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("join"))
        .count() as i64;
    let pl_content = st
        .storage
        .get_state_event(room_id, "m.room.power_levels", "")
        .await
        .and_then(|e| e.event.get("content").cloned());

    // Forward scan of recent events; count those strictly after the read receipt.
    let page = st.storage.get_events_by_room(room_id, 1000, Some(0), Direction::Forward).await;
    let mut seen_read = read_event.is_none();
    let mut notifications = 0i64;
    let mut highlights = 0i64;
    for er in page.events {
        if !seen_read {
            if er.event_id.as_str() == read_event.as_deref().unwrap_or("") {
                seen_read = true;
            }
            continue;
        }
        let sender = er.event.get("sender").and_then(Value::as_str).unwrap_or("");
        if sender == auth.user_id.as_str() {
            continue;
        }
        let sender_pl = pl_content
            .as_ref()
            .and_then(|pl| pl.get("users").and_then(|u| u.get(sender)).and_then(Value::as_i64))
            .or_else(|| pl_content.as_ref().and_then(|pl| pl.get("users_default").and_then(Value::as_i64)))
            .unwrap_or(0);
        let result = evaluate_push_rules(
            rules,
            &EvaluationContext {
                event: &er.event,
                user_id: auth.user_id.as_str(),
                display_name,
                member_count,
                power_levels: pl_content.as_ref(),
                sender_power_level: sender_pl,
            },
        );
        if result.notify {
            notifications += 1;
        }
        if result.highlight {
            highlights += 1;
        }
    }
    (notifications, highlights)
}

/// Build the ephemeral EDU list (typing + receipts) for a room.
async fn build_ephemeral(st: &AppState, room_id: &RoomId) -> Vec<Value> {
    let mut events = Vec::new();

    let typing: Vec<String> = st
        .storage
        .get_typing_users(room_id)
        .await
        .iter()
        .map(|u| u.as_str().to_string())
        .collect();
    if !typing.is_empty() {
        events.push(json!({ "type": "m.typing", "content": { "user_ids": typing } }));
    }

    // m.receipt: { <event_id>: { <receipt_type>: { <user_id>: { ts, thread_id? } } } }
    let receipts = st.storage.get_receipts(room_id).await;
    if !receipts.is_empty() {
        let mut by_event: Map<String, Value> = Map::new();
        for r in receipts {
            let mut data = Map::new();
            data.insert("ts".to_string(), json!(r.ts));
            if let Some(tid) = &r.thread_id {
                data.insert("thread_id".to_string(), json!(tid));
            }
            let by_type = by_event
                .entry(r.event_id.as_str().to_string())
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .unwrap();
            let by_user = by_type
                .entry(r.receipt_type.clone())
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .unwrap();
            by_user.insert(r.user_id.as_str().to_string(), Value::Object(data));
        }
        events.push(json!({ "type": "m.receipt", "content": Value::Object(by_event) }));
    }

    events
}
