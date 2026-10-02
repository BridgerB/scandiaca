//! Sliding Sync (MSC3575 / MSC4186) — port of strix `handlers/sliding-sync.ts`.
//!
//! A simplified but functional implementation: `pos` is the stream position (no
//! persistent per-connection state), lists are recomputed each call from the
//! user's joined rooms with range windowing + `by_recency`/`by_name` sort +
//! is_dm/room_types filters, plus room subscriptions and the e2ee/to_device/
//! account_data extensions. The MSC4308 thread-subscriptions extension is not
//! ported (returns empty).

use axum::extract::State;
use axum::response::Json;
use serde_json::{json, Map, Value};

use crate::handlers::client_event;
use crate::push_rules::{evaluate_push_rules, get_or_init_rules, EvaluationContext};
use crate::server::{AppState, AuthCtx};
use crate::storage::Direction;
use crate::types::identifiers::{RoomId, UserId};

const DEFAULT_TIMELINE_LIMIT: usize = 20;
const MAX_TIMEOUT: u64 = 30_000;

/// Compute a human-readable room name (m.room.name → canonical_alias → none).
async fn compute_room_name(st: &AppState, room_id: &RoomId) -> Option<String> {
    if let Some(e) = st.storage.get_state_event(room_id, "m.room.name", "").await {
        if let Some(name) = e.event.get("content").and_then(|c| c.get("name")).and_then(Value::as_str) {
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    if let Some(e) = st.storage.get_state_event(room_id, "m.room.canonical_alias", "").await {
        if let Some(alias) = e.event.get("content").and_then(|c| c.get("alias")).and_then(Value::as_str) {
            return Some(alias.to_string());
        }
    }
    None
}

async fn room_latest_timestamp(st: &AppState, room_id: &RoomId) -> i64 {
    let page = st.storage.get_events_by_room(room_id, 1, None, Direction::Backward).await;
    page.events
        .first()
        .and_then(|e| e.event.get("origin_server_ts").and_then(Value::as_i64))
        .unwrap_or(0)
}

async fn get_dm_room_ids(st: &AppState, user_id: &UserId) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    if let Some(direct) = st.storage.get_global_account_data(user_id, "m.direct").await {
        for v in direct.values() {
            if let Some(arr) = v.as_array() {
                for rid in arr {
                    if let Some(s) = rid.as_str() {
                        out.insert(s.to_string());
                    }
                }
            }
        }
    }
    out
}

async fn get_room_type(st: &AppState, room_id: &RoomId) -> Option<String> {
    st.storage
        .get_state_event(room_id, "m.room.create", "")
        .await
        .and_then(|e| e.event.get("content").and_then(|c| c.get("type")).and_then(Value::as_str).map(String::from))
}

/// Apply a list's is_dm/room_types/not_room_types filters.
async fn filter_rooms(
    st: &AppState,
    rooms: &[String],
    filters: Option<&Value>,
    dm_rooms: &std::collections::HashSet<String>,
) -> Vec<String> {
    let Some(filters) = filters else { return rooms.to_vec() };
    let mut out = Vec::new();
    for room_id in rooms {
        if let Some(is_dm) = filters.get("is_dm").and_then(Value::as_bool) {
            if is_dm != dm_rooms.contains(room_id) {
                continue;
            }
        }
        let rid = RoomId::from(room_id.as_str());
        if let Some(types) = filters.get("room_types").and_then(Value::as_array) {
            let rt = get_room_type(st, &rid).await;
            let matches = types.iter().any(|t| match t.as_str() {
                Some(s) => Some(s) == rt.as_deref(),
                None => t.is_null() && rt.is_none(),
            });
            if !matches {
                continue;
            }
        }
        if let Some(types) = filters.get("not_room_types").and_then(Value::as_array) {
            let rt = get_room_type(st, &rid).await;
            let excluded = types.iter().any(|t| match t.as_str() {
                Some(s) => Some(s) == rt.as_deref(),
                None => t.is_null() && rt.is_none(),
            });
            if excluded {
                continue;
            }
        }
        out.push(room_id.clone());
    }
    out
}

/// Build the `required_state` client events for a room from `[type, state_key]`
/// pairs, honoring `*` wildcards.
async fn build_required_state(st: &AppState, room_id: &RoomId, required: Option<&Value>) -> Vec<Value> {
    let Some(pairs) = required.and_then(Value::as_array) else { return Vec::new() };
    if pairs.is_empty() {
        return Vec::new();
    }
    let mut events = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for pair in pairs {
        let Some(arr) = pair.as_array() else { continue };
        let etype = arr.first().and_then(Value::as_str).unwrap_or("");
        let skey = arr.get(1).and_then(Value::as_str).unwrap_or("");
        if etype == "*" && skey == "*" {
            for s in st.storage.get_all_state(room_id).await {
                let t = s.event.get("type").and_then(Value::as_str).unwrap_or("");
                let sk = s.event.get("state_key").and_then(Value::as_str).unwrap_or("");
                let key = format!("{t}\u{1f}{sk}");
                if seen.insert(key) {
                    events.push(client_event(&s.event, s.event_id.as_str()));
                }
            }
        } else if skey == "*" {
            for s in st.storage.get_all_state(room_id).await {
                if s.event.get("type").and_then(Value::as_str) == Some(etype) {
                    let sk = s.event.get("state_key").and_then(Value::as_str).unwrap_or("");
                    let key = format!("{etype}\u{1f}{sk}");
                    if seen.insert(key) {
                        events.push(client_event(&s.event, s.event_id.as_str()));
                    }
                }
            }
        } else {
            let key = format!("{etype}\u{1f}{skey}");
            if !seen.insert(key) {
                continue;
            }
            if let Some(s) = st.storage.get_state_event(room_id, etype, skey).await {
                events.push(client_event(&s.event, s.event_id.as_str()));
            }
        }
    }
    events
}

/// Notification/highlight counts over the room's recent events (strix
/// `computeSlidingSyncNotifications`: scan the last 20, evaluate push rules).
async fn sliding_notifications(st: &AppState, room_id: &RoomId, user_id: &UserId) -> (i64, i64) {
    let rules = get_or_init_rules(&*st.storage, user_id).await;
    let display_name = st.storage.get_profile(user_id).await.and_then(|p| p.displayname);
    let members = st.storage.get_member_events(room_id).await;
    let member_count = members
        .iter()
        .filter(|m| m.event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("join"))
        .count() as i64;
    let pl_content = st
        .storage
        .get_state_event(room_id, "m.room.power_levels", "")
        .await
        .and_then(|e| e.event.get("content").cloned());

    let page = st.storage.get_events_by_room(room_id, 20, None, Direction::Backward).await;
    let mut notifications = 0i64;
    let mut highlights = 0i64;
    for er in &page.events {
        let sender = er.event.get("sender").and_then(Value::as_str).unwrap_or("");
        if sender == user_id.as_str() {
            continue;
        }
        let sender_pl = pl_content
            .as_ref()
            .and_then(|pl| pl.get("users").and_then(|u| u.get(sender)).and_then(Value::as_i64))
            .or_else(|| pl_content.as_ref().and_then(|pl| pl.get("users_default").and_then(Value::as_i64)))
            .unwrap_or(0);
        let result = evaluate_push_rules(
            &rules,
            &EvaluationContext {
                event: &er.event,
                user_id: user_id.as_str(),
                display_name: display_name.as_deref(),
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

/// Build one room's response object.
#[allow(clippy::too_many_arguments)]
async fn build_room_data(
    st: &AppState,
    room_id: &RoomId,
    user_id: &UserId,
    required_state: Option<&Value>,
    timeline_limit: usize,
    is_initial: bool,
    since: Option<i64>,
) -> Value {
    let mut room = Map::new();
    if let Some(name) = compute_room_name(st, room_id).await {
        room.insert("name".to_string(), json!(name));
    }
    if let Some(e) = st.storage.get_state_event(room_id, "m.room.avatar", "").await {
        if let Some(url) = e.event.get("content").and_then(|c| c.get("url")).and_then(Value::as_str) {
            room.insert("avatar".to_string(), json!(url));
        }
    }
    if is_initial {
        room.insert("initial".to_string(), json!(true));
        room.insert(
            "required_state".to_string(),
            Value::Array(build_required_state(st, room_id, required_state).await),
        );
    }

    let limit = timeline_limit.min(50);
    if let (Some(since), false) = (since, is_initial) {
        let page = st.storage.get_events_by_room_since(room_id, since, limit).await;
        if page.events.is_empty() {
            // No timeline delta; still return counts below.
        } else {
            let timeline: Vec<Value> =
                page.events.iter().map(|e| client_event(&e.event, e.event_id.as_str())).collect();
            room.insert("timeline".to_string(), Value::Array(timeline));
        }
    } else {
        let page = st.storage.get_events_by_room(room_id, limit, None, Direction::Backward).await;
        let mut evs = page.events.clone();
        evs.reverse();
        let timeline: Vec<Value> =
            evs.iter().map(|e| client_event(&e.event, e.event_id.as_str())).collect();
        room.insert("timeline".to_string(), Value::Array(timeline));
        // Determine if there is more history for prev_batch.
        let total = st.storage.get_events_by_room(room_id, limit + 1, None, Direction::Backward).await;
        if total.events.len() > limit {
            if let Some(end) = page.end {
                room.insert("prev_batch".to_string(), json!(end.to_string()));
            }
        }
    }

    let members = st.storage.get_member_events(room_id).await;
    let joined = members
        .iter()
        .filter(|m| m.event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("join"))
        .count();
    let invited = members
        .iter()
        .filter(|m| m.event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("invite"))
        .count();
    room.insert("joined_count".to_string(), json!(joined));
    room.insert("invited_count".to_string(), json!(invited));

    let (notif, highlight) = sliding_notifications(st, room_id, user_id).await;
    room.insert("notification_count".to_string(), json!(notif));
    room.insert("highlight_count".to_string(), json!(highlight));

    Value::Object(room)
}

/// `POST /_matrix/client/unstable/org.matrix.simplified_msc3575/sync` and
/// `/_matrix/client/v4/sync`.
pub async fn sliding_sync(
    State(st): State<AppState>,
    auth: AuthCtx,
    body: Option<Json<Value>>,
) -> Json<Value> {
    let body = body.map(|Json(v)| v).unwrap_or_else(|| json!({}));
    let user_id = &auth.user_id;

    let pos = body.get("pos").and_then(Value::as_str).and_then(|s| s.parse::<i64>().ok());
    let timeout = body.get("timeout").and_then(Value::as_u64).unwrap_or(0).min(MAX_TIMEOUT);

    if let Some(pos) = pos {
        if timeout > 0 && st.storage.get_stream_position().await <= pos {
            st.storage.wait_for_events(pos, timeout).await;
        }
    }

    let next_batch = st.storage.get_stream_position().await;
    let is_initial = pos.is_none();

    let joined_room_ids: Vec<String> = st
        .storage
        .get_rooms_for_user_with_membership(user_id)
        .await
        .into_iter()
        .filter(|r| r.membership == "join")
        .map(|r| r.room_id.as_str().to_string())
        .collect();

    let dm_rooms = get_dm_room_ids(&st, user_id).await;

    let mut response = Map::new();
    response.insert("pos".to_string(), json!(next_batch.to_string()));

    // room_id → (required_state, timeline_limit)
    let mut rooms_to_include: std::collections::HashMap<String, (Value, usize)> = std::collections::HashMap::new();

    // Lists.
    if let Some(lists) = body.get("lists").and_then(Value::as_object) {
        let mut lists_resp = Map::new();
        for (list_key, list) in lists {
            let filtered = filter_rooms(&st, &joined_room_ids, list.get("filters"), &dm_rooms).await;

            let sort_mode = list
                .get("sort")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(Value::as_str)
                .unwrap_or("by_recency");

            let mut sorted = filtered.clone();
            if sort_mode == "by_name" {
                let mut named: Vec<(String, String)> = Vec::new();
                for r in &sorted {
                    let name = compute_room_name(&st, &RoomId::from(r.as_str())).await.unwrap_or_default();
                    named.push((r.clone(), name));
                }
                named.sort_by(|a, b| a.1.cmp(&b.1));
                sorted = named.into_iter().map(|(r, _)| r).collect();
            } else {
                let mut stamped: Vec<(String, i64)> = Vec::new();
                for r in &sorted {
                    let ts = room_latest_timestamp(&st, &RoomId::from(r.as_str())).await;
                    stamped.push((r.clone(), ts));
                }
                stamped.sort_by_key(|(_, ts)| std::cmp::Reverse(*ts));
                sorted = stamped.into_iter().map(|(r, _)| r).collect();
            }

            let total = sorted.len() as i64;
            let mut ops = Vec::new();
            let required_state = list.get("required_state").cloned().unwrap_or(Value::Null);
            let timeline_limit = list
                .get("timeline_limit")
                .and_then(Value::as_u64)
                .map(|n| n as usize)
                .unwrap_or(DEFAULT_TIMELINE_LIMIT);

            if let Some(ranges) = list.get("ranges").and_then(Value::as_array) {
                for range in ranges {
                    let Some(r) = range.as_array() else { continue };
                    let start = r.first().and_then(Value::as_i64).unwrap_or(0);
                    let end = r.get(1).and_then(Value::as_i64).unwrap_or(0);
                    let clamped_end = end.min(total - 1);
                    let room_ids: Vec<String> = if start > clamped_end || start >= total {
                        Vec::new()
                    } else {
                        sorted[start as usize..=clamped_end as usize].to_vec()
                    };
                    for rid in &room_ids {
                        rooms_to_include
                            .entry(rid.clone())
                            .or_insert_with(|| (required_state.clone(), timeline_limit));
                    }
                    ops.push(json!({ "op": "SYNC", "range": range, "room_ids": room_ids }));
                }
            }

            lists_resp.insert(list_key.clone(), json!({ "count": total, "ops": ops }));
        }
        response.insert("lists".to_string(), Value::Object(lists_resp));
    }

    // Room subscriptions.
    if let Some(subs) = body.get("room_subscriptions").and_then(Value::as_object) {
        for (rid, sub) in subs {
            if joined_room_ids.contains(rid) {
                let required_state = sub.get("required_state").cloned().unwrap_or(Value::Null);
                let timeline_limit = sub
                    .get("timeline_limit")
                    .and_then(Value::as_u64)
                    .map(|n| n as usize)
                    .unwrap_or(DEFAULT_TIMELINE_LIMIT);
                rooms_to_include.insert(rid.clone(), (required_state, timeline_limit));
            }
        }
    }

    // Room data.
    if !rooms_to_include.is_empty() {
        let mut rooms_resp = Map::new();
        for (rid, (required_state, timeline_limit)) in &rooms_to_include {
            let room_id = RoomId::from(rid.as_str());
            let rs = if required_state.is_null() { None } else { Some(required_state) };
            let data = build_room_data(&st, &room_id, user_id, rs, *timeline_limit, is_initial, pos).await;
            rooms_resp.insert(rid.clone(), data);
        }
        response.insert("rooms".to_string(), Value::Object(rooms_resp));
    }

    // Extensions.
    if let Some(ext) = body.get("extensions").and_then(Value::as_object) {
        let mut ext_resp = Map::new();

        if ext.get("e2ee").and_then(|e| e.get("enabled")).and_then(Value::as_bool) == Some(true) {
            let otk = st.storage.get_one_time_key_counts(user_id, &auth.device_id).await;
            let fallback = st.storage.get_fallback_key_types(user_id, &auth.device_id).await;
            ext_resp.insert(
                "e2ee".to_string(),
                json!({
                    "device_one_time_keys_count": otk,
                    "device_unused_fallback_key_types": fallback,
                }),
            );
        }

        if ext.get("to_device").and_then(|e| e.get("enabled")).and_then(Value::as_bool) == Some(true) {
            let events: Vec<Value> = st
                .storage
                .get_to_device_messages(user_id, &auth.device_id)
                .await
                .into_iter()
                .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
                .collect();
            if !events.is_empty() {
                st.storage.clear_to_device_messages(user_id, &auth.device_id).await;
            }
            ext_resp.insert(
                "to_device".to_string(),
                json!({ "next_batch": next_batch.to_string(), "events": events }),
            );
        }

        if ext.get("account_data").and_then(|e| e.get("enabled")).and_then(Value::as_bool) == Some(true) {
            let global: Vec<Value> = st
                .storage
                .get_all_global_account_data(user_id)
                .await
                .into_iter()
                .map(|d| json!({ "type": d.data_type, "content": Value::Object(d.content) }))
                .collect();
            ext_resp.insert("account_data".to_string(), json!({ "global": global }));
        }

        response.insert("extensions".to_string(), Value::Object(ext_resp));
    }

    Json(Value::Object(response))
}
