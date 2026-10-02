//! Space hierarchy (MSC2946) — port of strix `handlers/spaces.ts`
//! (`getSpaceHierarchy`), local rooms only. Remote-room fetch over federation is
//! deferred.

use std::collections::HashMap;
use std::collections::HashSet;

use axum::extract::{Path, Query, State};
use axum::response::Json;
use serde_json::{json, Value};

use crate::errors::{not_found, MatrixResult};
use crate::events::get_membership;
use crate::server::{AppState, AuthCtx};
use crate::types::internal::RoomState;

const MAX_ROOMS: usize = 100;

fn state_content<'a>(room: &'a RoomState, key: &str, field: &str) -> Option<&'a str> {
    room.state_events
        .get(key)
        .and_then(|e| e.get("content"))
        .and_then(|c| c.get(field))
        .and_then(Value::as_str)
}

fn num_joined(room: &RoomState) -> usize {
    room.state_events
        .iter()
        .filter(|(k, v)| {
            k.starts_with("m.room.member\u{1f}")
                && v.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("join")
        })
        .count()
}

fn summary_fields(room: &RoomState, room_id: &str) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert("room_id".into(), json!(room_id));
    m.insert("num_joined_members".into(), json!(num_joined(room)));
    m.insert(
        "world_readable".into(),
        json!(state_content(room, "m.room.history_visibility\u{1f}", "history_visibility") == Some("world_readable")),
    );
    m.insert(
        "guest_can_join".into(),
        json!(state_content(room, "m.room.guest_access\u{1f}", "guest_access") == Some("can_join")),
    );
    for (field, key, sub) in [
        ("name", "m.room.name\u{1f}", "name"),
        ("topic", "m.room.topic\u{1f}", "topic"),
        ("avatar_url", "m.room.avatar\u{1f}", "url"),
        ("canonical_alias", "m.room.canonical_alias\u{1f}", "alias"),
        ("join_rule", "m.room.join_rules\u{1f}", "join_rule"),
        ("room_type", "m.room.create\u{1f}", "type"),
    ] {
        if let Some(v) = state_content(room, key, sub) {
            m.insert(field.into(), json!(v));
        }
    }
    m
}

/// Whether a room is a space (m.room.create `type` == `m.space`). Only spaces'
/// `m.space.child` links are listed/traversed in the hierarchy (MSC2946); a
/// non-space room is a leaf, even if it carries stray child links.
fn is_space(room: &RoomState) -> bool {
    state_content(room, "m.room.create\u{1f}", "type") == Some("m.space")
}

/// The `m.space.child` events (with a `via`) as stripped state, ordered per
/// MSC1772/MSC2946: by the `order` field (entries with a valid `order` first,
/// lexicographically), then `origin_server_ts`, then `state_key`.
fn children(room: &RoomState) -> Vec<(String, Value)> {
    let mut out: Vec<(String, Value)> = room
        .state_events
        .iter()
        .filter(|(k, v)| {
            k.starts_with("m.space.child\u{1f}")
                && v.get("content").and_then(|c| c.get("via")).map(Value::is_array).unwrap_or(false)
        })
        .filter_map(|(_, e)| {
            let child_id = e.get("state_key").and_then(Value::as_str)?.to_string();
            let stripped = json!({
                "content": e.get("content").cloned().unwrap_or(json!({})),
                "sender": e.get("sender").cloned().unwrap_or(Value::Null),
                "state_key": e.get("state_key").cloned().unwrap_or(Value::Null),
                "type": "m.space.child",
                "origin_server_ts": e.get("origin_server_ts").cloned().unwrap_or(json!(0)),
            });
            Some((child_id, stripped))
        })
        .collect();

    // A valid `order` is a string of ≤50 chars in the range 0x20..=0x7E.
    let order_key = |s: &Value| -> Option<String> {
        s.get("content")
            .and_then(|c| c.get("order"))
            .and_then(Value::as_str)
            .filter(|o| o.len() <= 50 && o.chars().all(|c| ('\u{20}'..='\u{7e}').contains(&c)))
            .map(String::from)
    };
    out.sort_by(|(a_id, a), (b_id, b)| {
        let ao = order_key(a);
        let bo = order_key(b);
        // Entries with a valid `order` sort before those without.
        match (ao, bo) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
        .then_with(|| {
            let ats = a.get("origin_server_ts").and_then(Value::as_i64).unwrap_or(0);
            let bts = b.get("origin_server_ts").and_then(Value::as_i64).unwrap_or(0);
            ats.cmp(&bts)
        })
        .then_with(|| a_id.cmp(b_id))
    });
    out
}

/// A local room is visible to the user if public/knockable, world-readable, a
/// restricted room whose `allow` rule the user satisfies, or they are a member.
async fn accessible(storage: &dyn crate::storage::Storage, room: &RoomState, user_id: &str) -> bool {
    match state_content(room, "m.room.join_rules\u{1f}", "join_rule") {
        Some("public") | Some("knock") | Some("knock_restricted") => return true,
        // MSC3083: a restricted room is visible in the hierarchy if the user can
        // join it via the allow rule (TestRestrictedRoomsSpacesSummaryLocal).
        Some("restricted") => {
            if crate::room_ops::user_satisfies_restricted_allow(storage, room, user_id, None).await {
                return true;
            }
        }
        _ => {}
    }
    if state_content(room, "m.room.history_visibility\u{1f}", "history_visibility") == Some("world_readable") {
        return true;
    }
    matches!(get_membership(room, user_id), Some("join") | Some("invite"))
}

/// `GET /_matrix/client/v1/rooms/{roomId}/hierarchy`.
pub async fn get_hierarchy(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(root): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let limit = params.get("limit").and_then(|l| l.parse().ok()).unwrap_or(MAX_ROOMS).min(MAX_ROOMS);
    let suggested_only = params.get("suggested_only").map(String::as_str) == Some("true");
    let max_depth: usize = params.get("max_depth").and_then(|d| d.parse().ok()).unwrap_or(50);
    let from = params.get("from").cloned();

    if st.storage.get_room(&root.as_str().into()).await.is_none() {
        return Err(not_found("Room not found"));
    }

    let mut visited: HashSet<String> = HashSet::new();
    let mut rooms: Vec<Value> = Vec::new();
    // Stack of (room_id, depth); pop LIFO so children pop in declaration order.
    let mut stack: Vec<(String, usize)> = vec![(root.clone(), 0)];
    // Pagination: when `from` is set, walk (rebuilding the stack) but don't
    // collect rooms until we re-encounter `from` (strix/Synapse behaviour).
    let mut skipping = from.is_some();

    // Stop as soon as we have `limit` rooms, leaving the stack intact so
    // `next_batch` can resume — draining it fully would lose the cursor.
    while rooms.len() < limit {
        let Some((room_id, depth)) = stack.pop() else { break };
        if visited.contains(&room_id) {
            continue;
        }
        visited.insert(room_id.clone());
        let Some(room) = st.storage.get_room(&room_id.as_str().into()).await else {
            continue;
        };
        if room_id != root && !accessible(&*st.storage, &room, auth.user_id.as_str()).await {
            continue;
        }
        // Only spaces contribute children to the hierarchy; a non-space room is a
        // leaf whose stray m.space.child links are ignored (not listed/traversed).
        let mut child_events: Vec<(String, Value)> = if is_space(&room) { children(&room) } else { Vec::new() };
        if suggested_only {
            child_events.retain(|(_, s)| s.get("content").and_then(|c| c.get("suggested")).and_then(Value::as_bool) == Some(true));
        }

        // Recurse into a space's children only while within max_depth.
        let push_children = |stack: &mut Vec<(String, usize)>| {
            if depth >= max_depth {
                return;
            }
            for (child_id, _) in child_events.iter().rev() {
                if !visited.contains(child_id) {
                    stack.push((child_id.clone(), depth + 1));
                }
            }
        };

        if skipping {
            if room_id == *from.as_deref().unwrap_or_default() {
                skipping = false;
            }
            push_children(&mut stack);
            continue;
        }

        let mut entry = summary_fields(&room, &room_id);
        entry.insert(
            "children_state".into(),
            json!(child_events.iter().map(|(_, s)| s.clone()).collect::<Vec<_>>()),
        );
        rooms.push(Value::Object(entry));
        push_children(&mut stack);
    }

    // A next_batch cursor is returned when we stopped at the limit with work left.
    let next_batch = if !stack.is_empty() && rooms.len() == limit {
        rooms.last().and_then(|r| r.get("room_id")).and_then(Value::as_str).map(String::from)
    } else {
        None
    };

    let mut body = serde_json::Map::new();
    body.insert("rooms".into(), Value::Array(rooms));
    if let Some(nb) = next_batch {
        body.insert("next_batch".into(), json!(nb));
    }
    Ok(Json(Value::Object(body)))
}
