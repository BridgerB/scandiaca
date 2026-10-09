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
use crate::middleware::federation_auth::FedAuth;
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

/// Room IDs whose membership grants access to `room` via a restricted (or
/// knock_restricted) join rule (MSC3083). Mirrors strix `getAllowedRoomIds`.
fn allowed_room_ids(room: &RoomState) -> Vec<String> {
    let Some(jr) = room.state_events.get("m.room.join_rules\u{1f}") else { return Vec::new() };
    let content = jr.get("content");
    let rule = content.and_then(|c| c.get("join_rule")).and_then(Value::as_str);
    if rule != Some("restricted") && rule != Some("knock_restricted") {
        return Vec::new();
    }
    content
        .and_then(|c| c.get("allow"))
        .and_then(Value::as_array)
        .map(|allow| {
            allow
                .iter()
                .filter(|e| e.get("type").and_then(Value::as_str) == Some("m.room_membership"))
                .filter_map(|e| e.get("room_id").and_then(Value::as_str).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Whether any join/invite member of `room` is on `origin`.
fn host_in_room(room: &RoomState, origin: &str) -> bool {
    room.state_events.iter().any(|(k, v)| {
        k.strip_prefix("m.room.member\u{1f}")
            .map(|uid| {
                let m = v.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str);
                matches!(m, Some("join") | Some("invite")) && crate::ids::domain_of(uid) == origin
            })
            .unwrap_or(false)
    })
}

/// Whether a room should be shown to the requesting `origin` server (MSC2946
/// federation path). Mirrors strix `isRoomAccessibleToServer`.
async fn room_accessible_to_server(
    storage: &dyn crate::storage::Storage,
    room: &RoomState,
    origin: &str,
) -> bool {
    match state_content(room, "m.room.join_rules\u{1f}", "join_rule") {
        Some("public") | Some("knock") | Some("knock_restricted") => return true,
        _ => {}
    }
    if state_content(room, "m.room.history_visibility\u{1f}", "history_visibility") == Some("world_readable") {
        return true;
    }
    if host_in_room(room, origin) {
        return true;
    }
    for allowed in allowed_room_ids(room) {
        if let Some(ar) = storage.get_room(&allowed.as_str().into()).await {
            if host_in_room(&ar, origin) {
                return true;
            }
        }
    }
    false
}

/// Whether a room summary received over federation should be shown to `user_id`
/// (MSC2946). Mirrors strix `isRemoteRoomAccessible`.
async fn remote_room_accessible(
    storage: &dyn crate::storage::Storage,
    user_id: &str,
    remote: &Value,
) -> bool {
    let join_rule = remote.get("join_rule").and_then(Value::as_str).unwrap_or("public");
    if matches!(join_rule, "public" | "knock" | "knock_restricted") {
        return true;
    }
    if remote.get("world_readable").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    if let Some(allowed) = remote.get("allowed_room_ids").and_then(Value::as_array) {
        for ar in allowed.iter().filter_map(Value::as_str) {
            if let Some(room) = storage.get_room(&ar.into()).await {
                if get_membership(&room, user_id) == Some("join") {
                    return true;
                }
            }
        }
    }
    false
}

/// A client-facing hierarchy room built from a remote federation summary
/// (strix `remoteToHierarchyRoom`); drops `allowed_room_ids`.
fn remote_to_hierarchy_room(remote: &Value) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    for key in [
        "room_id", "name", "topic", "avatar_url", "canonical_alias", "join_rule", "room_type",
    ] {
        if let Some(v) = remote.get(key) {
            if !v.is_null() {
                m.insert(key.into(), v.clone());
            }
        }
    }
    m.insert(
        "num_joined_members".into(),
        json!(remote.get("num_joined_members").and_then(Value::as_i64).unwrap_or(0)),
    );
    m.insert("world_readable".into(), json!(remote.get("world_readable").and_then(Value::as_bool) == Some(true)));
    m.insert("guest_can_join".into(), json!(remote.get("guest_can_join").and_then(Value::as_bool) == Some(true)));
    m.insert(
        "children_state".into(),
        remote.get("children_state").cloned().unwrap_or(json!([])),
    );
    m
}

/// A single room's federation hierarchy entry: summary + child links +
/// allowed_room_ids. Mirrors strix `buildFederationRoomEntry`.
fn federation_room_entry(room: &RoomState, room_id: &str, suggested_only: bool) -> Value {
    let mut entry = summary_fields(room, room_id);
    let mut child_events = children(room);
    if suggested_only {
        child_events.retain(|(_, s)| {
            s.get("content").and_then(|c| c.get("suggested")).and_then(Value::as_bool) == Some(true)
        });
    }
    entry.insert(
        "children_state".into(),
        json!(child_events.iter().map(|(_, s)| s.clone()).collect::<Vec<_>>()),
    );
    entry.insert("allowed_room_ids".into(), json!(allowed_room_ids(room)));
    Value::Object(entry)
}

/// `GET /_matrix/federation/v1/hierarchy/{roomId}` — this server's view of one
/// space: the room plus a one-level summary of each child it holds locally.
/// Mirrors strix `postFederationHierarchy`.
pub async fn get_federation_hierarchy(
    State(st): State<AppState>,
    auth: FedAuth,
    Path(room_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let suggested_only = params.get("suggested_only").map(String::as_str) == Some("true");
    let origin = auth.origin.as_str();

    let room = st
        .storage
        .get_room(&room_id.as_str().into())
        .await
        .ok_or_else(|| not_found("Room not found"))?;
    if !room_accessible_to_server(&*st.storage, &room, origin).await {
        return Err(not_found("Room not found"));
    }

    let root_entry = federation_room_entry(&room, &room_id, suggested_only);

    let mut children_out: Vec<Value> = Vec::new();
    let mut inaccessible: Vec<String> = Vec::new();
    if let Some(cs) = root_entry.get("children_state").and_then(Value::as_array) {
        let child_ids: Vec<String> = cs
            .iter()
            .filter_map(|c| c.get("state_key").and_then(Value::as_str).map(String::from))
            .collect();
        for child_id in child_ids {
            match st.storage.get_room(&child_id.as_str().into()).await {
                Some(child_room) if room_accessible_to_server(&*st.storage, &child_room, origin).await => {
                    children_out.push(federation_room_entry(&child_room, &child_id, suggested_only));
                }
                _ => inaccessible.push(child_id),
            }
        }
    }

    Ok(Json(json!({
        "room": root_entry,
        "children": children_out,
        "inaccessible_children": inaccessible,
    })))
}

/// The `via` servers for a local room's `m.space.child` link.
fn via_for_child(room: &RoomState, child_id: &str) -> Vec<String> {
    room.state_events
        .get(&format!("m.space.child\u{1f}{child_id}"))
        .and_then(|e| e.get("content"))
        .and_then(|c| c.get("via"))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
        .unwrap_or_default()
}

/// Fetch a remote server's view of a space over federation, trying each `via`.
async fn fetch_remote_hierarchy(
    client: &crate::federation::FederationClient,
    via: &[String],
    room_id: &str,
    suggested_only: bool,
) -> Option<(Value, Vec<Value>)> {
    let path = format!(
        "/_matrix/federation/v1/hierarchy/{}{}",
        crate::handlers::federation::membership::urlencode_public(room_id),
        if suggested_only { "?suggested_only=true" } else { "" }
    );
    for server in via {
        if let Ok(res) = client.request(server, "GET", &path, None).await {
            if res.status == 200 {
                if let Some(room) = res.body.get("room") {
                    let children = res.body.get("children").and_then(Value::as_array).cloned().unwrap_or_default();
                    return Some((room.clone(), children));
                }
            }
        }
    }
    None
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
    // Stack of (room_id, depth, via); pop LIFO so children pop in declaration order.
    let mut stack: Vec<(String, usize, Vec<String>)> = vec![(root.clone(), 0, Vec::new())];
    // Pagination: when `from` is set, walk (rebuilding the stack) but don't
    // collect rooms until we re-encounter `from` (strix/Synapse behaviour).
    let mut skipping = from.is_some();
    // Summaries of remote rooms returned as children of a fetched remote room,
    // so we can render them without re-querying federation.
    let mut remote_cache: HashMap<String, Value> = HashMap::new();

    // Stop as soon as we have `limit` rooms, leaving the stack intact so
    // `next_batch` can resume — draining it fully would lose the cursor.
    while rooms.len() < limit {
        let Some((room_id, depth, via)) = stack.pop() else { break };
        if visited.contains(&room_id) {
            continue;
        }
        visited.insert(room_id.clone());

        let is_local = crate::ids::domain_of(&room_id) == st.server_name.as_ref();
        let local_room = st.storage.get_room(&room_id.as_str().into()).await;

        // Resolve this room into (summary entry, child (id, via) items, is-space).
        let entry: serde_json::Map<String, Value>;
        let child_items: Vec<(String, Vec<String>)>;
        let entry_is_space: bool;

        if let Some(room) = local_room {
            if room_id != root && !accessible(&*st.storage, &room, auth.user_id.as_str()).await {
                continue;
            }
            // Only spaces contribute children; a non-space room is a leaf whose
            // stray m.space.child links are ignored (not listed/traversed).
            let mut child_events = if is_space(&room) { children(&room) } else { Vec::new() };
            if suggested_only {
                child_events.retain(|(_, s)| s.get("content").and_then(|c| c.get("suggested")).and_then(Value::as_bool) == Some(true));
            }
            let mut e = summary_fields(&room, &room_id);
            e.insert("children_state".into(), json!(child_events.iter().map(|(_, s)| s.clone()).collect::<Vec<_>>()));
            child_items = child_events.iter().map(|(cid, _)| (cid.clone(), via_for_child(&room, cid))).collect();
            entry_is_space = is_space(&room);
            entry = e;
        } else if !is_local && (st.federation_client.is_some() || remote_cache.contains_key(&room_id)) {
            // Remote room: use a cached summary or fetch the owning server's view.
            let mut remote_room = remote_cache.get(&room_id).cloned();
            if remote_room.is_none() {
                if let Some(fed) = &st.federation_client {
                    if let Some((room, children)) = fetch_remote_hierarchy(fed, &via, &room_id, suggested_only).await {
                        for child in &children {
                            if let Some(cid) = child.get("room_id").and_then(Value::as_str) {
                                remote_cache.insert(cid.to_string(), child.clone());
                            }
                        }
                        remote_room = Some(room);
                    }
                }
            }
            let Some(remote_room) = remote_room else { continue };
            if room_id != root && !remote_room_accessible(&*st.storage, auth.user_id.as_str(), &remote_room).await {
                continue;
            }
            let e = remote_to_hierarchy_room(&remote_room);
            child_items = e
                .get("children_state")
                .and_then(Value::as_array)
                .map(|cs| {
                    cs.iter()
                        .filter_map(|c| {
                            let cid = c.get("state_key").and_then(Value::as_str)?.to_string();
                            let cvia = c
                                .get("content")
                                .and_then(|ct| ct.get("via"))
                                .and_then(Value::as_array)
                                .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
                                .unwrap_or_default();
                            Some((cid, cvia))
                        })
                        .collect()
                })
                .unwrap_or_default();
            entry_is_space = e.get("room_type").and_then(Value::as_str) == Some("m.space");
            entry = e;
        } else {
            continue;
        }

        // Recurse into a space's children only while within max_depth.
        let push_children = |stack: &mut Vec<(String, usize, Vec<String>)>| {
            if !entry_is_space || depth >= max_depth {
                return;
            }
            for (child_id, cvia) in child_items.iter().rev() {
                if !visited.contains(child_id) {
                    stack.push((child_id.clone(), depth + 1, cvia.clone()));
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
