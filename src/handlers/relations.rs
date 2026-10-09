//! Event relations + threads — ports of strix `handlers/relations.ts`
//! (`getRelations`) and `handlers/threads.ts` (`getThreads`).

use std::collections::{HashMap, HashSet};

use axum::extract::{Path, Query, State};
use axum::response::Json;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::errors::{forbidden, not_found, MatrixResult};
use crate::events::{compute_event_id, get_membership, pdu_to_client_event};
use crate::middleware::federation_auth::FedAuthBody;
use crate::relations::bundle_aggregations;
use crate::room_ops::require_joined_room;
use crate::server::{AppState, AuthCtx};
use crate::storage::{Direction, ThreadInclude};
use crate::types::identifiers::{EventId, RoomId};

fn parse_limit(params: &HashMap<String, String>, default: usize) -> usize {
    params
        .get("limit")
        .and_then(|l| l.parse::<usize>().ok())
        .unwrap_or(default)
        .min(1000)
}

/// `GET /_matrix/client/v1/rooms/{roomId}/relations/{eventId}` and the
/// `/{relType}` and `/{relType}/{eventType}` variants.
pub async fn get_relations(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(params): Path<Vec<String>>,
    Query(query): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    // Path is [roomId, eventId] (+ optional relType, eventType).
    let room_id = params.first().cloned().unwrap_or_default();
    let event_id = params.get(1).cloned().unwrap_or_default();
    let rel_type = params.get(2).map(String::as_str);
    let event_type = params.get(3).map(String::as_str);

    let rid = RoomId::from(room_id.as_str());
    require_joined_room(&*st.storage, &rid, auth.user_id.as_str()).await?;

    let eid = EventId::from(event_id.as_str());
    let target = st.storage.get_event(&eid).await;
    if target
        .as_ref()
        .and_then(|t| t.event.get("room_id").and_then(Value::as_str))
        != Some(&room_id)
    {
        return Err(not_found("Event not found"));
    }

    let limit = parse_limit(&query, 50);
    let from = query.get("from").map(String::as_str);
    let direction = match query.get("dir").map(String::as_str) {
        Some("f") => Direction::Forward,
        _ => Direction::Backward,
    };

    let result = st
        .storage
        .get_related_events(&rid, &eid, rel_type, event_type, Some(limit), from, direction)
        .await;
    let mut chunk: Vec<Value> = result
        .events
        .iter()
        .map(|e| serde_json::to_value(pdu_to_client_event(&e.event, e.event_id.as_str())).unwrap_or(Value::Null))
        .collect();
    bundle_aggregations(&*st.storage, &mut chunk, &auth.user_id).await;

    Ok(Json(json!({ "chunk": chunk, "next_batch": result.next_batch })))
}

/// `GET /_matrix/client/v1/rooms/{roomId}/threads`.
pub async fn get_threads(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    require_joined_room(&*st.storage, &rid, auth.user_id.as_str()).await?;

    let include = match query.get("include").map(String::as_str) {
        Some("participated") => ThreadInclude::Participated,
        _ => ThreadInclude::All,
    };
    let limit = parse_limit(&query, 20);
    let from = query.get("from").map(String::as_str);

    let result = st.storage.get_thread_roots(&rid, &auth.user_id, include, limit, from).await;
    let mut chunk: Vec<Value> = result
        .events
        .iter()
        .map(|e| serde_json::to_value(pdu_to_client_event(&e.event, e.event_id.as_str())).unwrap_or(Value::Null))
        .collect();
    bundle_aggregations(&*st.storage, &mut chunk, &auth.user_id).await;

    Ok(Json(json!({ "chunk": chunk, "next_batch": result.next_batch })))
}

// ---------------------------------------------------------------------------
// MSC2836 — Relationship based threading
// POST /_matrix/client/unstable/event_relationships (client, auth)
// POST /_matrix/federation/unstable/event_relationships (server, fedAuth)
//
// Both walk the `m.relationship` graph (rel_type "m.reference") from a root
// event, returning events in DAG-walk order. Port of strix relations.ts
// (postEventRelationships / postFederationEventRelationships), mirroring
// dendrite's msc2836. Relations are not indexed into a table here, so the
// parent<->child graph is built by scanning the room timeline. The client
// endpoint spiders in missing events over federation; the federation endpoint
// answers only from local state and returns the auth_chain too.
// ---------------------------------------------------------------------------

const REL_TYPE: &str = "m.reference";

/// The MSC2836 `m.relationship` (falling back to `m.relates_to`) parent
/// reference `(parent_id, rel_type)` of an event, if any.
fn parent_relationship(event: &Value) -> Option<(String, String)> {
    let content = event.get("content")?;
    let rel = content.get("m.relationship").or_else(|| content.get("m.relates_to"))?;
    let parent = rel.get("event_id").and_then(Value::as_str)?;
    let rel_type = rel.get("rel_type").and_then(Value::as_str)?;
    Some((parent.to_string(), rel_type.to_string()))
}

#[derive(Default)]
struct RelationGraph {
    /// parent id -> child (event, id) entries in insertion (stream) order
    children: HashMap<String, Vec<(Value, String)>>,
    /// child id -> (parent id, rel_type)
    parent: HashMap<String, (String, String)>,
    /// all events by id
    by_id: HashMap<String, (Value, String)>,
}

/// Index one event into the relation graph.
fn index_into_graph(graph: &mut RelationGraph, event: Value, event_id: String) {
    graph.by_id.entry(event_id.clone()).or_insert_with(|| (event.clone(), event_id.clone()));
    if let Some((parent_id, rel_type)) = parent_relationship(&event) {
        graph.parent.entry(event_id.clone()).or_insert_with(|| (parent_id.clone(), rel_type));
        let list = graph.children.entry(parent_id).or_default();
        if !list.iter().any(|(_, id)| id == &event_id) {
            list.push((event, event_id));
        }
    }
}

/// Build the relation graph for a room by scanning its timeline (ascending).
async fn build_graph_for_room(storage: &dyn crate::storage::Storage, room_id: Option<&str>) -> RelationGraph {
    let mut graph = RelationGraph::default();
    let Some(room_id) = room_id else { return graph };
    let rid = RoomId::from(room_id);
    let stream_pos = storage.get_stream_position().await;
    let page = storage
        .get_events_by_room(&rid, (stream_pos + 1).max(1) as usize, Some(0), Direction::Forward)
        .await;
    for e in page.events {
        index_into_graph(&mut graph, e.event, e.event_id.as_str().to_string());
    }
    graph
}

/// Children of `event_id` with rel_type m.reference, ordered by origin_server_ts
/// (event id tie-break); reversed when `recent_first`.
fn children_for_parent(graph: &RelationGraph, event_id: &str, recent_first: bool) -> Vec<(Value, String)> {
    let mut list: Vec<(Value, String)> = graph
        .children
        .get(event_id)
        .map(|v| {
            v.iter()
                .filter(|(_, id)| graph.parent.get(id).map(|(_, rt)| rt == REL_TYPE).unwrap_or(false))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    list.sort_by(|(a, aid), (b, bid)| {
        let ta = a.get("origin_server_ts").and_then(Value::as_i64).unwrap_or(0);
        let tb = b.get("origin_server_ts").and_then(Value::as_i64).unwrap_or(0);
        ta.cmp(&tb).then_with(|| aid.cmp(bid))
    });
    if recent_first {
        list.reverse();
    }
    list
}

struct RelReq {
    event_id: String,
    room_id: Option<String>,
    limit: usize,
    max_breadth: usize,
    max_depth: usize,
    depth_first: bool,
    recent_first: bool,
    include_parent: bool,
    include_children: bool,
    direction: String,
}

fn parse_rel_request(body: &Value) -> RelReq {
    let b = |k: &str| body.get(k).and_then(Value::as_bool);
    let n = |k: &str, d: usize| body.get(k).and_then(Value::as_u64).map(|v| v as usize).unwrap_or(d);
    RelReq {
        event_id: body.get("event_id").and_then(Value::as_str).unwrap_or("").to_string(),
        room_id: body.get("room_id").and_then(Value::as_str).map(String::from),
        limit: n("limit", 100),
        max_breadth: n("max_breadth", 10),
        max_depth: n("max_depth", 3),
        depth_first: b("depth_first").unwrap_or(false),
        recent_first: b("recent_first").unwrap_or(true),
        include_parent: b("include_parent").unwrap_or(false),
        include_children: b("include_children").unwrap_or(false),
        direction: if body.get("direction").and_then(Value::as_str) == Some("up") { "up" } else { "down" }.to_string(),
    }
}

/// Next walk layer: children (down) or the single parent id (up).
fn walk_layer(graph: &RelationGraph, event_id: &str, direction: &str, recent_first: bool) -> Vec<String> {
    if direction == "down" {
        return children_for_parent(graph, event_id, recent_first).into_iter().map(|(_, id)| id).collect();
    }
    match graph.parent.get(event_id) {
        Some((parent_id, rt)) if rt == REL_TYPE => vec![parent_id.clone()],
        _ => Vec::new(),
    }
}

/// Attach MSC2836 unsigned.children / unsigned.children_hash to a client event.
fn add_child_metadata(graph: &RelationGraph, client_event: &mut Value) {
    let event_id = client_event.get("event_id").and_then(Value::as_str).unwrap_or("").to_string();
    let kids = children_for_parent(graph, &event_id, false);
    if kids.is_empty() {
        return;
    }
    let mut ids: Vec<String> = kids.iter().map(|(_, id)| id.clone()).collect();
    ids.sort();
    // children_hash is unpadded STANDARD base64 of sha256(concatenated sorted ids).
    let hash = STANDARD_NO_PAD.encode(Sha256::digest(ids.join("").as_bytes()));
    let unsigned = client_event
        .as_object_mut()
        .and_then(|o| o.entry("unsigned").or_insert_with(|| Value::Object(Map::new())).as_object_mut());
    if let Some(u) = unsigned {
        u.insert("children".to_string(), json!({ REL_TYPE: kids.len() }));
        u.insert("children_hash".to_string(), json!(hash));
    }
}

/// Spider: POST /_matrix/federation/unstable/event_relationships to up to 5
/// servers in the room, persist returned auth_chain + events, index them, and
/// return the entry for `event_id` if present. No-op without a federation client
/// or room id.
#[allow(clippy::too_many_arguments)]
async fn fetch_remote(
    st: &AppState,
    room_id: Option<&str>,
    event_id: &str,
    req: &RelReq,
    graph: &mut RelationGraph,
) -> Option<(Value, String)> {
    let fed = st.federation_client.as_ref()?;
    let room_id = room_id?;
    let rid = RoomId::from(room_id);
    let room_version = st.storage.get_room(&rid).await.map(|r| r.room_version);
    let servers: Vec<String> = st
        .storage
        .get_servers_in_room(&rid)
        .await
        .into_iter()
        .map(|s| s.as_str().to_string())
        .filter(|s| s.as_str() != st.server_name.as_ref())
        .take(5)
        .collect();

    let payload = json!({
        "event_id": event_id,
        "direction": req.direction,
        "limit": req.limit,
        "max_breadth": req.max_breadth,
        "max_depth": req.max_depth,
        "depth_first": req.depth_first,
        "recent_first": req.recent_first,
    });

    for srv in &servers {
        let Ok(res) = fed
            .request(srv, "POST", "/_matrix/federation/unstable/event_relationships", Some(payload.clone()))
            .await
        else {
            continue;
        };
        if res.status != 200 {
            continue;
        }
        for ev in res.body.get("auth_chain").and_then(Value::as_array).into_iter().flatten() {
            let id = compute_event_id(ev, room_version.as_deref());
            let eid = EventId::from(id.as_str());
            if st.storage.get_event(&eid).await.is_none() {
                st.storage.store_event(ev.clone(), &eid).await;
            }
        }
        let mut found: Option<(Value, String)> = None;
        for ev in res.body.get("events").and_then(Value::as_array).into_iter().flatten() {
            let id = compute_event_id(ev, room_version.as_deref());
            let eid = EventId::from(id.as_str());
            if st.storage.get_event(&eid).await.is_none() {
                st.storage.store_event(ev.clone(), &eid).await;
            }
            index_into_graph(graph, ev.clone(), id.clone());
            if id == event_id {
                found = Some((ev.clone(), id));
            }
        }
        if found.is_some() {
            return found;
        }
    }
    None
}

/// Resolve an event: from the graph if held, else spider it in (client only).
async fn look_for_event(
    st: &AppState,
    room_id: Option<&str>,
    event_id: &str,
    req: &RelReq,
    graph: &mut RelationGraph,
    spider: bool,
) -> Option<(Value, String)> {
    if let Some(entry) = graph.by_id.get(event_id) {
        return Some(entry.clone());
    }
    if spider {
        return fetch_remote(st, room_id, event_id, req, graph).await;
    }
    None
}

/// Shared DAG walk for both handlers. `spider` enables remote fetches (client).
async fn process_relationships(
    st: &AppState,
    req: &RelReq,
    root: (Value, String),
    room_id: &str,
    graph: &mut RelationGraph,
    spider: bool,
) -> (Vec<(Value, String)>, bool) {
    let mut returned: Vec<(Value, String)> = vec![root.clone()];
    let mut included: HashSet<String> = HashSet::new();
    included.insert(root.1.clone());

    if req.include_parent {
        if let Some((parent_id, rt)) = graph.parent.get(&root.1).cloned() {
            if rt == REL_TYPE {
                if let Some(p) = look_for_event(st, Some(room_id), &parent_id, req, graph, spider).await {
                    if included.insert(p.1.clone()) {
                        returned.push(p);
                    }
                }
            }
        }
    }

    if req.include_children && returned.len() < req.limit {
        for (ev, id) in children_for_parent(graph, &root.1, req.recent_first) {
            if returned.len() >= req.limit {
                break;
            }
            if included.insert(id.clone()) {
                returned.push((ev, id));
            }
        }
    }

    let mut walk_limited = false;
    if returned.len() < req.limit {
        // Frontier of (event_id, depth); FIFO for breadth-first, LIFO for depth.
        let mut to_walk: Vec<(String, usize)> = Vec::new();
        let seed = walk_layer(graph, &root.1, &req.direction, req.recent_first);
        for id in seed.into_iter().take(req.max_breadth.max(0)) {
            to_walk.push((id, 1));
        }
        loop {
            let next = if req.depth_first { to_walk.pop() } else if to_walk.is_empty() { None } else { Some(to_walk.remove(0)) };
            let Some((id, depth)) = next else { break };
            if included.contains(&id) {
                continue;
            }
            if returned.len() >= req.limit {
                walk_limited = true;
                break;
            }
            if let Some(entry) = look_for_event(st, Some(room_id), &id, req, graph, spider).await {
                returned.push(entry);
            }
            included.insert(id.clone());
            if depth < req.max_depth {
                let mut layer = walk_layer(graph, &id, &req.direction, req.recent_first);
                if layer.len() > req.max_breadth {
                    layer.truncate(req.max_breadth);
                }
                for cid in layer {
                    to_walk.push((cid, depth + 1));
                }
            }
        }
    }

    let limited = returned.len() >= req.limit || walk_limited;
    (returned, limited)
}

/// `POST /_matrix/client/unstable/event_relationships` (authenticated).
pub async fn post_event_relationships(
    State(st): State<AppState>,
    auth: AuthCtx,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let req = parse_rel_request(&body);
    if req.event_id.is_empty() {
        return Err(not_found("Missing event_id"));
    }

    let mut graph = build_graph_for_room(&*st.storage, req.room_id.as_deref()).await;

    // Resolve the root: local graph, then storage, then remote spider.
    let mut root = graph.by_id.get(&req.event_id).cloned();
    if root.is_none() {
        if let Some(e) = st.storage.get_event(&EventId::from(req.event_id.as_str())).await {
            root = Some((e.event, req.event_id.clone()));
        }
    }
    let mut room_id = req
        .room_id
        .clone()
        .or_else(|| root.as_ref().and_then(|(e, _)| e.get("room_id").and_then(Value::as_str).map(String::from)));
    if root.is_none() {
        root = fetch_remote(&st, room_id.as_deref(), &req.event_id, &req, &mut graph).await;
        room_id = req
            .room_id
            .clone()
            .or_else(|| root.as_ref().and_then(|(e, _)| e.get("room_id").and_then(Value::as_str).map(String::from)));
    }

    let (Some(mut root), Some(room_id)) = (root, room_id) else {
        return Err(forbidden("Event does not exist or you are not authorised to see it"));
    };
    if root.0.get("room_id").and_then(Value::as_str) != Some(room_id.as_str()) {
        return Err(forbidden("Event does not exist or you are not authorised to see it"));
    }

    // If room_id was omitted, the graph was built empty; rebuild it now.
    if !graph.by_id.contains_key(&root.1) {
        graph = build_graph_for_room(&*st.storage, Some(room_id.as_str())).await;
        if let Some(e) = graph.by_id.get(&req.event_id) {
            root = e.clone();
        }
    }

    let rid = RoomId::from(room_id.as_str());
    let room = st.storage.get_room(&rid).await;
    if room.as_ref().map(|r| get_membership(r, auth.user_id.as_str())) != Some(Some("join")) {
        return Err(forbidden("Event does not exist or you are not authorised to see it"));
    }

    let (returned, limited) = process_relationships(&st, &req, root, &room_id, &mut graph, true).await;

    let events: Vec<Value> = returned
        .iter()
        .map(|(ev, id)| {
            let mut ce = serde_json::to_value(pdu_to_client_event(ev, id)).unwrap_or(Value::Null);
            add_child_metadata(&graph, &mut ce);
            ce
        })
        .collect();

    Ok(Json(json!({ "events": events, "limited": limited })))
}

/// `POST /_matrix/federation/unstable/event_relationships` (federation).
/// Answers only from local state (no spidering) and returns the auth_chain.
pub async fn post_federation_event_relationships(
    State(st): State<AppState>,
    auth: FedAuthBody,
) -> MatrixResult<Json<Value>> {
    let req = parse_rel_request(&auth.body);
    if req.event_id.is_empty() {
        return Err(not_found("Missing event_id"));
    }

    let root_stored = st.storage.get_event(&EventId::from(req.event_id.as_str())).await;
    let room_id = req
        .room_id
        .clone()
        .or_else(|| root_stored.as_ref().and_then(|e| e.event.get("room_id").and_then(Value::as_str).map(String::from)));

    let (Some(root_stored), Some(room_id)) = (root_stored, room_id) else {
        return Err(forbidden("Event does not exist or you are not authorised to see it"));
    };
    if root_stored.event.get("room_id").and_then(Value::as_str) != Some(room_id.as_str()) {
        return Err(forbidden("Event does not exist or you are not authorised to see it"));
    }

    // The origin server must be resident in the room.
    let rid = RoomId::from(room_id.as_str());
    let in_room = st.storage.get_servers_in_room(&rid).await.iter().any(|s| s.as_str() == auth.origin.as_str());
    if !in_room {
        return Err(forbidden("Event does not exist or you are not authorised to see it"));
    }

    let mut graph = build_graph_for_room(&*st.storage, Some(room_id.as_str())).await;
    let root = (root_stored.event, req.event_id.clone());
    let (returned, limited) = process_relationships(&st, &req, root, &room_id, &mut graph, false).await;

    // Events with MSC2836 child metadata overlaid onto each PDU's unsigned.
    let events: Vec<Value> = returned
        .iter()
        .map(|(ev, id)| {
            let mut ce = serde_json::to_value(pdu_to_client_event(ev, id)).unwrap_or(Value::Null);
            add_child_metadata(&graph, &mut ce);
            let mut out = ev.clone();
            if let (Some(obj), Some(unsigned)) = (out.as_object_mut(), ce.get("unsigned")) {
                obj.insert("unsigned".to_string(), unsigned.clone());
            }
            out
        })
        .collect();

    // auth_chain: union of every returned event's auth_events.
    let mut auth_ids: HashSet<String> = HashSet::new();
    for (ev, _) in &returned {
        for a in ev.get("auth_events").and_then(Value::as_array).into_iter().flatten() {
            if let Some(a) = a.as_str() {
                auth_ids.insert(a.to_string());
            }
        }
    }
    let auth_chain: Vec<Value> = if auth_ids.is_empty() {
        Vec::new()
    } else {
        let ids: Vec<EventId> = auth_ids.iter().map(|s| EventId::from(s.as_str())).collect();
        st.storage.get_auth_chain(&ids).await
    };

    Ok(Json(json!({ "events": events, "auth_chain": auth_chain, "limited": limited })))
}
