//! Inbound federation handlers — port of strix `src/handlers/federation/`.
//!
//! This iteration covers the self-contained query/key endpoints. The heavy
//! endpoints (transactions, make/send join+leave+knock, backfill, event/state
//! fetch, device/keys query) are ported in subsequent passes; behavioural
//! validation is via the Complement federation suite.

pub mod keys;
pub mod media;
pub mod membership;
pub mod transactions;

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::response::Json;
use serde_json::{json, Value};

use crate::errors::{bad_json, forbidden, invalid_param, missing_param, not_found, MatrixResult};
use crate::events::compute_event_id;
use crate::middleware::federation_auth::FedAuth;
use crate::server::{now_ms, AppState};
use crate::types::identifiers::{EventId, KeyId, RoomAlias, RoomId, ServerName, UserId};
use crate::types::internal::StateEvents;

/// `GET /_matrix/federation/v1/version` (public).
pub async fn version() -> Json<Value> {
    Json(json!({ "server": { "name": "scandiaca", "version": "0.0.1" } }))
}

/// `GET /_matrix/federation/v1/query/profile` (fedauth).
pub async fn query_profile(
    State(st): State<AppState>,
    _auth: FedAuth,
    Query(params): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let Some(user_id) = params.get("user_id") else {
        return Err(missing_param(
            "The request body did not contain required argument 'user_id'.",
        ));
    };
    // A valid user id is `@localpart:server_name`, where server_name is a host
    // optionally followed by a numeric port. `@user1:localhost:http` is malformed
    // (non-numeric port) and must be rejected with 400 (TestInboundFederationProfile).
    let valid = user_id.starts_with('@')
        && user_id[1..].split_once(':').is_some_and(|(local, domain)| {
            !local.is_empty()
                && !domain.is_empty()
                && domain.rsplit_once(':').is_none_or(|(host, port)| {
                    !host.is_empty() && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit())
                })
        });
    if !valid {
        return Err(invalid_param(format!("Invalid user ID: {user_id}")));
    }
    let profile = st
        .storage
        .get_profile(&UserId::from(user_id.as_str()))
        .await
        .ok_or_else(|| not_found("The user does not exist or does not have a profile."))?;
    match params.get("field").map(String::as_str) {
        Some("displayname") => Ok(Json(json!({ "displayname": profile.displayname }))),
        Some("avatar_url") => Ok(Json(json!({ "avatar_url": profile.avatar_url }))),
        Some(_) => Err(invalid_param(
            "The request body did not contain an allowed value of argument 'field'. Allowed values are either: 'avatar_url', 'displayname'.",
        )),
        None => Ok(Json(json!({
            "displayname": profile.displayname,
            "avatar_url": profile.avatar_url,
        }))),
    }
}

/// `GET /_matrix/federation/v1/query/directory` (fedauth).
pub async fn query_directory(
    State(st): State<AppState>,
    _auth: FedAuth,
    Query(params): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let Some(room_alias) = params.get("room_alias") else {
        return Err(bad_json("Must supply room alias parameter."));
    };
    let colon = room_alias.find(':');
    if !room_alias.starts_with('#') || colon.is_none() || colon == Some(1) {
        return Err(bad_json("Room alias must be in the form '#localpart:domain'"));
    }
    let result = st
        .storage
        .get_room_by_alias(&RoomAlias::from(room_alias.as_str()))
        .await
        .ok_or_else(|| not_found(format!("Room alias {room_alias} not found")))?;
    let servers: Vec<String> = if result.servers.is_empty() {
        vec![room_alias[colon.unwrap() + 1..].to_string()]
    } else {
        result.servers.iter().map(|s| s.as_str().to_string()).collect()
    };
    Ok(Json(json!({ "room_id": result.room_id.as_str(), "servers": servers })))
}

/// `POST /_matrix/key/v2/query` — key notary batch lookup (public).
pub async fn key_notary_query(
    State(st): State<AppState>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let mut server_keys = Vec::new();
    if let Some(requests) = body.get("server_keys").and_then(Value::as_object) {
        for (server_name, key_requests) in requests {
            if let Some(keys) = key_requests.as_object() {
                for key_id in keys.keys() {
                    if let Some(cached) = st
                        .storage
                        .get_server_keys(&ServerName::from(server_name.as_str()), &KeyId::from(key_id.as_str()))
                        .await
                    {
                        server_keys.push(json!({
                            "server_name": server_name,
                            "verify_keys": { key_id: { "key": cached.key } },
                            "old_verify_keys": {},
                            "valid_until_ts": cached.valid_until,
                            "signatures": {},
                        }));
                    }
                }
            }
        }
    }
    Json(json!({ "server_keys": server_keys }))
}

/// `GET /_matrix/key/v2/query/{serverName}` — notary single lookup. We cannot
/// enumerate a server's keys without a key id, so return an empty set (strix).
pub async fn key_notary_get() -> Json<Value> {
    Json(json!({ "server_keys": [] }))
}

// --- Event / state fetch (fedauth) -----------------------------------------

/// Resolve the room's state map as of `event_id` (or current state when `None`).
async fn resolve_state_map(st: &AppState, room_id: &RoomId, event_id: Option<&str>) -> Option<StateEvents> {
    let room = st.storage.get_room(room_id).await?;
    match event_id {
        None => Some(room.state_events),
        Some(eid) => {
            match st.storage.get_state_at_event(room_id, &EventId::from(eid)).await {
                Some(m) => Some(m),
                None => Some(room.state_events),
            }
        }
    }
}

/// Auth chain over a set of state events (their `auth_events`' transitive closure).
async fn auth_chain_for_state(st: &AppState, state: &StateEvents) -> Vec<Value> {
    let mut ids: Vec<EventId> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for ev in state.values() {
        if let Some(arr) = ev.get("auth_events").and_then(Value::as_array) {
            for a in arr {
                if let Some(s) = a.as_str() {
                    if seen.insert(s.to_string()) {
                        ids.push(EventId::from(s));
                    }
                }
            }
        }
    }
    st.storage.get_auth_chain(&ids).await
}

/// `GET /_matrix/federation/v1/event/{eventId}`.
pub async fn get_event(
    State(st): State<AppState>,
    _auth: FedAuth,
    axum::extract::Path(event_id): axum::extract::Path<String>,
) -> MatrixResult<Json<Value>> {
    let entry = st
        .storage
        .get_event(&EventId::from(event_id.as_str()))
        .await
        .ok_or_else(|| not_found("Event not found"))?;
    Ok(Json(json!({
        "origin": st.server_name.as_ref(),
        "origin_server_ts": now_ms(),
        "pdus": [entry.event],
    })))
}

/// Minimal percent-decoder for query values (event ids carry `$`, `:` etc.).
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(h) => {
                    out.push(h);
                    i += 3;
                }
                Err(_) => {
                    out.push(b[i]);
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `GET /_matrix/federation/v1/backfill/{roomId}?v=<eventId>&limit=N` — walk the
/// room DAG backward from the seed events (`v`), newest-first, returning up to
/// `limit` PDUs. Mirrors strix `postFederationBackfill` / Synapse
/// `_get_backfill_events`.
pub async fn get_backfill(
    State(st): State<AppState>,
    _auth: FedAuth,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::RawQuery(q): axum::extract::RawQuery,
) -> MatrixResult<Json<Value>> {
    let q = q.unwrap_or_default();
    let mut seeds: Vec<String> = Vec::new();
    let mut limit = 100usize;
    for kv in q.split('&') {
        if let Some(v) = kv.strip_prefix("v=") {
            seeds.push(percent_decode(v));
        } else if let Some(v) = kv.strip_prefix("limit=") {
            if let Ok(n) = v.parse::<usize>() {
                limit = n.min(100);
            }
        }
    }

    let in_room = |ev: &Value| ev.get("room_id").and_then(Value::as_str) == Some(room_id.as_str());
    let depth_ts = |ev: &Value| {
        (
            ev.get("depth").and_then(Value::as_i64).unwrap_or(0),
            ev.get("origin_server_ts").and_then(Value::as_i64).unwrap_or(0),
        )
    };

    // frontier: (id, depth, ts); processed newest-first.
    let mut frontier: Vec<(String, i64, i64)> = Vec::new();
    for s in &seeds {
        if let Some(e) = st.storage.get_event(&EventId::from(s.as_str())).await {
            if in_room(&e.event) {
                let (d, t) = depth_ts(&e.event);
                frontier.push((s.clone(), d, t));
            }
        }
    }

    let mut collected: Vec<Value> = Vec::new();
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut budget = 5000;
    while !frontier.is_empty() && collected.len() < limit && budget > 0 {
        budget -= 1;
        frontier.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)));
        let (id, _, _) = frontier.remove(0);
        if !visited.insert(id.clone()) {
            continue;
        }
        let Some(e) = st.storage.get_event(&EventId::from(id.as_str())).await else {
            continue;
        };
        if !in_room(&e.event) {
            continue;
        }
        for prev in e.event.get("prev_events").and_then(Value::as_array).cloned().unwrap_or_default() {
            let Some(pid) = prev.as_str() else { continue };
            if visited.contains(pid) || frontier.iter().any(|f| f.0 == pid) {
                continue;
            }
            if let Some(pe) = st.storage.get_event(&EventId::from(pid)).await {
                if in_room(&pe.event) {
                    let (d, t) = depth_ts(&pe.event);
                    frontier.push((pid.to_string(), d, t));
                }
            }
        }
        collected.push(e.event);
    }
    collected.sort_by(|a, b| {
        let (da, ta) = depth_ts(a);
        let (db, tb) = depth_ts(b);
        db.cmp(&da).then(tb.cmp(&ta))
    });
    Ok(Json(json!({
        "origin": st.server_name.as_ref(),
        "origin_server_ts": now_ms(),
        "pdus": collected,
    })))
}

/// `POST /_matrix/federation/v1/get_missing_events/{roomId}`.
///
/// Walk the room DAG backwards from `latest_events` (excluded) following
/// prev_events, stopping at `earliest_events` (the boundary, excluded) or the
/// limit, and return the discovered events oldest-first. Mirrors strix
/// `postFederationMissingEvents` / Synapse `_get_missing_events`.
pub async fn get_missing_events(
    State(st): State<AppState>,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    auth: crate::middleware::federation_auth::FedAuthBody,
) -> MatrixResult<Json<Value>> {
    let body = &auth.body;
    let limit = body.get("limit").and_then(Value::as_u64).unwrap_or(10).min(20) as usize;

    let earliest: std::collections::HashSet<String> = body
        .get("earliest_events")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let latest: Vec<String> = body
        .get("latest_events")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    // Determine the room (path may not carry it in the signed body, so fall back
    // to the first latest event's room).
    let mut seen = earliest;
    let mut front: Vec<String> = latest.into_iter().filter(|id| !seen.contains(id)).collect();

    let mut result: Vec<(Value, String)> = Vec::new();
    let mut budget = 5000;
    while !front.is_empty() && result.len() < limit && budget > 0 {
        budget -= 1;
        let mut next: Vec<String> = Vec::new();
        for id in &front {
            if result.len() >= limit {
                break;
            }
            let Some(entry) = st.storage.get_event(&EventId::from(id.as_str())).await else {
                continue;
            };
            if entry.event.get("room_id").and_then(Value::as_str) != Some(room_id.as_str()) {
                continue;
            }
            let prevs = entry.event.get("prev_events").and_then(Value::as_array).cloned().unwrap_or_default();
            for prev in prevs {
                let Some(prev_id) = prev.as_str() else { continue };
                if seen.contains(prev_id) {
                    continue;
                }
                seen.insert(prev_id.to_string());
                if result.len() >= limit {
                    break;
                }
                if let Some(pe) = st.storage.get_event(&EventId::from(prev_id)).await {
                    if pe.event.get("room_id").and_then(Value::as_str) == Some(room_id.as_str()) {
                        result.push((pe.event, prev_id.to_string()));
                        next.push(prev_id.to_string());
                    }
                }
            }
        }
        front = next;
    }

    // Oldest-first: sort by (depth, origin_server_ts, event_id) ascending.
    result.sort_by(|a, b| {
        let da = a.0.get("depth").and_then(Value::as_i64).unwrap_or(0);
        let db = b.0.get("depth").and_then(Value::as_i64).unwrap_or(0);
        let ta = a.0.get("origin_server_ts").and_then(Value::as_i64).unwrap_or(0);
        let tb = b.0.get("origin_server_ts").and_then(Value::as_i64).unwrap_or(0);
        da.cmp(&db).then(ta.cmp(&tb)).then(a.1.cmp(&b.1))
    });
    let events: Vec<Value> = result.into_iter().map(|(e, _)| e).collect();
    Ok(Json(json!({ "events": events })))
}

/// `GET /_matrix/federation/v1/state/{roomId}`.
pub async fn get_room_state(
    State(st): State<AppState>,
    auth: FedAuth,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    require_host_in_room(&st, &rid, &auth.origin).await?;
    let state = resolve_state_map(&st, &rid, params.get("event_id").map(String::as_str))
        .await
        .ok_or_else(|| not_found("State not found"))?;
    let pdus: Vec<Value> = state.values().cloned().collect();
    let auth_chain = auth_chain_for_state(&st, &state).await;
    Ok(Json(json!({ "pdus": pdus, "auth_chain": auth_chain })))
}

/// `GET /_matrix/federation/v1/state_ids/{roomId}`.
pub async fn get_room_state_ids(
    State(st): State<AppState>,
    auth: FedAuth,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let Some(event_id) = params.get("event_id") else {
        return Err(not_found("Missing event_id"));
    };
    let rid = RoomId::from(room_id.as_str());
    let room = st.storage.get_room(&rid).await.ok_or_else(|| not_found("Room not found"))?;
    require_host_in_room(&st, &rid, &auth.origin).await?;
    let state = resolve_state_map(&st, &rid, Some(event_id))
        .await
        .ok_or_else(|| not_found("State not found"))?;
    let rv = Some(room.room_version.as_str());
    let pdu_ids: Vec<String> = state.values().map(|e| compute_event_id(e, rv)).collect();
    let auth_chain = auth_chain_for_state(&st, &state).await;
    let auth_chain_ids: Vec<String> = auth_chain.iter().map(|e| compute_event_id(e, rv)).collect();
    Ok(Json(json!({ "pdu_ids": pdu_ids, "auth_chain_ids": auth_chain_ids })))
}

/// `GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}`.
pub async fn get_event_auth(
    State(st): State<AppState>,
    auth: FedAuth,
    axum::extract::Path((room_id, event_id)): axum::extract::Path<(String, String)>,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    let _ = st.storage.get_room(&rid).await.ok_or_else(|| not_found("Room not found"))?;
    let entry = st
        .storage
        .get_event(&EventId::from(event_id.as_str()))
        .await
        .filter(|e| e.event.get("room_id").and_then(Value::as_str) == Some(&room_id))
        .ok_or_else(|| not_found("Event not found"))?;
    require_host_in_room(&st, &rid, &auth.origin).await?;
    let ids: Vec<EventId> = entry
        .event
        .get("auth_events")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(EventId::from)).collect())
        .unwrap_or_default();
    let auth_chain = st.storage.get_auth_chain(&ids).await;
    Ok(Json(json!({ "auth_chain": auth_chain })))
}

/// Require the origin server to be resident in the room (assert_host_in_room).
async fn require_host_in_room(st: &AppState, room_id: &RoomId, origin: &str) -> MatrixResult<()> {
    let servers = st.storage.get_servers_in_room(room_id).await;
    if servers.iter().any(|s| s.as_str() == origin) {
        Ok(())
    } else {
        Err(forbidden("Host not in room"))
    }
}
