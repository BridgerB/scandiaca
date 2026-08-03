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
    if !user_id.starts_with('@') || !user_id.contains(':') {
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
