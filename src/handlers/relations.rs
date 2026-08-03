//! Event relations + threads — ports of strix `handlers/relations.ts`
//! (`getRelations`) and `handlers/threads.ts` (`getThreads`).

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::response::Json;
use serde_json::{json, Value};

use crate::errors::{not_found, MatrixResult};
use crate::events::pdu_to_client_event;
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
