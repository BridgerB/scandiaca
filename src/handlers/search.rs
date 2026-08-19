//! Message search — port of strix `handlers/search.ts` (core room_events
//! search; event_context / include_state enrichment simplified).

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::response::Json;
use serde_json::{json, Value};

use crate::errors::{bad_json, MatrixResult};
use crate::events::pdu_to_client_event;
use crate::server::{AppState, AuthCtx};
use crate::storage::Direction;
use crate::types::identifiers::RoomId;

/// `POST /_matrix/client/v3/search`.
pub async fn search(
    State(st): State<AppState>,
    auth: AuthCtx,
    Query(query): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let room_events = body
        .get("search_categories")
        .and_then(|c| c.get("room_events"));
    let Some(search_term) = room_events
        .and_then(|r| r.get("search_term"))
        .and_then(Value::as_str)
    else {
        return Err(bad_json("Missing search_categories.room_events.search_term"));
    };

    let keys: Vec<String> = room_events
        .and_then(|r| r.get("keys"))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_else(|| vec!["content.body".to_string()]);
    let order_by = room_events
        .and_then(|r| r.get("order_by"))
        .and_then(Value::as_str)
        .unwrap_or("recent");
    let limit = room_events
        .and_then(|r| r.get("filter"))
        .and_then(|f| f.get("limit"))
        .and_then(Value::as_u64)
        .unwrap_or(10) as usize;
    let from = query.get("next_batch").map(String::as_str);
    // MSC-era event_context: include events around each result (TestSearch).
    let event_context = room_events.and_then(|r| r.get("event_context"));
    let before_limit = event_context.and_then(|c| c.get("before_limit")).and_then(Value::as_u64).unwrap_or(5) as usize;
    let after_limit = event_context.and_then(|c| c.get("after_limit")).and_then(Value::as_u64).unwrap_or(5) as usize;

    // Restrict to the searcher's joined rooms (optionally filtered).
    let mut room_ids: Vec<RoomId> = st.storage.get_rooms_for_user(&auth.user_id).await;
    if let Some(filter_rooms) = room_events
        .and_then(|r| r.get("filter"))
        .and_then(|f| f.get("rooms"))
        .and_then(Value::as_array)
    {
        let allowed: std::collections::HashSet<&str> =
            filter_rooms.iter().filter_map(|v| v.as_str()).collect();
        room_ids.retain(|r| allowed.contains(r.as_str()));
    }

    let result = st
        .storage
        .search_room_events(&room_ids, search_term, &keys, limit, from)
        .await;

    let mut results = Vec::new();
    for er in &result.events {
        // Skip redacted events.
        if er.event.get("unsigned").and_then(|u| u.get("redacted_because")).is_some() {
            continue;
        }
        let rank = if order_by == "rank" { 1.0 } else { er.stream_pos as f64 };
        let mut entry = json!({
            "rank": rank,
            "result": pdu_to_client_event(&er.event, er.event_id.as_str()),
        });
        if event_context.is_some() {
            let room = RoomId::from(er.event.get("room_id").and_then(Value::as_str).unwrap_or(""));
            let before = st.storage.get_events_by_room(&room, before_limit, Some(er.stream_pos), Direction::Backward).await;
            let after = st.storage.get_events_by_room(&room, after_limit, Some(er.stream_pos), Direction::Forward).await;
            let ev_before: Vec<Value> = before.events.iter().map(|e| serde_json::to_value(pdu_to_client_event(&e.event, e.event_id.as_str())).unwrap_or(Value::Null)).collect();
            let ev_after: Vec<Value> = after.events.iter().map(|e| serde_json::to_value(pdu_to_client_event(&e.event, e.event_id.as_str())).unwrap_or(Value::Null)).collect();
            entry["context"] = json!({ "events_before": ev_before, "events_after": ev_after });
        }
        results.push(entry);
    }

    // Omit next_batch entirely on the last page (a present-but-null token would
    // make clients paginate forever) — TestSearch back-pagination.
    let mut room_events_resp = serde_json::Map::new();
    room_events_resp.insert("count".to_string(), json!(result.count));
    room_events_resp.insert("results".to_string(), json!(results));
    room_events_resp.insert("highlights".to_string(), json!([search_term]));
    if let Some(nb) = &result.next_batch {
        room_events_resp.insert("next_batch".to_string(), json!(nb));
    }
    Ok(Json(json!({
        "search_categories": { "room_events": Value::Object(room_events_resp) }
    })))
}
