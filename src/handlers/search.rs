//! Message search — port of strix `handlers/search.ts` (core room_events
//! search; event_context / include_state enrichment simplified).

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::response::Json;
use serde_json::{json, Value};

use crate::errors::{bad_json, MatrixResult};
use crate::events::pdu_to_client_event;
use crate::server::{AppState, AuthCtx};
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
        results.push(json!({
            "rank": rank,
            "result": pdu_to_client_event(&er.event, er.event_id.as_str()),
        }));
    }

    Ok(Json(json!({
        "search_categories": {
            "room_events": {
                "count": result.count,
                "results": results,
                "highlights": [search_term],
                "next_batch": result.next_batch,
            }
        }
    })))
}
