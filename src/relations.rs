//! Event relations — port of strix `src/relations.ts`.
//!
//! `index_relation` extracts `m.relates_to` after an event is stored;
//! `bundle_aggregations` enriches client events with
//! `unsigned["m.relations"]` (reaction counts, latest edit, thread summary).

use serde_json::{json, Map, Value};

use crate::events::pdu_to_client_event;
use crate::storage::Storage;
use crate::types::identifiers::{EventId, RoomId, UserId};

/// Extract relation info from a stored event's content and index it (strix
/// `indexRelation`). No-op unless `m.relates_to` carries both `rel_type` and
/// `event_id`.
pub async fn index_relation(storage: &dyn Storage, event: &Value, event_id: &EventId) {
    let Some(relates_to) = event
        .get("content")
        .and_then(|c| c.get("m.relates_to"))
        .and_then(Value::as_object)
    else {
        return;
    };
    let rel_type = relates_to.get("rel_type").and_then(Value::as_str);
    let target = relates_to.get("event_id").and_then(Value::as_str);
    let (Some(rel_type), Some(target)) = (rel_type, target) else {
        return;
    };
    let key = relates_to.get("key").and_then(Value::as_str);
    let room_id: RoomId = event
        .get("room_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .into();
    storage
        .store_relation(event_id, &room_id, rel_type, &EventId::from(target), key)
        .await;
}

/// Enrich client events (JSON objects with `event_id`/`sender`) with bundled
/// aggregations under `unsigned["m.relations"]` (strix `bundleAggregations`).
pub async fn bundle_aggregations(storage: &dyn Storage, events: &mut [Value], user_id: &UserId) {
    for event in events.iter_mut() {
        let Some(event_id) = event.get("event_id").and_then(Value::as_str).map(EventId::from) else {
            continue;
        };
        let sender: UserId = event
            .get("sender")
            .and_then(Value::as_str)
            .unwrap_or("")
            .into();

        let mut relations = Map::new();

        let annotations = storage.get_annotation_counts(&event_id).await;
        if !annotations.is_empty() {
            let chunk: Vec<Value> = annotations
                .iter()
                .map(|a| {
                    json!({ "type": a.annotation_type, "key": a.key, "count": a.count })
                })
                .collect();
            relations.insert("m.annotation".to_string(), json!({ "chunk": chunk }));
        }

        if let Some(edit) = storage.get_latest_edit(&event_id, &sender).await {
            let ce = pdu_to_client_event(&edit.event, edit.event_id.as_str());
            relations.insert(
                "m.replace".to_string(),
                json!({
                    "event_id": ce.event_id,
                    "origin_server_ts": ce.origin_server_ts,
                    "sender": ce.sender,
                }),
            );
        }

        if let Some(summary) = storage.get_thread_summary(&event_id, user_id).await {
            let latest = pdu_to_client_event(
                &summary.latest_event.event,
                summary.latest_event.event_id.as_str(),
            );
            relations.insert(
                "m.thread".to_string(),
                json!({
                    "latest_event": latest,
                    "count": summary.count,
                    "current_user_participated": summary.current_user_participated,
                }),
            );
        }

        if !relations.is_empty() {
            let unsigned = event
                .as_object_mut()
                .and_then(|o| {
                    o.entry("unsigned")
                        .or_insert_with(|| Value::Object(Map::new()))
                        .as_object_mut()
                });
            if let Some(unsigned) = unsigned {
                unsigned.insert("m.relations".to_string(), Value::Object(relations));
            }
        }
    }
}
