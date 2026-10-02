//! Notifications — port of strix `handlers/notifications.ts`. Computed on the
//! fly by evaluating push rules over recent events (no dedicated store).

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::response::Json;
use serde_json::{json, Value};

use crate::events::pdu_to_client_event;
use crate::push_rules::{evaluate_push_rules, get_or_init_rules, EvaluationContext};
use crate::server::{AppState, AuthCtx};
use crate::storage::Direction;

/// `GET /_matrix/client/v3/notifications`.
pub async fn get_notifications(
    State(st): State<AppState>,
    auth: AuthCtx,
    Query(params): Query<HashMap<String, String>>,
) -> Json<Value> {
    let limit: usize = params.get("limit").and_then(|l| l.parse().ok()).unwrap_or(20).min(1000);
    let only_highlights = params.get("only").map(String::as_str) == Some("highlight");

    let rules = get_or_init_rules(&*st.storage, &auth.user_id).await;
    let profile = st.storage.get_profile(&auth.user_id).await;
    let display_name = profile.and_then(|p| p.displayname);

    let mut notifications = Vec::new();
    for room_id in st.storage.get_rooms_for_user(&auth.user_id).await {
        let member_events = st.storage.get_member_events(&room_id).await;
        let member_count = member_events
            .iter()
            .filter(|m| m.event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("join"))
            .count() as i64;
        let pl = st.storage.get_state_event(&room_id, "m.room.power_levels", "").await;
        let pl_content = pl.as_ref().and_then(|e| e.event.get("content")).cloned();

        let page = st.storage.get_events_by_room(&room_id, 100, None, Direction::Backward).await;
        for er in page.events {
            let sender = er.event.get("sender").and_then(Value::as_str).unwrap_or("");
            if sender == auth.user_id.as_str() {
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
                    user_id: auth.user_id.as_str(),
                    display_name: display_name.as_deref(),
                    member_count,
                    power_levels: pl_content.as_ref(),
                    sender_power_level: sender_pl,
                },
            );
            if !result.notify {
                continue;
            }
            if only_highlights && !result.highlight {
                continue;
            }
            let mut actions = vec![json!("notify")];
            if result.highlight {
                actions.push(json!({ "set_tweak": "highlight" }));
            }
            if let Some(sound) = &result.sound {
                actions.push(json!({ "set_tweak": "sound", "value": sound }));
            }
            let ce = serde_json::to_value(pdu_to_client_event(&er.event, er.event_id.as_str())).unwrap_or(Value::Null);
            let ts = ce.get("origin_server_ts").cloned().unwrap_or(Value::Null);
            notifications.push(json!({
                "actions": actions,
                "event": ce,
                "room_id": room_id.as_str(),
                "ts": ts,
                "read": false,
            }));
        }
    }

    notifications.truncate(limit);
    Json(json!({ "notifications": notifications }))
}
