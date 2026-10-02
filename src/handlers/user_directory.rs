//! User directory search — port of strix `handlers/user-directory.ts`.

use std::collections::{HashMap, HashSet};

use axum::extract::State;
use axum::response::Json;
use serde_json::{json, Value};

use crate::errors::{bad_json, MatrixResult};
use crate::server::{AppState, AuthCtx};
use crate::types::identifiers::RoomId;

/// `POST /_matrix/client/v3/user_directory/search`.
pub async fn search(
    State(st): State<AppState>,
    auth: AuthCtx,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let Some(term_raw) = body.get("search_term").and_then(Value::as_str) else {
        return Err(bad_json("Missing search_term"));
    };
    let term = term_raw.to_lowercase();
    let limit = body.get("limit").and_then(Value::as_u64).unwrap_or(10).clamp(1, 50) as usize;

    let searcher = auth.user_id.as_str();
    let searcher_rooms: HashSet<String> = st
        .storage
        .get_rooms_for_user(&auth.user_id)
        .await
        .iter()
        .map(|r| r.as_str().to_string())
        .collect();
    let public_rooms: HashSet<String> = st
        .storage
        .get_public_room_ids()
        .await
        .iter()
        .map(|r| r.as_str().to_string())
        .collect();

    // A room counts as public (for directory visibility) if it is listed in the
    // public directory, is publicly joinable, or is world-readable.
    async fn room_public(st: &AppState, public_rooms: &HashSet<String>, room_id: &str) -> bool {
        if public_rooms.contains(room_id) {
            return true;
        }
        if let Some(room) = st.storage.get_room(&RoomId::from(room_id)).await {
            let jr = room
                .state_events
                .get("m.room.join_rules\u{1f}")
                .and_then(|e| e.get("content"))
                .and_then(|c| c.get("join_rule"))
                .and_then(Value::as_str);
            let hv = room
                .state_events
                .get("m.room.history_visibility\u{1f}")
                .and_then(|e| e.get("content"))
                .and_then(|c| c.get("history_visibility"))
                .and_then(Value::as_str);
            return jr == Some("public") || hv == Some("world_readable");
        }
        false
    }

    let mut results: HashMap<String, Value> = HashMap::new();

    // 1. Local directory candidates, filtered by directory visibility.
    for candidate in st.storage.search_user_directory(term_raw, 200).await {
        let uid = candidate.user_id.as_str().to_string();
        if results.contains_key(&uid) {
            continue;
        }
        let is_self = uid == searcher;
        let candidate_rooms = st.storage.get_rooms_for_user(&candidate.user_id).await;
        let mut in_public = false;
        for r in &candidate_rooms {
            if room_public(&st, &public_rooms, r.as_str()).await {
                in_public = true;
                break;
            }
        }
        let shares = candidate_rooms.iter().any(|r| searcher_rooms.contains(r.as_str()));
        if in_public || (shares && !is_self) {
            results.insert(
                uid.clone(),
                json!({ "user_id": uid, "display_name": candidate.display_name, "avatar_url": candidate.avatar_url }),
            );
        }
    }

    // 2. Members of the searcher's rooms (local + remote) matching the term.
    for room_id in &searcher_rooms {
        for m in st.storage.get_member_events(&RoomId::from(room_id.as_str())).await {
            let Some(uid) = m.event.get("state_key").and_then(Value::as_str) else {
                continue;
            };
            if uid == searcher || results.contains_key(uid) {
                continue;
            }
            let content = m.event.get("content");
            if content.and_then(|c| c.get("membership")).and_then(Value::as_str) != Some("join") {
                continue;
            }
            let dn = content.and_then(|c| c.get("displayname")).and_then(Value::as_str);
            let matches = uid.to_lowercase().contains(&term)
                || dn.map(|d| d.to_lowercase().contains(&term)).unwrap_or(false);
            if matches {
                results.insert(
                    uid.to_string(),
                    json!({
                        "user_id": uid,
                        "display_name": dn,
                        "avatar_url": content.and_then(|c| c.get("avatar_url")).and_then(Value::as_str),
                    }),
                );
            }
        }
    }

    let mut list: Vec<Value> = results.into_values().collect();
    let limited = list.len() > limit;
    list.truncate(limit);
    Ok(Json(json!({ "results": list, "limited": limited })))
}
