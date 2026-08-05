//! Room directory — aliases + public room list — port of strix
//! `handlers/directory.ts` (local paths; remote alias resolution over
//! federation arrives with the federation phase).

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::response::Json;
use serde_json::{json, Value};

use crate::errors::{bad_json, forbidden, not_found, MatrixResult};
use crate::events::{get_membership, get_user_power_level};
use crate::ids::domain_of;
use crate::room_ops::{require_joined_room, send_state_event, EventContext};
use crate::server::{AppState, AuthCtx};
use crate::storage::Visibility;
use crate::types::identifiers::{RoomAlias, RoomId};
use crate::types::internal::RoomState;

const MAX_PUBLIC_ROOMS: usize = 100;

fn visibility_str(v: Visibility) -> &'static str {
    match v {
        Visibility::Public => "public",
        Visibility::Private => "private",
    }
}

/// Read a scalar field from a room state event's content.
fn state_content<'a>(room: &'a RoomState, key: &str, field: &str) -> Option<&'a str> {
    room.state_events
        .get(key)
        .and_then(|e| e.get("content"))
        .and_then(|c| c.get(field))
        .and_then(Value::as_str)
}

/// `GET /_matrix/client/v3/directory/room/{roomAlias}`.
pub async fn get_alias(
    State(st): State<AppState>,
    Path(room_alias): Path<String>,
) -> MatrixResult<Json<Value>> {
    let result = st
        .storage
        .get_room_by_alias(&RoomAlias::from(room_alias.as_str()))
        .await
        .ok_or_else(|| not_found("Room alias not found"))?;
    let servers: Vec<String> = result.servers.iter().map(|s| s.as_str().to_string()).collect();
    Ok(Json(json!({ "room_id": result.room_id.as_str(), "servers": servers })))
}

/// `PUT /_matrix/client/v3/directory/room/{roomAlias}`.
pub async fn put_alias(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_alias): Path<String>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let Some(room_id) = body.get("room_id").and_then(Value::as_str) else {
        return Err(bad_json("Missing 'room_id'"));
    };
    let alias = RoomAlias::from(room_alias.as_str());
    if st.storage.get_room_by_alias(&alias).await.is_some() {
        return Err(bad_json("Room alias already exists"));
    }
    if domain_of(&room_alias) != st.server_name.as_ref() {
        return Err(bad_json("Cannot create alias for remote server"));
    }
    let rid = RoomId::from(room_id);
    let room = st.storage.get_room(&rid).await.ok_or_else(|| not_found("Room not found"))?;
    if get_membership(&room, auth.user_id.as_str()) != Some("join") {
        return Err(forbidden("Must be in the room to create an alias"));
    }
    st.storage
        .create_room_alias(&alias, &rid, vec![st.server_name.as_ref().into()], &auth.user_id)
        .await;
    Ok(Json(json!({})))
}

/// `DELETE /_matrix/client/v3/directory/room/{roomAlias}`.
pub async fn delete_alias(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_alias): Path<String>,
) -> MatrixResult<Json<Value>> {
    let alias = RoomAlias::from(room_alias.as_str());
    let result = st.storage.get_room_by_alias(&alias).await.ok_or_else(|| not_found("Room alias not found"))?;
    let room = st.storage.get_room(&result.room_id).await;

    let creator = st.storage.get_alias_creator(&alias).await;
    if creator.as_ref() != Some(&auth.user_id) {
        match &room {
            Some(r) if get_user_power_level(auth.user_id.as_str(), r) >= 50.0 => {}
            Some(_) => return Err(forbidden("Must be alias creator or room admin to delete alias")),
            None => return Err(forbidden("Must be alias creator to delete alias")),
        }
    }
    st.storage.delete_room_alias(&alias).await;

    // If the room's m.room.canonical_alias referenced this alias (as `alias` or in
    // `alt_aliases`), emit an updated canonical_alias with it removed, so the state
    // stays consistent and the change is observable via /sync (TestRoomDeleteAlias).
    if let Some(room) = room {
        if let Some(canonical) = room.state_events.get("m.room.canonical_alias\u{1f}") {
            let content = canonical.get("content").cloned().unwrap_or_else(|| json!({}));
            let a = room_alias.as_str();
            let refs = content.get("alias").and_then(Value::as_str) == Some(a)
                || content
                    .get("alt_aliases")
                    .and_then(Value::as_array)
                    .map(|arr| arr.iter().any(|x| x.as_str() == Some(a)))
                    .unwrap_or(false);
            if refs && get_user_power_level(auth.user_id.as_str(), &room) >= 50.0 {
                let mut new_content = serde_json::Map::new();
                if let Some(cur) = content.get("alias").and_then(Value::as_str) {
                    if cur != a {
                        new_content.insert("alias".to_string(), json!(cur));
                    }
                }
                if let Some(alts) = content.get("alt_aliases").and_then(Value::as_array) {
                    let kept: Vec<&Value> = alts.iter().filter(|x| x.as_str() != Some(a)).collect();
                    if !kept.is_empty() {
                        new_content.insert("alt_aliases".to_string(), json!(kept));
                    }
                }
                let mut ctx = EventContext {
                    depth: room.depth,
                    prev_events: room.forward_extremities.iter().map(|e| e.as_str().to_string()).collect(),
                    room_state: room,
                };
                let _ = send_state_event(
                    &*st.storage,
                    &st.server_name,
                    &mut ctx,
                    auth.user_id.as_str(),
                    "m.room.canonical_alias",
                    "",
                    Value::Object(new_content),
                    Some(st.signing_key.as_ref()),
                    None,
                )
                .await;
            }
        }
    }
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v3/directory/list/room/{roomId}`.
pub async fn get_list_room(
    State(st): State<AppState>,
    Path(room_id): Path<String>,
) -> Json<Value> {
    let v = st.storage.get_room_visibility(&RoomId::from(room_id.as_str())).await;
    Json(json!({ "visibility": visibility_str(v) }))
}

/// `PUT /_matrix/client/v3/directory/list/room/{roomId}`.
pub async fn put_list_room(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let vis = body.get("visibility").and_then(Value::as_str);
    let visibility = match vis {
        Some("public") => Visibility::Public,
        Some("private") => Visibility::Private,
        _ => return Err(bad_json("visibility must be 'public' or 'private'")),
    };
    let rid = RoomId::from(room_id.as_str());
    let room = st.storage.get_room(&rid).await.ok_or_else(|| not_found("Room not found"))?;
    if get_membership(&room, auth.user_id.as_str()) != Some("join") {
        return Err(forbidden("Must be in the room"));
    }
    if get_user_power_level(auth.user_id.as_str(), &room) < 50.0 {
        return Err(forbidden("Insufficient power level"));
    }
    st.storage.set_room_visibility(&rid, visibility).await;
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v3/publicRooms`.
pub async fn get_public_rooms(
    State(st): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<Value> {
    let limit = params.get("limit").and_then(|l| l.parse().ok()).unwrap_or(20).min(MAX_PUBLIC_ROOMS);
    Json(build_public_rooms(&st, limit, params.get("since"), None).await)
}

/// `POST /_matrix/client/v3/publicRooms`.
pub async fn post_public_rooms(
    State(st): State<AppState>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let limit = body.get("limit").and_then(Value::as_u64).unwrap_or(20).min(MAX_PUBLIC_ROOMS as u64) as usize;
    let since = body.get("since").and_then(Value::as_str).map(String::from);
    let search = body
        .get("filter")
        .and_then(|f| f.get("generic_search_term"))
        .and_then(Value::as_str)
        .map(|s| s.to_lowercase());
    Json(build_public_rooms(&st, limit, since.as_ref(), search.as_deref()).await)
}

/// `GET /_matrix/client/v3/rooms/{roomId}/aliases`.
pub async fn get_room_aliases(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    require_joined_room(&*st.storage, &rid, auth.user_id.as_str()).await?;
    let aliases: Vec<String> = st
        .storage
        .get_aliases_for_room(&rid)
        .await
        .iter()
        .map(|a| a.as_str().to_string())
        .collect();
    Ok(Json(json!({ "aliases": aliases })))
}

async fn public_room_entry(st: &AppState, room_id: &RoomId) -> Option<Value> {
    let room = st.storage.get_room(room_id).await?;
    let num_joined = room
        .state_events
        .iter()
        .filter(|(k, v)| {
            k.starts_with("m.room.member\u{1f}")
                && v.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("join")
        })
        .count();
    let mut entry = json!({
        "room_id": room_id.as_str(),
        "num_joined_members": num_joined,
        "world_readable": state_content(&room, "m.room.history_visibility\u{1f}", "history_visibility") == Some("world_readable"),
        "guest_can_join": state_content(&room, "m.room.guest_access\u{1f}", "guest_access") == Some("can_join"),
    });
    if let Some(name) = state_content(&room, "m.room.name\u{1f}", "name") {
        entry["name"] = json!(name);
    }
    if let Some(topic) = state_content(&room, "m.room.topic\u{1f}", "topic") {
        entry["topic"] = json!(topic);
    }
    if let Some(avatar) = state_content(&room, "m.room.avatar\u{1f}", "url") {
        entry["avatar_url"] = json!(avatar);
    }
    if let Some(alias) = state_content(&room, "m.room.canonical_alias\u{1f}", "alias") {
        entry["canonical_alias"] = json!(alias);
    }
    if let Some(jr) = state_content(&room, "m.room.join_rules\u{1f}", "join_rule") {
        entry["join_rule"] = json!(jr);
    }
    if let Some(rt) = state_content(&room, "m.room.create\u{1f}", "type") {
        entry["room_type"] = json!(rt);
    }
    let aliases = st.storage.get_aliases_for_room(room_id).await;
    if !aliases.is_empty() {
        entry["aliases"] = json!(aliases.iter().map(|a| a.as_str()).collect::<Vec<_>>());
    }
    Some(entry)
}

async fn build_public_rooms(
    st: &AppState,
    limit: usize,
    since: Option<&String>,
    search: Option<&str>,
) -> Value {
    let mut entries: Vec<Value> = Vec::new();
    for room_id in st.storage.get_public_room_ids().await {
        let Some(entry) = public_room_entry(st, &room_id).await else {
            continue;
        };
        if let Some(term) = search {
            let hit = |f: &str| entry.get(f).and_then(Value::as_str).is_some_and(|s| s.to_lowercase().contains(term));
            if !hit("name") && !hit("topic") && !hit("canonical_alias") {
                continue;
            }
        }
        entries.push(entry);
    }
    entries.sort_by(|a, b| {
        b["num_joined_members"].as_u64().unwrap_or(0).cmp(&a["num_joined_members"].as_u64().unwrap_or(0))
    });

    let total = entries.len();
    let offset: usize = since
        .and_then(|s| base64_decode_usize(s))
        .unwrap_or(0);
    let sliced: Vec<Value> = entries.into_iter().skip(offset).take(limit).collect();
    let next_offset = offset + limit;

    let mut resp = json!({ "chunk": sliced, "total_room_count_estimate": total });
    if next_offset < total {
        resp["next_batch"] = json!(base64_encode_usize(next_offset));
    }
    if offset > 0 {
        resp["prev_batch"] = json!(base64_encode_usize(offset.saturating_sub(limit)));
    }
    resp
}

fn base64_encode_usize(n: usize) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(n.to_string())
}

fn base64_decode_usize(s: &str) -> Option<usize> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let bytes = URL_SAFE_NO_PAD.decode(s).ok()?;
    String::from_utf8(bytes).ok()?.parse().ok()
}
