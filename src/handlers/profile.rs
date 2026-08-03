//! Profile — port of strix `handlers/profile.ts` (local paths; remote-profile
//! federation lookup arrives with the federation phase).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use axum::extract::{Path, State};
use axum::response::Json;
use serde_json::{json, Map, Value};

use crate::errors::{bad_json, forbidden, not_found, MatrixResult};
use crate::events::get_membership;
use crate::room_ops::{send_state_event, EventContext};
use crate::server::{AppState, AuthCtx};
use crate::types::identifiers::UserId;

const MAX_DISPLAYNAME_BYTES: usize = 256;
const MAX_AVATAR_URL_BYTES: usize = 1000;

/// Process-local store for extended (custom) profile fields, keyed
/// `userId\x1fkeyName` (strix keeps these in an in-memory map).
fn extended_fields() -> &'static Mutex<HashMap<String, Value>> {
    static FIELDS: OnceLock<Mutex<HashMap<String, Value>>> = OnceLock::new();
    FIELDS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn field_key(user_id: &str, key_name: &str) -> String {
    format!("{user_id}\u{1f}{key_name}")
}

fn get_extended(user_id: &str) -> Map<String, Value> {
    let prefix = format!("{user_id}\u{1f}");
    let map = extended_fields().lock().unwrap();
    map.iter()
        .filter_map(|(k, v)| k.strip_prefix(&prefix).map(|name| (name.to_string(), v.clone())))
        .collect()
}

/// `GET /_matrix/client/v3/profile/{userId}`.
pub async fn get_profile(
    State(st): State<AppState>,
    Path(user_id): Path<String>,
) -> MatrixResult<Json<Value>> {
    let uid = UserId::from(user_id.as_str());
    let profile = st
        .storage
        .get_profile(&uid)
        .await
        .ok_or_else(|| not_found("User not found"))?;
    let mut body = Map::new();
    if let Some(dn) = profile.displayname {
        body.insert("displayname".to_string(), json!(dn));
    }
    if let Some(av) = profile.avatar_url {
        body.insert("avatar_url".to_string(), json!(av));
    }
    for (k, v) in get_extended(&user_id) {
        body.insert(k, v);
    }
    Ok(Json(Value::Object(body)))
}

/// `GET /_matrix/client/v3/profile/{userId}/displayname`.
pub async fn get_displayname(
    State(st): State<AppState>,
    Path(user_id): Path<String>,
) -> MatrixResult<Json<Value>> {
    let uid = UserId::from(user_id.as_str());
    let profile = st
        .storage
        .get_profile(&uid)
        .await
        .ok_or_else(|| not_found("User not found"))?;
    Ok(Json(json!({ "displayname": profile.displayname })))
}

/// `GET /_matrix/client/v3/profile/{userId}/avatar_url`.
pub async fn get_avatar_url(
    State(st): State<AppState>,
    Path(user_id): Path<String>,
) -> MatrixResult<Json<Value>> {
    let uid = UserId::from(user_id.as_str());
    let profile = st
        .storage
        .get_profile(&uid)
        .await
        .ok_or_else(|| not_found("User not found"))?;
    Ok(Json(json!({ "avatar_url": profile.avatar_url })))
}

/// `PUT /_matrix/client/v3/profile/{userId}/displayname`.
pub async fn put_displayname(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(user_id): Path<String>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    if auth.user_id.as_str() != user_id {
        return Err(forbidden("Cannot set displayname for another user"));
    }
    let displayname = body.get("displayname").and_then(Value::as_str);
    if let Some(dn) = displayname {
        if dn.len() > MAX_DISPLAYNAME_BYTES {
            return Err(bad_json(format!("Displayname exceeds {MAX_DISPLAYNAME_BYTES} bytes")));
        }
    }
    let uid = UserId::from(user_id.as_str());
    st.storage.set_display_name(&uid, displayname).await;
    propagate_profile_to_rooms(&st, &uid).await?;
    Ok(Json(json!({})))
}

/// `PUT /_matrix/client/v3/profile/{userId}/avatar_url`.
pub async fn put_avatar_url(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(user_id): Path<String>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    if auth.user_id.as_str() != user_id {
        return Err(forbidden("Cannot set avatar_url for another user"));
    }
    let avatar_url = body.get("avatar_url").and_then(Value::as_str);
    if let Some(av) = avatar_url {
        if av.len() > MAX_AVATAR_URL_BYTES {
            return Err(bad_json(format!("Avatar URL exceeds {MAX_AVATAR_URL_BYTES} bytes")));
        }
    }
    let uid = UserId::from(user_id.as_str());
    st.storage.set_avatar_url(&uid, avatar_url).await;
    propagate_profile_to_rooms(&st, &uid).await?;
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v3/profile/{userId}/{keyName}` (MSC4133 extended
/// profile fields, with the two well-known keys delegated).
pub async fn get_profile_field(
    State(st): State<AppState>,
    Path((user_id, key_name)): Path<(String, String)>,
) -> MatrixResult<Json<Value>> {
    let uid = UserId::from(user_id.as_str());
    let profile = st
        .storage
        .get_profile(&uid)
        .await
        .ok_or_else(|| not_found("User not found"))?;
    match key_name.as_str() {
        "displayname" => Ok(Json(json!({ "displayname": profile.displayname }))),
        "avatar_url" => Ok(Json(json!({ "avatar_url": profile.avatar_url }))),
        _ => {
            let value = extended_fields()
                .lock()
                .unwrap()
                .get(&field_key(&user_id, &key_name))
                .cloned();
            match value {
                Some(v) => Ok(Json(json!({ key_name: v }))),
                None => Err(not_found("Profile field not found")),
            }
        }
    }
}

/// `PUT /_matrix/client/v3/profile/{userId}/{keyName}`.
pub async fn put_profile_field(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((user_id, key_name)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    if auth.user_id.as_str() != user_id {
        return Err(forbidden("Cannot set profile fields for another user"));
    }
    let uid = UserId::from(user_id.as_str());
    match key_name.as_str() {
        "displayname" => {
            let dn = body.get("displayname").and_then(Value::as_str);
            if let Some(dn) = dn {
                if dn.len() > MAX_DISPLAYNAME_BYTES {
                    return Err(bad_json(format!("Displayname exceeds {MAX_DISPLAYNAME_BYTES} bytes")));
                }
            }
            st.storage.set_display_name(&uid, dn).await;
            propagate_profile_to_rooms(&st, &uid).await?;
        }
        "avatar_url" => {
            let av = body.get("avatar_url").and_then(Value::as_str);
            if let Some(av) = av {
                if av.len() > MAX_AVATAR_URL_BYTES {
                    return Err(bad_json(format!("Avatar URL exceeds {MAX_AVATAR_URL_BYTES} bytes")));
                }
            }
            st.storage.set_avatar_url(&uid, av).await;
            propagate_profile_to_rooms(&st, &uid).await?;
        }
        _ => {
            let value = body.get(&key_name).cloned().unwrap_or(Value::Null);
            extended_fields()
                .lock()
                .unwrap()
                .insert(field_key(&user_id, &key_name), value);
        }
    }
    Ok(Json(json!({})))
}

/// Rewrite the user's `m.room.member` (join) event in every joined room to carry
/// the new displayname/avatar (strix `propagateProfileToRooms`, local path).
async fn propagate_profile_to_rooms(st: &AppState, user_id: &UserId) -> MatrixResult<()> {
    let profile = st.storage.get_profile(user_id).await;
    let (displayname, avatar_url) = profile
        .map(|p| (p.displayname, p.avatar_url))
        .unwrap_or((None, None));
    let sn: &str = &st.server_name;
    let key = Some(st.signing_key.as_ref());

    for room_id in st.storage.get_rooms_for_user(user_id).await {
        let Some(room) = st.storage.get_room(&room_id).await else {
            continue;
        };
        if get_membership(&room, user_id.as_str()) != Some("join") {
            continue;
        }
        let mut content = Map::new();
        content.insert("membership".to_string(), json!("join"));
        if let Some(dn) = &displayname {
            content.insert("displayname".to_string(), json!(dn));
        }
        if let Some(av) = &avatar_url {
            content.insert("avatar_url".to_string(), json!(av));
        }

        // `room.depth` is already the *next* depth to use (send_state_event stores
        // post-increment), so seed the context with it directly — not depth + 1.
        let mut ctx = EventContext {
            depth: room.depth,
            prev_events: room.forward_extremities.iter().map(|e| e.as_str().to_string()).collect(),
            room_state: room,
        };
        send_state_event(
            &*st.storage,
            sn,
            &mut ctx,
            user_id.as_str(),
            "m.room.member",
            user_id.as_str(),
            Value::Object(content),
            key,
            None,
        )
        .await?;
    }
    Ok(())
}
