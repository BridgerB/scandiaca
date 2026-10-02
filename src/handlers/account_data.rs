//! Account data + room tags — port of strix `handlers/account-data.ts`.

use axum::extract::{Path, State};
use axum::response::Json;
use serde_json::{json, Map, Value};

use crate::errors::{bad_json, forbidden, not_found, MatrixResult};
use crate::server::{AppState, AuthCtx};
use crate::types::identifiers::{RoomId, UserId};

/// Types clients may not set/delete via the account-data endpoints.
const FORBIDDEN_TYPES: &[&str] = &["m.fully_read", "m.push_rules"];

/// True if `content` is an empty JSON object `{}`.
fn is_empty_object(content: &Map<String, Value>) -> bool {
    content.is_empty()
}

fn require_self(auth: &AuthCtx, user_id: &str, action: &str) -> MatrixResult<()> {
    if auth.user_id.as_str() != user_id {
        return Err(forbidden(format!("Cannot {action} another user's account data")));
    }
    Ok(())
}

/// `GET /_matrix/client/v3/user/{userId}/account_data/{type}`.
pub async fn get_global(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((user_id, data_type)): Path<(String, String)>,
) -> MatrixResult<Json<Value>> {
    require_self(&auth, &user_id, "access")?;
    let uid = UserId::from(user_id.as_str());
    match st.storage.get_global_account_data(&uid, &data_type).await {
        // MSC3391: an empty-object tombstone is treated as absent.
        Some(data) if !is_empty_object(&data) => Ok(Json(Value::Object(data))),
        _ => Err(not_found("Account data not found")),
    }
}

/// `PUT /_matrix/client/v3/user/{userId}/account_data/{type}`.
pub async fn put_global(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((user_id, data_type)): Path<(String, String)>,
    Json(content): Json<Value>,
) -> MatrixResult<Json<Value>> {
    require_self(&auth, &user_id, "set")?;
    if FORBIDDEN_TYPES.contains(&data_type.as_str()) {
        return Err(bad_json(format!("Cannot set {data_type} via this endpoint")));
    }
    let uid = UserId::from(user_id.as_str());
    let content = content.as_object().cloned().unwrap_or_default();
    if is_empty_object(&content) {
        // MSC3391: PUT with an empty content dict deletes the type.
        st.storage.delete_global_account_data(&uid, &data_type).await;
    } else {
        st.storage
            .set_global_account_data(&uid, &data_type, content)
            .await;
    }
    Ok(Json(json!({})))
}

/// `DELETE /_matrix/client/v3/user/{userId}/account_data/{type}` (MSC3391).
pub async fn delete_global(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((user_id, data_type)): Path<(String, String)>,
) -> MatrixResult<Json<Value>> {
    require_self(&auth, &user_id, "delete")?;
    if FORBIDDEN_TYPES.contains(&data_type.as_str()) {
        return Err(bad_json(format!("Cannot delete {data_type} via this endpoint")));
    }
    let uid = UserId::from(user_id.as_str());
    st.storage.delete_global_account_data(&uid, &data_type).await;
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}`.
pub async fn get_room(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((user_id, room_id, data_type)): Path<(String, String, String)>,
) -> MatrixResult<Json<Value>> {
    require_self(&auth, &user_id, "access")?;
    let uid = UserId::from(user_id.as_str());
    let rid = RoomId::from(room_id.as_str());
    match st.storage.get_room_account_data(&uid, &rid, &data_type).await {
        Some(data) if !is_empty_object(&data) => Ok(Json(Value::Object(data))),
        _ => Err(not_found("Account data not found")),
    }
}

/// `PUT /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}`.
pub async fn put_room(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((user_id, room_id, data_type)): Path<(String, String, String)>,
    Json(content): Json<Value>,
) -> MatrixResult<Json<Value>> {
    require_self(&auth, &user_id, "set")?;
    if FORBIDDEN_TYPES.contains(&data_type.as_str()) {
        return Err(bad_json(format!("Cannot set {data_type} via this endpoint")));
    }
    let uid = UserId::from(user_id.as_str());
    let rid = RoomId::from(room_id.as_str());
    let content = content.as_object().cloned().unwrap_or_default();
    if is_empty_object(&content) {
        st.storage
            .delete_room_account_data(&uid, &rid, &data_type)
            .await;
    } else {
        st.storage
            .set_room_account_data(&uid, &rid, &data_type, content)
            .await;
    }
    Ok(Json(json!({})))
}

/// `DELETE /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}`.
pub async fn delete_room(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((user_id, room_id, data_type)): Path<(String, String, String)>,
) -> MatrixResult<Json<Value>> {
    require_self(&auth, &user_id, "delete")?;
    if FORBIDDEN_TYPES.contains(&data_type.as_str()) {
        return Err(bad_json(format!("Cannot delete {data_type} via this endpoint")));
    }
    let uid = UserId::from(user_id.as_str());
    let rid = RoomId::from(room_id.as_str());
    st.storage
        .delete_room_account_data(&uid, &rid, &data_type)
        .await;
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v3/user/{userId}/rooms/{roomId}/tags`.
pub async fn get_tags(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((user_id, room_id)): Path<(String, String)>,
) -> MatrixResult<Json<Value>> {
    require_self(&auth, &user_id, "access")?;
    let uid = UserId::from(user_id.as_str());
    let rid = RoomId::from(room_id.as_str());
    let tags = st
        .storage
        .get_room_account_data(&uid, &rid, "m.tag")
        .await
        .and_then(|d| d.get("tags").cloned())
        .unwrap_or_else(|| json!({}));
    Ok(Json(json!({ "tags": tags })))
}

/// `PUT /_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag}`.
pub async fn put_tag(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((user_id, room_id, tag)): Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    require_self(&auth, &user_id, "set")?;
    if tag.len() > 255 {
        return Err(bad_json("Tag name exceeds 255 bytes"));
    }
    let uid = UserId::from(user_id.as_str());
    let rid = RoomId::from(room_id.as_str());
    let mut tags = current_tags(&st, &uid, &rid).await;
    let mut tag_data = Map::new();
    if let Some(order) = body.get("order") {
        tag_data.insert("order".to_string(), order.clone());
    }
    tags.insert(tag, Value::Object(tag_data));
    let mut content = Map::new();
    content.insert("tags".to_string(), Value::Object(tags));
    st.storage
        .set_room_account_data(&uid, &rid, "m.tag", content)
        .await;
    Ok(Json(json!({})))
}

/// `DELETE /_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag}`.
pub async fn delete_tag(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((user_id, room_id, tag)): Path<(String, String, String)>,
) -> MatrixResult<Json<Value>> {
    require_self(&auth, &user_id, "delete")?;
    let uid = UserId::from(user_id.as_str());
    let rid = RoomId::from(room_id.as_str());
    let mut tags = current_tags(&st, &uid, &rid).await;
    tags.remove(&tag);
    let mut content = Map::new();
    content.insert("tags".to_string(), Value::Object(tags));
    st.storage
        .set_room_account_data(&uid, &rid, "m.tag", content)
        .await;
    Ok(Json(json!({})))
}

async fn current_tags(st: &AppState, uid: &UserId, rid: &RoomId) -> Map<String, Value> {
    st.storage
        .get_room_account_data(uid, rid, "m.tag")
        .await
        .and_then(|d| d.get("tags").and_then(Value::as_object).cloned())
        .unwrap_or_default()
}
