//! Key backup (`/room_keys`) — port of strix `handlers/key-backup.ts`.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::response::Json;
use serde_json::{json, Value};

use crate::errors::{bad_json, missing_param, not_found, MatrixError, MatrixResult};
use crate::server::{AppState, AuthCtx};
use crate::storage::{KeyBackupCount, KeyBackupVersionInfo};
use crate::types::identifiers::RoomId;

fn version_json(v: &KeyBackupVersionInfo) -> Value {
    json!({
        "version": v.version,
        "algorithm": v.algorithm,
        "auth_data": Value::Object(v.auth_data.clone()),
        "count": v.count,
        "etag": v.etag,
    })
}

fn count_json(c: &KeyBackupCount) -> Value {
    json!({ "count": c.count, "etag": c.etag })
}

fn version_param(params: &HashMap<String, String>) -> MatrixResult<String> {
    params
        .get("version")
        .cloned()
        .ok_or_else(|| missing_param("Missing required query parameter: version"))
}

async fn wrong_version(st: &AppState, auth: &AuthCtx) -> MatrixError {
    let latest = st.storage.get_key_backup_version(&auth.user_id, None).await;
    let mut extra = serde_json::Map::new();
    extra.insert(
        "current_version".to_string(),
        latest.map(|v| json!(v.version)).unwrap_or(Value::Null),
    );
    MatrixError::new("M_WRONG_ROOM_KEYS_VERSION", "Wrong backup version", 403).with_extra(extra)
}

/// `POST /_matrix/client/v3/room_keys/version`.
pub async fn post_version(
    State(st): State<AppState>,
    auth: AuthCtx,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let Some(algorithm) = body.get("algorithm").and_then(Value::as_str) else {
        return Err(missing_param("algorithm"));
    };
    let Some(auth_data) = body.get("auth_data").and_then(Value::as_object) else {
        return Err(missing_param("auth_data"));
    };
    let version = st
        .storage
        .create_key_backup_version(&auth.user_id, algorithm, auth_data.clone())
        .await;
    Ok(Json(json!({ "version": version })))
}

/// `GET /_matrix/client/v3/room_keys/version` and `.../version/{version}`.
pub async fn get_version(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(params): Path<Vec<String>>,
) -> MatrixResult<Json<Value>> {
    let version = params.first().map(String::as_str);
    let backup = st
        .storage
        .get_key_backup_version(&auth.user_id, version)
        .await
        .ok_or_else(|| not_found("No backup found"))?;
    Ok(Json(version_json(&backup)))
}

/// `PUT /_matrix/client/v3/room_keys/version/{version}`.
pub async fn put_version(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(version): Path<String>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    if let Some(v) = body.get("version").and_then(Value::as_str) {
        if v != version {
            return Err(MatrixError::new("M_INVALID_PARAM", "Version in body does not match path", 400));
        }
    }
    let existing = st
        .storage
        .get_key_backup_version(&auth.user_id, Some(&version))
        .await
        .ok_or_else(|| not_found("Backup version not found"))?;
    if body.get("algorithm").and_then(Value::as_str) != Some(existing.algorithm.as_str()) {
        return Err(MatrixError::new("M_INVALID_PARAM", "Algorithm does not match existing backup", 400));
    }
    let auth_data = body.get("auth_data").and_then(Value::as_object).cloned().unwrap_or_default();
    st.storage.update_key_backup_version(&auth.user_id, &version, auth_data).await;
    Ok(Json(json!({})))
}

/// `DELETE /_matrix/client/v3/room_keys/version/{version}`.
pub async fn delete_version(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(version): Path<String>,
) -> MatrixResult<Json<Value>> {
    if !st.storage.delete_key_backup_version(&auth.user_id, &version).await {
        return Err(not_found("Backup version not found"));
    }
    Ok(Json(json!({})))
}

// --- keys (session / room / all) -------------------------------------------

/// `PUT /_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}`.
pub async fn put_session(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((room_id, session_id)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let version = version_param(&params)?;
    if !valid_backup_data(&body) {
        return Err(bad_json("Invalid key backup data"));
    }
    match st
        .storage
        .put_key_backup_keys(&auth.user_id, &version, Some(&RoomId::from(room_id.as_str())), Some(&session_id), body)
        .await
    {
        Some(c) => Ok(Json(count_json(&c))),
        None => Err(wrong_version(&st, &auth).await),
    }
}

/// `GET /_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}`.
pub async fn get_session(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((room_id, session_id)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let version = version_param(&params)?;
    if st.storage.get_key_backup_version(&auth.user_id, Some(&version)).await.is_none() {
        return Err(not_found("Backup version not found"));
    }
    st.storage
        .get_key_backup_keys(&auth.user_id, &version, Some(&RoomId::from(room_id.as_str())), Some(&session_id))
        .await
        .map(Json)
        .ok_or_else(|| not_found("Key not found"))
}

/// `DELETE /_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}`.
pub async fn delete_session(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((room_id, session_id)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let version = version_param(&params)?;
    match st
        .storage
        .delete_key_backup_keys(&auth.user_id, &version, Some(&RoomId::from(room_id.as_str())), Some(&session_id))
        .await
    {
        Some(c) => Ok(Json(count_json(&c))),
        None => Err(not_found("Backup version not found")),
    }
}

/// `PUT /_matrix/client/v3/room_keys/keys/{roomId}`.
pub async fn put_room(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let version = version_param(&params)?;
    match st
        .storage
        .put_key_backup_keys(&auth.user_id, &version, Some(&RoomId::from(room_id.as_str())), None, body)
        .await
    {
        Some(c) => Ok(Json(count_json(&c))),
        None => Err(wrong_version(&st, &auth).await),
    }
}

/// `GET /_matrix/client/v3/room_keys/keys/{roomId}`.
pub async fn get_room(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let version = version_param(&params)?;
    if st.storage.get_key_backup_version(&auth.user_id, Some(&version)).await.is_none() {
        return Err(not_found("Backup version not found"));
    }
    let data = st
        .storage
        .get_key_backup_keys(&auth.user_id, &version, Some(&RoomId::from(room_id.as_str())), None)
        .await
        .unwrap_or_else(|| json!({ "sessions": {} }));
    Ok(Json(data))
}

/// `DELETE /_matrix/client/v3/room_keys/keys/{roomId}`.
pub async fn delete_room(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let version = version_param(&params)?;
    match st
        .storage
        .delete_key_backup_keys(&auth.user_id, &version, Some(&RoomId::from(room_id.as_str())), None)
        .await
    {
        Some(c) => Ok(Json(count_json(&c))),
        None => Err(not_found("Backup version not found")),
    }
}

/// `PUT /_matrix/client/v3/room_keys/keys`.
pub async fn put_all(
    State(st): State<AppState>,
    auth: AuthCtx,
    Query(params): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let version = version_param(&params)?;
    match st.storage.put_key_backup_keys(&auth.user_id, &version, None, None, body).await {
        Some(c) => Ok(Json(count_json(&c))),
        None => Err(wrong_version(&st, &auth).await),
    }
}

/// `GET /_matrix/client/v3/room_keys/keys`.
pub async fn get_all(
    State(st): State<AppState>,
    auth: AuthCtx,
    Query(params): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let version = version_param(&params)?;
    if st.storage.get_key_backup_version(&auth.user_id, Some(&version)).await.is_none() {
        return Err(not_found("Backup version not found"));
    }
    let data = st
        .storage
        .get_key_backup_keys(&auth.user_id, &version, None, None)
        .await
        .unwrap_or_else(|| json!({ "rooms": {} }));
    Ok(Json(data))
}

/// `DELETE /_matrix/client/v3/room_keys/keys`.
pub async fn delete_all(
    State(st): State<AppState>,
    auth: AuthCtx,
    Query(params): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let version = version_param(&params)?;
    match st.storage.delete_key_backup_keys(&auth.user_id, &version, None, None).await {
        Some(c) => Ok(Json(count_json(&c))),
        None => Err(not_found("Backup version not found")),
    }
}

/// A single-session backup body must have the four required fields.
fn valid_backup_data(body: &Value) -> bool {
    body.get("first_message_index").is_some()
        && body.get("forwarded_count").is_some()
        && body.get("is_verified").is_some()
        && body.get("session_data").is_some()
}
