//! Admin lock/suspend/whois — port of strix `handlers/admin.ts` + the whois
//! from `threepid-verify.ts`. Lock/suspend state is process-local (strix keeps
//! it in in-memory maps; there are no admin roles, so only self-target).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use axum::extract::{Path, State};
use axum::response::Json;
use serde_json::{json, Value};

use crate::errors::{forbidden, not_found, MatrixResult};
use crate::extract::OptionalJson;
use crate::server::{AppState, AuthCtx};
use crate::types::identifiers::UserId;

fn locked_users() -> &'static Mutex<HashMap<String, bool>> {
    static M: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}
fn suspended_users() -> &'static Mutex<HashMap<String, bool>> {
    static M: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

async fn require_self_and_exists(st: &AppState, auth: &AuthCtx, target: &str, action: &str) -> MatrixResult<()> {
    if auth.user_id.as_str() != target {
        return Err(forbidden(format!("Only server admins can {action}")));
    }
    if st.storage.get_user_by_id(&UserId::from(target)).await.is_none() {
        return Err(not_found("User not found"));
    }
    Ok(())
}

/// `PUT /_matrix/client/v1/admin/lock/{userId}`.
pub async fn put_lock(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(user_id): Path<String>,
    OptionalJson(body): OptionalJson,
) -> MatrixResult<Json<Value>> {
    require_self_and_exists(&st, &auth, &user_id, "lock other users").await?;
    let locked = body.get("locked").and_then(Value::as_bool).unwrap_or(false);
    locked_users().lock().unwrap().insert(user_id, locked);
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v1/admin/lock/{userId}`.
pub async fn get_lock(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(user_id): Path<String>,
) -> MatrixResult<Json<Value>> {
    require_self_and_exists(&st, &auth, &user_id, "view lock status").await?;
    let locked = locked_users().lock().unwrap().get(&user_id).copied().unwrap_or(false);
    Ok(Json(json!({ "locked": locked })))
}

/// `PUT /_matrix/client/v1/admin/suspend/{userId}`.
pub async fn put_suspend(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(user_id): Path<String>,
    OptionalJson(body): OptionalJson,
) -> MatrixResult<Json<Value>> {
    require_self_and_exists(&st, &auth, &user_id, "suspend other users").await?;
    let suspended = body.get("suspended").and_then(Value::as_bool).unwrap_or(false);
    suspended_users().lock().unwrap().insert(user_id, suspended);
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v1/admin/suspend/{userId}`.
pub async fn get_suspend(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(user_id): Path<String>,
) -> MatrixResult<Json<Value>> {
    require_self_and_exists(&st, &auth, &user_id, "view suspend status").await?;
    let suspended = suspended_users().lock().unwrap().get(&user_id).copied().unwrap_or(false);
    Ok(Json(json!({ "suspended": suspended })))
}

/// `GET /_matrix/client/v3/admin/whois/{userId}`.
pub async fn whois(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(user_id): Path<String>,
) -> MatrixResult<Json<Value>> {
    if auth.user_id.as_str() != user_id {
        return Err(forbidden("Cannot query another user"));
    }
    let mut devices = serde_json::Map::new();
    for d in st.storage.get_all_devices(&UserId::from(user_id.as_str())).await {
        devices.insert(
            d.device_id.as_str().to_string(),
            json!({ "sessions": [{ "connections": [] }] }),
        );
    }
    Ok(Json(json!({ "user_id": user_id, "devices": devices })))
}
