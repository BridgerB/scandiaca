//! Device management — port of strix `handlers/devices.ts` (local paths; the
//! device-list-update EDU fan-out arrives with the federation phase).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde_json::{json, Value};
use crate::extract::OptionalJson;

use crate::errors::{bad_json, forbidden, not_found, MatrixResult};
use crate::handlers::logout::LOCAL_NOTIFICATION_SETTINGS_PREFIX;
use crate::server::{AppState, AuthCtx};
use crate::types::identifiers::DeviceId;
use crate::uiaa::{require_uiaa, UiaaOutcome};

/// `GET /_matrix/client/v3/devices`.
pub async fn get_devices(State(st): State<AppState>, auth: AuthCtx) -> Json<Value> {
    let devices = st.storage.get_all_devices(&auth.user_id).await;
    Json(json!({ "devices": devices }))
}

/// `GET /_matrix/client/v3/devices/{deviceId}`.
pub async fn get_device(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(device_id): Path<String>,
) -> MatrixResult<Json<Value>> {
    let device = st
        .storage
        .get_device(&auth.user_id, &DeviceId::from(device_id.as_str()))
        .await
        .ok_or_else(|| not_found("Device not found"))?;
    Ok(Json(serde_json::to_value(device).unwrap_or(Value::Null)))
}

/// `PUT /_matrix/client/v3/devices/{deviceId}`.
pub async fn put_device(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(device_id): Path<String>,
    OptionalJson(body): OptionalJson,
) -> MatrixResult<Json<Value>> {
    let did = DeviceId::from(device_id.as_str());
    if st.storage.get_device(&auth.user_id, &did).await.is_none() {
        return Err(not_found("Device not found"));
    }
    if let Some(display_name) = body.get("display_name").and_then(Value::as_str) {
        st.storage
            .update_device_display_name(&auth.user_id, &did, display_name)
            .await;
        // A display-name change is device info that must propagate to remote
        // servers sharing a room (TestDeviceListsUpdateOverFederation).
        crate::handlers::e2ee::send_device_list_update(&st, &auth.user_id, &did).await;
    }
    Ok(Json(json!({})))
}

/// `DELETE /_matrix/client/v3/devices/{deviceId}` (UIAA-gated).
pub async fn delete_device(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(device_id): Path<String>,
    OptionalJson(body): OptionalJson,
) -> MatrixResult<Response> {
    assert_uia_user(&body, auth.user_id.as_str())?;
    if let UiaaOutcome::Challenge(c) =
        require_uiaa(&*st.storage, &body, Some(auth.user_id.as_str())).await?
    {
        return Ok((StatusCode::UNAUTHORIZED, Json(c)).into_response());
    }
    let did = DeviceId::from(device_id.as_str());
    st.storage.delete_device_session(&auth.user_id, &did).await;
    delete_local_notification_settings(&st, &auth, &device_id).await;
    Ok(Json(json!({})).into_response())
}

/// `POST /_matrix/client/v3/delete_devices` (UIAA-gated).
pub async fn delete_devices(
    State(st): State<AppState>,
    auth: AuthCtx,
    OptionalJson(body): OptionalJson,
) -> MatrixResult<Response> {
    let Some(device_ids) = body.get("devices").and_then(Value::as_array) else {
        return Err(bad_json("Missing 'devices' array"));
    };
    let device_ids: Vec<String> = device_ids
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    assert_uia_user(&body, auth.user_id.as_str())?;
    if let UiaaOutcome::Challenge(c) =
        require_uiaa(&*st.storage, &body, Some(auth.user_id.as_str())).await?
    {
        return Ok((StatusCode::UNAUTHORIZED, Json(c)).into_response());
    }
    for device_id in device_ids {
        st.storage
            .delete_device_session(&auth.user_id, &DeviceId::from(device_id.as_str()))
            .await;
        delete_local_notification_settings(&st, &auth, &device_id).await;
    }
    Ok(Json(json!({})).into_response())
}

/// Reject before UIA if the auth block names a different user (strix
/// `assertUIAUserMatchesRequester`).
fn assert_uia_user(body: &Value, user_id: &str) -> MatrixResult<()> {
    if let Some(identifier) = body.get("auth").and_then(|a| a.get("identifier")) {
        if identifier.get("type").and_then(Value::as_str) == Some("m.id.user") {
            if let Some(u) = identifier.get("user").and_then(Value::as_str) {
                let full = if u.starts_with('@') {
                    u.to_string()
                } else {
                    return Ok(());
                };
                if full != user_id {
                    return Err(forbidden("Cannot authenticate as a different user"));
                }
            }
        }
    }
    Ok(())
}

async fn delete_local_notification_settings(st: &AppState, auth: &AuthCtx, device_id: &str) {
    st.storage
        .delete_global_account_data(
            &auth.user_id,
            &format!("{LOCAL_NOTIFICATION_SETTINGS_PREFIX}{device_id}"),
        )
        .await;
}
