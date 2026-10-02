//! Federation E2EE key queries — port of strix `handlers/federation/keys.ts`
//! (the `postFederationUserDevices`, `postFederationKeysQuery`,
//! `postFederationKeysClaim` handlers) and `federation/devices.ts`.
//!
//! A remote server asks us for our local users' device keys / one-time keys.
//! These mirror the CS-API `keys/query` and `keys/claim` handlers in
//! `handlers/e2ee.rs`, but are guarded by X-Matrix federation auth instead of a
//! user access token, and shape the response the way Synapse's
//! `on_federation_query_client_keys` / `on_claim_client_keys` do.

use axum::extract::{Path, State};
use axum::response::Json;
use serde_json::{json, Map, Value};

use crate::errors::{not_found, MatrixResult};
use crate::handlers::e2ee::with_display_name;
use crate::middleware::federation_auth::FedAuthBody;
use crate::server::AppState;
use crate::types::identifiers::{DeviceId, UserId};

/// `GET /_matrix/federation/v1/user/devices/{userId}` — a remote server queries
/// the full device list of one of our local users (Synapse
/// `on_query_user_devices`).
pub async fn get_user_devices(
    State(st): State<AppState>,
    Path(user_id): Path<String>,
    _auth: FedAuthBody,
) -> MatrixResult<Json<Value>> {
    let uid = UserId::from(user_id.as_str());
    if st.storage.get_user_by_id(&uid).await.is_none() {
        return Err(not_found("User not found"));
    }

    let mut devices = Vec::new();
    for device in st.storage.get_all_devices(&uid).await {
        if let Some(keys) = st.storage.get_device_keys(&uid, &device.device_id).await {
            let mut entry = Map::new();
            entry.insert("device_id".to_string(), json!(device.device_id.as_str()));
            entry.insert("keys".to_string(), serde_json::to_value(keys).unwrap_or(Value::Null));
            if let Some(name) = device.display_name {
                entry.insert("device_display_name".to_string(), json!(name));
            }
            devices.push(Value::Object(entry));
        }
    }

    let cross = st.storage.get_cross_signing_keys(&uid).await;
    let mut body = Map::new();
    body.insert("user_id".to_string(), json!(user_id));
    body.insert("stream_id".to_string(), json!(0));
    body.insert("devices".to_string(), Value::Array(devices));
    if let Some(mk) = cross.master_key {
        body.insert("master_key".to_string(), serde_json::to_value(mk).unwrap_or(Value::Null));
    }
    if let Some(ssk) = cross.self_signing_key {
        body.insert("self_signing_key".to_string(), serde_json::to_value(ssk).unwrap_or(Value::Null));
    }
    Ok(Json(Value::Object(body)))
}

/// `POST /_matrix/federation/v1/user/keys/query` — remote server asks for the
/// device keys of one or more of our local users (Synapse
/// `on_federation_query_client_keys`). Each device carries
/// `unsigned.device_display_name`.
pub async fn post_keys_query(
    State(st): State<AppState>,
    auth: FedAuthBody,
) -> MatrixResult<Json<Value>> {
    let body = auth.body;
    let mut device_keys = Map::new();
    let mut master_keys = Map::new();
    let mut self_signing_keys = Map::new();

    if let Some(request) = body.get("device_keys").and_then(Value::as_object) {
        for (target, device_ids) in request {
            let uid = UserId::from(target.as_str());
            let ids = device_ids.as_array().cloned().unwrap_or_default();

            let mut user_devices = Map::new();
            if ids.is_empty() {
                for (did, keys) in st.storage.get_all_device_keys(&uid).await {
                    user_devices.insert(
                        did.as_str().to_string(),
                        with_display_name(&st, &uid, &did, keys).await,
                    );
                }
            } else {
                for did_val in &ids {
                    let Some(did_str) = did_val.as_str() else { continue };
                    let did = DeviceId::from(did_str);
                    if let Some(keys) = st.storage.get_device_keys(&uid, &did).await {
                        user_devices.insert(
                            did_str.to_string(),
                            with_display_name(&st, &uid, &did, keys).await,
                        );
                    }
                }
            }
            device_keys.insert(target.clone(), Value::Object(user_devices));

            let cross = st.storage.get_cross_signing_keys(&uid).await;
            if let Some(mk) = cross.master_key {
                master_keys.insert(target.clone(), serde_json::to_value(mk).unwrap_or(Value::Null));
            }
            if let Some(ssk) = cross.self_signing_key {
                self_signing_keys
                    .insert(target.clone(), serde_json::to_value(ssk).unwrap_or(Value::Null));
            }
        }
    }

    let mut resp = json!({ "device_keys": device_keys });
    if !master_keys.is_empty() {
        resp["master_keys"] = Value::Object(master_keys);
    }
    if !self_signing_keys.is_empty() {
        resp["self_signing_keys"] = Value::Object(self_signing_keys);
    }
    Ok(Json(resp))
}

/// `POST /_matrix/federation/v1/user/keys/claim` — remote server claims one OTK
/// per requested (user, device, algorithm) from our local users (Synapse
/// `on_claim_client_keys`).
pub async fn post_keys_claim(
    State(st): State<AppState>,
    auth: FedAuthBody,
) -> MatrixResult<Json<Value>> {
    let body = auth.body;
    let mut one_time_keys = Map::new();
    if let Some(request) = body.get("one_time_keys").and_then(Value::as_object) {
        for (target, devices) in request {
            let uid = UserId::from(target.as_str());
            let Some(devices) = devices.as_object() else { continue };
            let mut user_keys = Map::new();
            for (device_id, algorithm) in devices {
                let Some(algo) = algorithm.as_str() else { continue };
                if let Some(claimed) = st
                    .storage
                    .claim_one_time_key(&uid, &DeviceId::from(device_id.as_str()), algo)
                    .await
                {
                    let mut km = Map::new();
                    km.insert(claimed.key_id.as_str().to_string(), claimed.key);
                    user_keys.insert(device_id.clone(), Value::Object(km));
                }
            }
            if !user_keys.is_empty() {
                one_time_keys.insert(target.clone(), Value::Object(user_keys));
            }
        }
    }
    Ok(Json(json!({ "one_time_keys": one_time_keys })))
}
