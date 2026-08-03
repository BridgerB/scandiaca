//! Cross-signing — port of strix `handlers/cross-signing.ts`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde_json::{json, Map, Value};

use crate::canonical_json::canonical_json;
use crate::crypto::generate_session_id;
use crate::extract::OptionalJson;
use crate::crypto_utils::verify_password;
use crate::errors::{bad_json, forbidden, MatrixResult};
use crate::server::{AppState, AuthCtx};
use crate::types::e2ee::{CrossSigningKey, CrossSigningKeys};

/// `POST /_matrix/client/v3/keys/device_signing/upload` (MSC3967: UIA only when
/// replacing an existing cross-signing key).
pub async fn post_device_signing_upload(
    State(st): State<AppState>,
    auth: AuthCtx,
    OptionalJson(body): OptionalJson,
) -> MatrixResult<Response> {
    let user_id = auth.user_id.as_str();
    let existing = st.storage.get_cross_signing_keys(&auth.user_id).await;
    let is_setup = existing.master_key.is_some();

    let provided = |k: &str| body.get(k).cloned().filter(|v| !v.is_null());
    let existing_json = |k: &Option<CrossSigningKey>| {
        k.as_ref().map(|v| canonical_json(&serde_json::to_value(v).unwrap_or(Value::Null)))
    };

    let mut keys_differ = false;
    for (name, stored) in [
        ("master_key", existing_json(&existing.master_key)),
        ("self_signing_key", existing_json(&existing.self_signing_key)),
        ("user_signing_key", existing_json(&existing.user_signing_key)),
    ] {
        if let Some(p) = provided(name) {
            let p_canon = canonical_json(&p);
            if stored.as_deref() != Some(p_canon.as_str()) {
                keys_differ = true;
                break;
            }
        }
    }

    // Idempotent re-upload (or empty body): no change, no UIA.
    if !keys_differ {
        return Ok(Json(json!({})).into_response());
    }

    // Replacing an existing key requires UIA (password flow only).
    if is_setup {
        let auth_block = body.get("auth").filter(|v| !v.is_null());
        let Some(auth_block) = auth_block else {
            let session_id = generate_session_id();
            st.storage.create_uiaa_session(&session_id).await;
            return Ok((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "flows": [{ "stages": ["m.login.password"] }],
                    "params": {},
                    "session": session_id,
                })),
            )
                .into_response());
        };
        if auth_block.get("type").and_then(Value::as_str) == Some("m.login.password") {
            let session = auth_block.get("session").and_then(Value::as_str);
            if session.is_none() || st.storage.get_uiaa_session(session.unwrap()).await.is_none() {
                return Err(forbidden("Unknown session"));
            }
            let account = st.storage.get_user_by_id(&auth.user_id).await.ok_or_else(|| forbidden("User not found"))?;
            let pw = auth_block.get("password").and_then(Value::as_str).unwrap_or("").to_string();
            let valid = tokio::task::spawn_blocking(move || verify_password(&pw, &account.password_hash))
                .await
                .expect("verify task");
            if !valid {
                return Err(forbidden("Invalid password"));
            }
            st.storage.delete_uiaa_session(session.unwrap()).await;
        } else {
            return Err(forbidden("Unsupported auth type"));
        }
    }

    // Validate key user_ids and device-id collisions.
    let devices = st.storage.get_all_devices(&auth.user_id).await;
    let device_ids: std::collections::HashSet<&str> = devices.iter().map(|d| d.device_id.as_str()).collect();

    let mut to_store = CrossSigningKeys::default();
    for (name, slot) in [
        ("master_key", 0),
        ("self_signing_key", 1),
        ("user_signing_key", 2),
    ] {
        let Some(v) = provided(name) else { continue };
        let key: CrossSigningKey = serde_json::from_value(v)
            .map_err(|_| bad_json(format!("{name} is malformed")))?;
        if key.user_id.as_str() != user_id {
            return Err(bad_json(format!("{name} user_id does not match authenticated user")));
        }
        for key_id in key.keys.keys() {
            if let Some(tag) = key_id.split(':').nth(1) {
                if device_ids.contains(tag) {
                    return Err(forbidden(format!("Key ID {key_id} collides with an existing device ID")));
                }
            }
        }
        match slot {
            0 => to_store.master_key = Some(key),
            1 => to_store.self_signing_key = Some(key),
            _ => to_store.user_signing_key = Some(key),
        }
    }

    st.storage.set_cross_signing_keys(&auth.user_id, to_store).await;
    Ok(Json(json!({})).into_response())
}

/// `POST /_matrix/client/v3/keys/signatures/upload`.
pub async fn post_signatures_upload(
    State(st): State<AppState>,
    auth: AuthCtx,
    OptionalJson(body): OptionalJson,
) -> MatrixResult<Json<Value>> {
    // body: { userId: { keyId: <signed key object> } }
    let mut signatures: std::collections::BTreeMap<String, std::collections::BTreeMap<String, Map<String, Value>>> =
        std::collections::BTreeMap::new();
    if let Some(obj) = body.as_object() {
        for (user, keys) in obj {
            if let Some(keys) = keys.as_object() {
                let inner = keys
                    .iter()
                    .filter_map(|(k, v)| v.as_object().map(|o| (k.clone(), o.clone())))
                    .collect();
                signatures.insert(user.clone(), inner);
            }
        }
    }
    let failures = st.storage.store_cross_signing_signatures(&auth.user_id, signatures).await;

    // Serialize failures: { user: { keyId: { errcode, error } } }.
    let mut out = Map::new();
    for (user, keys) in failures {
        let mut inner = Map::new();
        for (key_id, f) in keys {
            inner.insert(key_id, json!({ "errcode": f.errcode, "error": f.error }));
        }
        if !inner.is_empty() {
            out.insert(user, Value::Object(inner));
        }
    }
    Ok(Json(json!({ "failures": out })))
}
