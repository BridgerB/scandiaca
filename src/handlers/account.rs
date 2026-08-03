//! Account management — port of strix `handlers/account.ts` (change password,
//! deactivate) + `getRegisterAvailable` from `threepid-verify.ts`.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde_json::{json, Value};
use crate::extract::OptionalJson;

use crate::crypto_utils::hash_password;
use crate::errors::{bad_json, invalid_username, user_in_use, MatrixResult};
use crate::server::{AppState, AuthCtx};
use crate::uiaa::{require_uiaa, UiaaOutcome};

const MIN_PASSWORD_LENGTH: usize = 8;

fn is_username_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '=' | '-' | '/')
}

/// `POST /_matrix/client/v3/account/password`.
pub async fn change_password(
    State(st): State<AppState>,
    auth: AuthCtx,
    OptionalJson(body): OptionalJson,
) -> MatrixResult<Response> {
    if let UiaaOutcome::Challenge(c) =
        require_uiaa(&*st.storage, &body, Some(auth.user_id.as_str())).await?
    {
        return Ok((StatusCode::UNAUTHORIZED, Json(c)).into_response());
    }

    let Some(new_password) = body.get("new_password").and_then(Value::as_str) else {
        return Err(bad_json("Missing 'new_password' field"));
    };
    if new_password.len() < MIN_PASSWORD_LENGTH {
        return Err(bad_json(format!(
            "Password must be at least {MIN_PASSWORD_LENGTH} characters"
        )));
    }

    let pw = new_password.to_string();
    let password_hash = tokio::task::spawn_blocking(move || hash_password(&pw))
        .await
        .expect("hash task");
    st.storage
        .update_password(&auth.user_id, &password_hash)
        .await;

    // logout_devices defaults to true: drop every session except the current.
    let logout_devices = body.get("logout_devices").and_then(Value::as_bool) != Some(false);
    if logout_devices {
        let current = auth.access_token.as_str();
        for session in st.storage.get_sessions_by_user(&auth.user_id).await {
            if session.access_token.as_str() != current {
                st.storage.delete_session(&session.access_token).await;
            }
        }
        for pusher in st.storage.get_pushers(&auth.user_id).await {
            if let Some(tok) = &pusher.access_token {
                if tok.as_str() != current {
                    st.storage
                        .delete_pusher(&auth.user_id, &pusher.app_id, &pusher.pushkey)
                        .await;
                }
            }
        }
    }

    Ok(Json(json!({})).into_response())
}

/// `POST /_matrix/client/v3/account/deactivate`.
pub async fn deactivate(
    State(st): State<AppState>,
    auth: AuthCtx,
    OptionalJson(body): OptionalJson,
) -> MatrixResult<Response> {
    if let UiaaOutcome::Challenge(c) =
        require_uiaa(&*st.storage, &body, Some(auth.user_id.as_str())).await?
    {
        return Ok((StatusCode::UNAUTHORIZED, Json(c)).into_response());
    }
    st.storage.deactivate_user(&auth.user_id).await;
    Ok(Json(json!({ "id_server_unbind_result": "no-support" })).into_response())
}

/// `GET /_matrix/client/v3/register/available`.
pub async fn register_available(
    State(st): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let Some(username) = params.get("username") else {
        return Err(bad_json("Missing 'username' query parameter"));
    };
    let localpart = username.to_lowercase();
    if localpart.is_empty() || !localpart.chars().all(is_username_char) {
        return Err(invalid_username(
            "Username can only contain lowercase letters, digits, and ._=-/",
        ));
    }
    if st.storage.get_user_by_localpart(&localpart).await.is_some() {
        return Err(user_in_use("User ID already taken"));
    }
    Ok(Json(json!({ "available": true })))
}

/// `GET /_matrix/client/v1/register/m.login.registration_token/validity` — we
/// don't support registration tokens.
pub async fn registration_token_validity() -> Json<Value> {
    Json(json!({ "valid": false }))
}
