//! Token refresh — port of strix `handlers/refresh.ts`.

use axum::extract::State;
use axum::response::Json;
use serde_json::{json, Value};

use crate::crypto::generate_token;
use crate::errors::{bad_json, unknown_token, MatrixResult};
use crate::server::{now_ms, AppState};
use crate::types::identifiers::{AccessToken, RefreshToken};

/// `POST /_matrix/client/v3/refresh`.
pub async fn refresh(
    State(st): State<AppState>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let Some(refresh_token) = body.get("refresh_token").and_then(Value::as_str) else {
        return Err(bad_json("Missing 'refresh_token' field"));
    };
    let session = st
        .storage
        .get_session_by_refresh_token(&RefreshToken::from(refresh_token))
        .await
        .ok_or_else(|| unknown_token("Unknown refresh token", false))?;

    let new_access = generate_token();
    let new_refresh = generate_token();
    let expires_at = now_ms() + 300_000;

    let updated = st
        .storage
        .rotate_token(
            &session.access_token,
            &AccessToken::from(new_access.as_str()),
            Some(&RefreshToken::from(new_refresh.as_str())),
            Some(expires_at),
        )
        .await;
    if updated.is_none() {
        return Err(unknown_token("Session no longer exists", false));
    }

    Ok(Json(json!({
        "access_token": new_access,
        "refresh_token": new_refresh,
        "expires_in_ms": 300_000,
    })))
}
