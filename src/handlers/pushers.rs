//! Pushers — port of strix `handlers/pushers.ts`.

use axum::extract::State;
use axum::response::Json;
use serde_json::{json, Value};

use crate::errors::{bad_json, missing_param, MatrixResult};
use crate::server::{AppState, AuthCtx};
use crate::types::push::Pusher;

/// `GET /_matrix/client/v3/pushers`.
pub async fn get_pushers(State(st): State<AppState>, auth: AuthCtx) -> Json<Value> {
    let pushers: Vec<Value> = st
        .storage
        .get_pushers(&auth.user_id)
        .await
        .into_iter()
        .map(|mut p| {
            // access_token is internal and must not be exposed to clients.
            p.access_token = None;
            serde_json::to_value(p).unwrap_or(Value::Null)
        })
        .collect();
    Json(json!({ "pushers": pushers }))
}

/// `POST /_matrix/client/v3/pushers/set`.
pub async fn set_pusher(
    State(st): State<AppState>,
    auth: AuthCtx,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let pushkey = body.get("pushkey").and_then(Value::as_str).ok_or_else(|| missing_param("pushkey"))?;
    let app_id = body.get("app_id").and_then(Value::as_str).ok_or_else(|| missing_param("app_id"))?;

    // kind: null deletes the pusher.
    if body.get("kind").is_some_and(Value::is_null) {
        st.storage.delete_pusher(&auth.user_id, app_id, pushkey).await;
        return Ok(Json(json!({})));
    }
    let kind = body.get("kind").and_then(Value::as_str).ok_or_else(|| missing_param("kind"))?;
    if kind != "http" && kind != "email" {
        return Err(bad_json("kind must be 'http', 'email', or null"));
    }
    let app_display_name = body.get("app_display_name").and_then(Value::as_str).ok_or_else(|| missing_param("app_display_name"))?;
    let device_display_name = body.get("device_display_name").and_then(Value::as_str).ok_or_else(|| missing_param("device_display_name"))?;
    let lang = body.get("lang").and_then(Value::as_str).ok_or_else(|| missing_param("lang"))?;
    let data = body.get("data").and_then(Value::as_object).ok_or_else(|| missing_param("data"))?;
    if kind == "http" && data.get("url").and_then(Value::as_str).is_none() {
        return Err(bad_json("HTTP pushers require data.url"));
    }

    let pusher = Pusher {
        pushkey: pushkey.to_string(),
        kind: Some(kind.to_string()),
        app_id: app_id.to_string(),
        app_display_name: app_display_name.to_string(),
        device_display_name: device_display_name.to_string(),
        profile_tag: body.get("profile_tag").and_then(Value::as_str).map(String::from),
        lang: lang.to_string(),
        data: serde_json::from_value(Value::Object(data.clone())).unwrap_or_default(),
        append: body.get("append").and_then(Value::as_bool),
        access_token: Some(auth.access_token.as_str().to_string()),
    };

    if body.get("append").and_then(Value::as_bool) != Some(true) {
        st.storage.delete_pusher_by_key(app_id, pushkey).await;
    }
    st.storage.set_pusher(&auth.user_id, pusher).await;
    Ok(Json(json!({})))
}
