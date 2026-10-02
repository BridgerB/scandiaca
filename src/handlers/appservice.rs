//! Appservice client-facing endpoints — port of strix `handlers/appservice.ts`.

use std::sync::OnceLock;

use axum::extract::{Path, State};
use axum::http::request::Parts;
use axum::response::Json;
use serde_json::{json, Value};

use crate::appservice::registration::find_appservice_by_token;
use crate::errors::{forbidden, not_found, MatrixError, MatrixResult};
use crate::server::{extract_access_token, now_ms, AppState};

fn http() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("build appservice ping http client")
    })
}

/// `POST /_matrix/client/v1/appservice/{appserviceId}/ping` — verify
/// connectivity to the appservice by POSTing to its `/_matrix/app/v1/ping`.
pub async fn ping(
    State(st): State<AppState>,
    Path(appservice_id): Path<String>,
    parts: Parts,
    _body: Option<Json<Value>>,
) -> MatrixResult<Json<Value>> {
    let token = extract_access_token(&parts)?;
    let reg = find_appservice_by_token(&token, &st.registrations)
        .ok_or_else(|| forbidden("Invalid as_token"))?;
    if reg.id != appservice_id {
        return Err(forbidden("as_token does not match appservice ID"));
    }
    if reg.url.is_empty() {
        return Err(not_found("Appservice has no URL configured"));
    }

    let url = format!("{}/_matrix/app/v1/ping", reg.url.trim_end_matches('/'));
    let start = now_ms();
    let resp = http()
        .post(&url)
        .header("Authorization", format!("Bearer {}", reg.hs_token))
        .json(&json!({ "transaction_id": format!("ping_{}", now_ms()) }))
        .send()
        .await
        .map_err(|e| MatrixError::new("M_CONNECTION_FAILED", format!("Ping failed: {e}"), 502))?;
    if resp.status().as_u16() >= 400 {
        return Err(MatrixError::new(
            "M_CONNECTION_FAILED",
            format!("Appservice returned status {}", resp.status()),
            502,
        ));
    }
    Ok(Json(json!({ "duration_ms": now_ms() - start })))
}
