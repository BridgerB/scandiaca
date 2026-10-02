//! Discovery, well-known, capabilities, auth metadata — port of strix
//! `src/handlers/discovery.ts`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use serde_json::{json, Value};

use crate::server::{AppState, AuthCtx};

/// `GET /_matrix/client/versions` — also the health check.
pub async fn versions() -> Json<Value> {
    Json(json!({
        "versions": [
            "v1.1", "v1.2", "v1.3", "v1.4", "v1.5", "v1.6", "v1.7", "v1.8",
            "v1.9", "v1.10", "v1.11", "v1.12", "v1.13", "v1.14", "v1.15",
            "v1.16", "v1.17", "v1.18"
        ],
        "unstable_features": {
            "org.matrix.msc3765.rich_topic": true,
            "org.matrix.msc3916.stable": true
        }
    }))
}

/// `GET /.well-known/matrix/server`.
pub async fn well_known_server(State(st): State<AppState>) -> Json<Value> {
    Json(json!({ "m.server": format!("{}:8448", st.server_name) }))
}

/// `GET /.well-known/matrix/client`.
pub async fn well_known_client(State(st): State<AppState>) -> Json<Value> {
    Json(json!({ "m.homeserver": { "base_url": format!("https://{}", st.server_name) } }))
}

/// `GET /.well-known/matrix/support`.
pub async fn well_known_support() -> Json<Value> {
    Json(json!({ "contacts": [] }))
}

/// `GET /.well-known/matrix/policy` — no policy server configured.
pub async fn well_known_policy_server() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "errcode": "M_NOT_FOUND", "error": "No policy server configured" })),
    )
        .into_response()
}

/// `GET /_matrix/client/v1/auth_metadata` — SSO/OIDC not configured.
pub async fn auth_metadata() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "errcode": "M_UNRECOGNIZED",
            "error": "SSO/OIDC is not configured on this server"
        })),
    )
        .into_response()
}

/// `GET /_matrix/client/v3/capabilities` (requires auth — 401 without a token).
pub async fn capabilities(_auth: AuthCtx) -> Json<Value> {
    Json(json!({
        "capabilities": {
            "m.change_password": { "enabled": true },
            "m.room_versions": {
                "default": "10",
                "available": {
                    "1": "stable", "2": "stable", "3": "stable", "4": "stable",
                    "5": "stable", "6": "stable", "7": "stable", "8": "stable",
                    "9": "stable", "10": "stable", "11": "stable", "12": "stable"
                }
            },
            "m.profile_fields": { "enabled": true }
        }
    }))
}
