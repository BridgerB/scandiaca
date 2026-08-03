//! Small self-contained endpoints — ports of strix `handlers/{voip,thirdparty,
//! openid}.ts`.

use axum::extract::{Path, State};
use axum::response::Json;
use serde_json::{json, Value};

use crate::crypto::generate_token;
use crate::errors::{forbidden, not_found, MatrixResult};
use crate::server::{now_ms, AppState, AuthCtx};

/// `GET /_matrix/client/v3/voip/turnServer`.
pub async fn turn_server(auth: AuthCtx) -> Json<Value> {
    let ttl: i64 = std::env::var("TURN_TTL").ok().and_then(|s| s.parse().ok()).unwrap_or(86400);
    let Ok(uris_env) = std::env::var("TURN_URIS") else {
        return Json(json!({ "username": "", "password": "", "uris": [], "ttl": 86400 }));
    };
    let uris: Vec<String> = uris_env.split(',').map(|u| u.trim().to_string()).collect();

    if let Ok(secret) = std::env::var("TURN_SHARED_SECRET") {
        // coturn use-auth-secret: username = "<expiry>:<user>", password = base64(HMAC-SHA1).
        let expiry = now_ms() / 1000 + ttl;
        let username = format!("{expiry}:{}", auth.user_id.as_str());
        let password = hmac_sha1_base64(secret.as_bytes(), username.as_bytes());
        return Json(json!({ "username": username, "password": password, "uris": uris, "ttl": ttl }));
    }
    if let (Ok(u), Ok(p)) = (std::env::var("TURN_USERNAME"), std::env::var("TURN_PASSWORD")) {
        return Json(json!({ "username": u, "password": p, "uris": uris, "ttl": ttl }));
    }
    Json(json!({ "username": "", "password": "", "uris": uris, "ttl": ttl }))
}

/// `GET /_matrix/client/v3/thirdparty/protocols` — no appservices yet → empty.
pub async fn thirdparty_protocols() -> Json<Value> {
    Json(json!({}))
}

/// `GET /_matrix/client/v3/thirdparty/protocol/{protocol}` — not found.
pub async fn thirdparty_protocol(Path(_protocol): Path<String>) -> MatrixResult<Json<Value>> {
    Err(not_found("Protocol not found"))
}

/// `POST /_matrix/client/v3/user/{userId}/openid/request_token`.
pub async fn openid_request_token(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(user_id): Path<String>,
) -> MatrixResult<Json<Value>> {
    if auth.user_id.as_str() != user_id {
        return Err(forbidden("Can only request tokens for yourself"));
    }
    let token = generate_token();
    let expires_in = 3600i64;
    st.storage
        .store_open_id_token(&token, &auth.user_id, now_ms() + expires_in * 1000)
        .await;
    Ok(Json(json!({
        "access_token": token,
        "token_type": "Bearer",
        "matrix_server_name": st.server_name.as_ref(),
        "expires_in": expires_in,
    })))
}

/// HMAC-SHA1 → base64 (coturn `use-auth-secret` credential).
fn hmac_sha1_base64(key: &[u8], msg: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg);
    STANDARD.encode(mac.finalize().into_bytes())
}
