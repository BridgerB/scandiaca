//! Registration, login, and whoami — ports of strix `register.ts` / `login.ts` /
//! `auth-shared.ts` (UIAA dummy flow; password login). Push-rule seeding,
//! guest registration, token/SSO/appservice login arrive in later phases.

use std::collections::HashMap;
use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde_json::{json, Value};

use crate::crypto::{generate_device_id, generate_token};
use crate::extract::OptionalJson;
use crate::crypto_utils::{hash_password, verify_password};
use crate::errors::{
    bad_json, forbidden, invalid_param, invalid_username, user_in_use, weak_password, MatrixResult,
};
use crate::middleware::rate_limit::check_rate_limit;
use crate::server::{now_ms, AppState, AuthCtx};
use crate::types::identifiers::UserId;
use crate::types::internal::{AccountType, StoredSession, UserAccount};
use crate::uiaa::{require_uiaa, UiaaOutcome};

/// `POST /_matrix/client/v3/register`.
pub async fn register(
    State(st): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    // OptionalJson (not axum's Json) so a malformed body yields M_NOT_JSON/400
    // rather than a non-Matrix rejection (TestRequestEncodingFails).
    OptionalJson(body): OptionalJson,
) -> MatrixResult<Response> {
    check_rate_limit(&addr.ip().to_string(), "register")?;
    if params.get("kind").map(String::as_str) == Some("guest") {
        return Err(invalid_param("Guest registration is not supported"));
    }

    // User-Interactive Auth (m.login.dummy / m.login.password).
    if let UiaaOutcome::Challenge(challenge) = require_uiaa(&*st.storage, &body, None).await? {
        return Ok((StatusCode::UNAUTHORIZED, Json(challenge)).into_response());
    }

    // Username / password validation.
    let Some(username) = body.get("username").and_then(Value::as_str) else {
        return Err(bad_json("Missing 'username' field"));
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
    // A localpart inside an appservice's *exclusive* namespace may only be
    // registered by that appservice (presenting its as_token).
    let candidate_id = format!("@{localpart}:{}", st.server_name);
    if let Some(reg) =
        crate::appservice::registration::find_exclusive_appservice_for_user(&candidate_id, &st.registrations)
    {
        let bearer = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .unwrap_or("");
        if bearer != reg.as_token {
            return Err(crate::errors::MatrixError::new(
                "M_EXCLUSIVE",
                "This user ID is reserved by an application service",
                400,
            ));
        }
    }
    let Some(password) = body.get("password").and_then(Value::as_str) else {
        return Err(bad_json("Missing 'password' field"));
    };
    if password.is_empty() {
        return Err(weak_password("Password must be at least 1 character"));
    }

    let user_id: UserId = format!("@{localpart}:{}", st.server_name).into();
    let pw = password.to_string();
    let password_hash = tokio::task::spawn_blocking(move || hash_password(&pw))
        .await
        .expect("hash task");

    st.storage
        .create_user(UserAccount {
            user_id: user_id.clone(),
            localpart: localpart.clone(),
            server_name: st.server_name.as_ref().into(),
            password_hash,
            account_type: AccountType::User,
            is_deactivated: false,
            created_at: now_ms(),
            displayname: None,
            avatar_url: None,
        })
        .await;

    if body
        .get("inhibit_login")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(Json(json!({ "user_id": user_id.as_str() })).into_response());
    }

    let (access_token, device_id, refresh_token) =
        create_session(&st, &headers, &user_id, &body).await;
    let mut resp = json!({
        "user_id": user_id.as_str(),
        "access_token": access_token,
        "device_id": device_id,
    });
    if let Some(rt) = refresh_token {
        resp["refresh_token"] = json!(rt);
        resp["expires_in_ms"] = json!(300_000);
    }
    Ok(Json(resp).into_response())
}

/// `GET /_matrix/client/v3/login` — advertised login flows.
pub async fn login_flows() -> Json<Value> {
    Json(json!({ "flows": [{ "type": "m.login.password" }, { "type": "m.login.token" }] }))
}

/// `POST /_matrix/client/v3/login` — password login.
pub async fn login(
    State(st): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> MatrixResult<Response> {
    check_rate_limit(&addr.ip().to_string(), "login")?;
    let Some(login_type) = body.get("type").and_then(Value::as_str) else {
        return Err(bad_json("Missing 'type' field"));
    };
    if login_type != "m.login.password" {
        return Err(invalid_param(format!(
            "Unsupported login type: {login_type}"
        )));
    }

    let user = body
        .get("identifier")
        .filter(|i| i.get("type").and_then(Value::as_str) == Some("m.id.user"))
        .and_then(|i| i.get("user").and_then(Value::as_str))
        .or_else(|| body.get("user").and_then(Value::as_str));
    let Some(user) = user else {
        return Err(invalid_param("Only m.id.user identifier is supported"));
    };

    // Accept a bare localpart or a full `@user:server` id.
    let mut localpart = user.to_string();
    if let Some(stripped) = localpart.strip_prefix('@') {
        localpart = match stripped.find(':') {
            Some(i) if i > 0 => stripped[..i].to_string(),
            _ => stripped.to_string(),
        };
    }
    localpart = localpart.to_lowercase();

    let Some(account) = st.storage.get_user_by_localpart(&localpart).await else {
        return Err(forbidden("Invalid username or password"));
    };
    if account.is_deactivated {
        return Err(forbidden("This account has been deactivated"));
    }

    let password = body
        .get("password")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let hash = account.password_hash.clone();
    let valid = tokio::task::spawn_blocking(move || verify_password(&password, &hash))
        .await
        .expect("verify task");
    if !valid {
        return Err(forbidden("Invalid username or password"));
    }

    let (access_token, device_id, refresh_token) =
        create_session(&st, &headers, &account.user_id, &body).await;
    let mut resp = json!({
        "user_id": account.user_id.as_str(),
        "access_token": access_token,
        "device_id": device_id,
        "well_known": { "m.homeserver": { "base_url": format!("https://{}", st.server_name) } },
    });
    if let Some(rt) = refresh_token {
        resp["refresh_token"] = json!(rt);
        resp["expires_in_ms"] = json!(300_000);
    }
    Ok(Json(resp).into_response())
}

/// `GET /_matrix/client/v3/account/whoami`.
pub async fn whoami(auth: AuthCtx) -> Json<Value> {
    Json(json!({
        "user_id": auth.user_id.as_str(),
        "device_id": auth.device_id.as_str(),
    }))
}

// --- helpers ---------------------------------------------------------------

fn is_username_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '=' | '-' | '/')
}

/// Create and persist a device session (strix `createSessionAndRespond`).
async fn create_session(
    st: &AppState,
    headers: &HeaderMap,
    user_id: &UserId,
    body: &Value,
) -> (String, String, Option<String>) {
    let device_id = body
        .get("device_id")
        .and_then(Value::as_str)
        .map(String::from)
        .unwrap_or_else(generate_device_id);
    let access_token = generate_token();
    let refresh_token = body
        .get("refresh_token")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        .then(generate_token);
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    st.storage
        .create_session(StoredSession {
            device_id: device_id.as_str().into(),
            user_id: user_id.clone(),
            access_token_hash: String::new(),
            display_name: body
                .get("initial_device_display_name")
                .and_then(Value::as_str)
                .map(String::from),
            last_seen_ip: Some("unknown".to_string()),
            last_seen_ts: Some(now_ms()),
            user_agent: Some(user_agent),
            access_token: access_token.as_str().into(),
            refresh_token: refresh_token.as_deref().map(Into::into),
            expires_at: None,
        })
        .await;

    (access_token, device_id, refresh_token)
}
