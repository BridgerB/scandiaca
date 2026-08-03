//! User-Interactive Auth — port of strix `src/uiaa.ts`.
//!
//! Session creation + stage validation for `m.login.password` (via
//! [`verify_password`]) and `m.login.dummy`. strix throws an object carrying a
//! `uiaaResponse`; the Rust port models that as [`UiaaOutcome::Challenge`]
//! (render as a 401 with the JSON body) vs [`UiaaOutcome::Complete`].

use serde_json::{json, Value};

use crate::crypto::generate_session_id;
use crate::crypto_utils::verify_password;
use crate::errors::{bad_json, forbidden, MatrixError};
use crate::storage::Storage;

/// The supported UIAA flows (strix `UIAA_FLOWS`).
pub const UIAA_FLOWS: &[&[&str]] = &[&["m.login.password"], &["m.login.dummy"]];

/// The result of a UIAA check.
pub enum UiaaOutcome {
    /// All stages of some flow are complete; proceed with the request.
    Complete,
    /// Auth incomplete — return HTTP 401 with this JSON body.
    Challenge(Value),
}

/// Build a UIAA 401 challenge body.
fn challenge(session_id: &str, extra: Option<(&str, Value)>) -> Value {
    let flows: Vec<Value> = UIAA_FLOWS
        .iter()
        .map(|stages| json!({ "stages": stages }))
        .collect();
    let mut body = json!({
        "flows": flows,
        "params": {},
        "session": session_id,
    });
    if let Some((k, v)) = extra {
        body[k] = v;
    }
    body
}

/// Run the UIAA state machine over a request `body` (strix `requireUIAA` +
/// `withUIAA` combined). Returns [`UiaaOutcome::Complete`] when a flow is
/// satisfied, [`UiaaOutcome::Challenge`] when more auth is needed, or an error
/// for genuinely malformed input.
///
/// `user_id` is the already-authenticated user, if any (used to resolve the
/// localpart for password auth on authenticated endpoints).
pub async fn require_uiaa(
    storage: &dyn Storage,
    body: &Value,
    user_id: Option<&str>,
) -> Result<UiaaOutcome, MatrixError> {
    let auth = body.get("auth").filter(|v| !v.is_null());

    let Some(auth) = auth else {
        let session_id = generate_session_id();
        storage.create_uiaa_session(&session_id).await;
        return Ok(UiaaOutcome::Challenge(challenge(&session_id, None)));
    };

    // Session id: from the request, or created on the fly for single-step auth.
    let session_id = match auth.get("session").and_then(Value::as_str) {
        Some(s) => s.to_string(),
        None => {
            let s = generate_session_id();
            storage.create_uiaa_session(&s).await;
            s
        }
    };
    if storage.get_uiaa_session(&session_id).await.is_none() {
        return Err(forbidden("Unknown session"));
    }

    match auth.get("type").and_then(Value::as_str) {
        Some("m.login.dummy") => {
            storage.add_uiaa_completed(&session_id, "m.login.dummy").await;
        }
        Some("m.login.password") => {
            let fail = |error: &str| {
                UiaaOutcome::Challenge(challenge(
                    &session_id,
                    Some(("errcode", json!("M_FORBIDDEN"))),
                ))
                .with_error(error)
            };

            let Some(password) = auth.get("password").and_then(Value::as_str) else {
                return Ok(fail("Missing password"));
            };

            let localpart = resolve_localpart(auth.get("identifier"), user_id);
            let Some(localpart) = localpart else {
                return Ok(fail("Cannot determine user for authentication"));
            };
            let Some(account) = storage.get_user_by_localpart(&localpart).await else {
                return Ok(fail("Invalid username or password"));
            };
            let pw = password.to_string();
            let hash = account.password_hash.clone();
            let valid = tokio::task::spawn_blocking(move || verify_password(&pw, &hash))
                .await
                .expect("verify task");
            if !valid {
                return Ok(fail("Invalid username or password"));
            }
            storage
                .add_uiaa_completed(&session_id, "m.login.password")
                .await;
        }
        Some(other) => return Err(bad_json(format!("Unsupported auth type: {other}"))),
        None => return Err(bad_json("Missing auth type")),
    }

    // Is any flow fully satisfied now?
    let completed = storage
        .get_uiaa_session(&session_id)
        .await
        .map(|u| u.completed)
        .unwrap_or_default();
    let all_completed = UIAA_FLOWS
        .iter()
        .any(|flow| flow.iter().all(|stage| completed.iter().any(|c| c == stage)));

    if !all_completed {
        return Ok(UiaaOutcome::Challenge(challenge(
            &session_id,
            Some(("completed", json!(completed))),
        )));
    }

    storage.delete_uiaa_session(&session_id).await;
    Ok(UiaaOutcome::Complete)
}

impl UiaaOutcome {
    /// Attach an `error` field to a challenge body (no-op on `Complete`).
    fn with_error(self, error: &str) -> Self {
        match self {
            UiaaOutcome::Challenge(mut body) => {
                body["error"] = json!(error);
                UiaaOutcome::Challenge(body)
            }
            other => other,
        }
    }
}

/// Resolve the localpart for password auth from an `m.id.user` identifier, or
/// fall back to the authenticated user id (strix identifier handling).
fn resolve_localpart(identifier: Option<&Value>, user_id: Option<&str>) -> Option<String> {
    if let Some(id) = identifier {
        if id.get("type").and_then(Value::as_str) == Some("m.id.user") {
            if let Some(user) = id.get("user").and_then(Value::as_str) {
                return Some(strip_localpart(user));
            }
        }
    }
    user_id.map(strip_localpart)
}

/// `@alice:server` → `alice`; a bare localpart is returned unchanged.
fn strip_localpart(user: &str) -> String {
    let s = user.strip_prefix('@').unwrap_or(user);
    match s.find(':') {
        Some(i) if i > 0 => s[..i].to_string(),
        _ => s.to_string(),
    }
}
