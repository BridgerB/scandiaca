//! Matrix error type — port of strix `src/errors.ts`.
//!
//! A [`MatrixError`] carries the `errcode`/`error`/HTTP status triple and
//! optional `extra` fields. `to_json` produces `{ errcode, error, ...extra }`,
//! which the router serializes. Engine functions that "throw" in strix return
//! `Result<_, MatrixError>` here.

use serde_json::{Map, Value};

/// A Matrix API error.
#[derive(Debug, Clone)]
pub struct MatrixError {
    pub errcode: String,
    pub error: String,
    pub status_code: u16,
    /// Extra top-level fields merged into the JSON body (e.g. `soft_logout`,
    /// `retry_after_ms`).
    pub extra: Option<Map<String, Value>>,
}

impl MatrixError {
    pub fn new(errcode: impl Into<String>, error: impl Into<String>, status_code: u16) -> Self {
        MatrixError {
            errcode: errcode.into(),
            error: error.into(),
            status_code,
            extra: None,
        }
    }

    pub fn with_extra(mut self, extra: Map<String, Value>) -> Self {
        self.extra = Some(extra);
        self
    }

    /// `{ errcode, error, ...extra }`.
    pub fn to_json(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("errcode".to_string(), Value::String(self.errcode.clone()));
        obj.insert("error".to_string(), Value::String(self.error.clone()));
        if let Some(extra) = &self.extra {
            for (k, v) in extra {
                obj.insert(k.clone(), v.clone());
            }
        }
        Value::Object(obj)
    }
}

impl std::fmt::Display for MatrixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.error, self.errcode)
    }
}

impl std::error::Error for MatrixError {}

impl axum::response::IntoResponse for MatrixError {
    fn into_response(self) -> axum::response::Response {
        let status = axum::http::StatusCode::from_u16(self.status_code)
            .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        (status, axum::Json(self.to_json())).into_response()
    }
}

/// A handler result: `Ok` body or a [`MatrixError`] rendered as a Matrix error.
pub type MatrixResult<T> = Result<T, MatrixError>;

// --- Convenience constructors (mirroring errors.ts) ------------------------

pub fn forbidden(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_FORBIDDEN", msg, 403)
}

pub fn unknown_token(msg: impl Into<String>, soft_logout: bool) -> MatrixError {
    let mut extra = Map::new();
    extra.insert("soft_logout".to_string(), Value::Bool(soft_logout));
    MatrixError::new("M_UNKNOWN_TOKEN", msg, 401).with_extra(extra)
}

pub fn missing_token(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_MISSING_TOKEN", msg, 401)
}

pub fn bad_json(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_BAD_JSON", msg, 400)
}

pub fn not_json(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_NOT_JSON", msg, 400)
}

pub fn not_found(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_NOT_FOUND", msg, 404)
}

pub fn unrecognized(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_UNRECOGNIZED", msg, 404)
}

pub fn user_in_use(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_USER_IN_USE", msg, 400)
}

pub fn invalid_username(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_INVALID_USERNAME", msg, 400)
}

pub fn weak_password(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_WEAK_PASSWORD", msg, 400)
}

pub fn unknown(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_UNKNOWN", msg, 500)
}

pub fn missing_param(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_MISSING_PARAM", msg, 400)
}

pub fn invalid_param(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_INVALID_PARAM", msg, 400)
}

pub fn bad_alias(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_BAD_ALIAS", msg, 400)
}

pub fn room_not_found(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_NOT_FOUND", msg, 404)
}

pub fn not_joined(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_FORBIDDEN", msg, 403)
}

pub fn server_not_trusted(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_SERVER_NOT_TRUSTED", msg, 403)
}

pub fn unable_to_authorise_join(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_UNABLE_TO_AUTHORISE_JOIN", msg, 403)
}

pub fn incompatible_room_version(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_INCOMPATIBLE_ROOM_VERSION", msg, 400)
}

pub fn user_locked(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_USER_LOCKED", msg, 403)
}

pub fn user_deactivated(msg: impl Into<String>) -> MatrixError {
    MatrixError::new("M_USER_DEACTIVATED", msg, 403)
}
