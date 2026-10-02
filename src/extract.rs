//! Shared extractors.
//!
//! [`OptionalJson`] parses a JSON body but tolerates an absent/empty body (and
//! any content-type), yielding `{}`. Many Matrix endpoints accept an optional
//! body (`POST /join`, `/leave`, `/logout`, …); axum's `Json` rejects those with
//! 400/415, so those handlers use `OptionalJson` instead.

use axum::body::Bytes;
use axum::extract::FromRequest;
use axum::http::Request;
use serde_json::{json, Value};

use crate::errors::not_json;

/// A request-body JSON value that defaults to `{}` when the body is empty.
pub struct OptionalJson(pub Value);

impl<S: Send + Sync> FromRequest<S> for OptionalJson {
    type Rejection = crate::errors::MatrixError;

    async fn from_request(req: Request<axum::body::Body>, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|_| not_json("Could not read request body"))?;
        if bytes.is_empty() {
            return Ok(OptionalJson(json!({})));
        }
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(v) => Ok(OptionalJson(v)),
            Err(_) => Err(not_json("Request body is not valid JSON")),
        }
    }
}
