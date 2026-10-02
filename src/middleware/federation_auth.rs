//! Inbound federation auth — port of strix `src/middleware/federation-auth.ts`.
//!
//! [`FedAuth`] is an axum extractor for **body-less** (GET) federation
//! endpoints: it parses the `X-Matrix` Authorization header, checks the
//! destination is us, fetches the origin's signing key, and verifies the
//! signature over `{ method, uri, origin, destination }`. Body-carrying
//! endpoints (transactions, send_join, …) verify with `content` included inside
//! their own handlers (they need the parsed body).

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde_json::json;

use crate::errors::{forbidden, server_not_trusted, MatrixError};
use crate::federation::key_store::get_server_key;
use crate::server::AppState;
use crate::signing::verify_json_signature;

/// The verified origin server of an inbound federation request.
pub struct FedAuth {
    pub origin: String,
}

/// Verified origin + parsed JSON body for body-carrying federation requests
/// (invite, send_join/leave/knock, send transactions). The X-Matrix signature
/// on these covers `content`, so verification must include the body — which
/// `FromRequestParts` can't read. This consuming extractor does.
pub struct FedAuthBody {
    pub origin: String,
    pub body: serde_json::Value,
}

impl axum::extract::FromRequest<AppState> for FedAuthBody {
    type Rejection = MatrixError;

    async fn from_request(
        req: axum::extract::Request,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let method = parts.method.as_str().to_uppercase();
        let uri = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| parts.uri.path().to_string());
        let header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| MatrixError::new("M_UNAUTHORIZED", "Missing Authorization header", 401))?;
        let x = parse_x_matrix(header).ok_or_else(|| forbidden("Invalid X-Matrix header"))?;
        if let Some(dest) = &x.destination {
            if dest.as_str() != state.server_name.as_ref() {
                return Err(forbidden("Wrong destination"));
            }
        }

        let bytes = axum::body::to_bytes(body, 64 * 1024 * 1024)
            .await
            .map_err(|_| crate::errors::bad_json("Could not read body"))?;
        let content: serde_json::Value = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(|_| crate::errors::not_json("Body is not JSON"))?
        };

        let client = state
            .federation_client
            .as_ref()
            .ok_or_else(|| forbidden("Federation not enabled"))?;
        let pub_key = get_server_key(&*state.storage, &x.origin, &x.key, client)
            .await
            .ok_or_else(|| server_not_trusted("Could not fetch origin key"))?;

        let mut obj = json!({
            "method": method,
            "uri": uri,
            "origin": x.origin,
            "destination": state.server_name.as_ref(),
        });
        if !content.is_null() {
            obj["content"] = content.clone();
        }
        obj["signatures"] = json!({ x.origin.clone(): { x.key.clone(): x.sig } });
        if !verify_json_signature(&obj, &x.origin, &x.key, &pub_key) {
            return Err(forbidden("Invalid request signature"));
        }
        Ok(FedAuthBody { origin: x.origin, body: content })
    }
}

/// Parsed `X-Matrix` Authorization header.
pub struct XMatrix {
    pub origin: String,
    pub destination: Option<String>,
    pub key: String,
    pub sig: String,
}

/// Parse an `X-Matrix origin="a",destination="b",key="ed25519:x",sig="…"` header.
pub fn parse_x_matrix(header: &str) -> Option<XMatrix> {
    let rest = header.strip_prefix("X-Matrix ")?;
    let mut origin = None;
    let mut destination = None;
    let mut key = None;
    let mut sig = None;
    for part in split_params(rest) {
        let (k, v) = part.split_once('=')?;
        let v = v.trim().trim_matches('"').to_string();
        match k.trim() {
            "origin" => origin = Some(v),
            "destination" => destination = Some(v),
            "key" => key = Some(v),
            "sig" => sig = Some(v),
            _ => {}
        }
    }
    Some(XMatrix {
        origin: origin?,
        destination,
        key: key?,
        sig: sig?,
    })
}

/// Split comma-separated params, respecting quoted values (sigs may contain no
/// commas in base64, but be safe).
fn split_params(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for c in s.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                cur.push(c);
            }
            ',' if !in_quotes => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

impl FromRequestParts<AppState> for FedAuth {
    type Rejection = MatrixError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| MatrixError::new("M_UNAUTHORIZED", "Missing Authorization header", 401))?;
        let x = parse_x_matrix(header).ok_or_else(|| forbidden("Invalid X-Matrix header"))?;

        if let Some(dest) = &x.destination {
            if dest.as_str() != state.server_name.as_ref() {
                return Err(forbidden("Wrong destination"));
            }
        }
        let client = state
            .federation_client
            .as_ref()
            .ok_or_else(|| forbidden("Federation not enabled"))?;

        let pub_key = get_server_key(&*state.storage, &x.origin, &x.key, client)
            .await
            .ok_or_else(|| server_not_trusted("Could not fetch origin key"))?;

        // Reconstruct the signed object (no content for body-less requests).
        let uri = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| parts.uri.path().to_string());
        let mut obj = json!({
            "method": parts.method.as_str().to_uppercase(),
            "uri": uri,
            "origin": x.origin,
            "destination": state.server_name.as_ref(),
        });
        // Attach the claimed signature so verify_json_signature can find it.
        obj["signatures"] = json!({ x.origin.clone(): { x.key.clone(): x.sig } });

        if !verify_json_signature(&obj, &x.origin, &x.key, &pub_key) {
            return Err(forbidden("Invalid request signature"));
        }
        Ok(FedAuth { origin: x.origin })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_header() {
        let h = r#"X-Matrix origin="hs1",destination="hs2",key="ed25519:abc",sig="AAAA""#;
        let x = parse_x_matrix(h).unwrap();
        assert_eq!(x.origin, "hs1");
        assert_eq!(x.destination.as_deref(), Some("hs2"));
        assert_eq!(x.key, "ed25519:abc");
        assert_eq!(x.sig, "AAAA");
    }
}
