//! Outbound federation client — port of strix `src/federation/client.ts`.
//!
//! Signs every request with an `X-Matrix` Authorization header over the
//! canonical request object `{ method, uri, origin, destination, content? }`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::federation::discovery::resolve_server;
use crate::signing::{sign_json, SigningKey};

/// A federation response: HTTP status + parsed (or null) JSON body.
pub struct FederationResponse {
    pub status: u16,
    pub body: Value,
}

/// Outbound federation client, holding our server name + signing key.
pub struct FederationClient {
    pub server_name: String,
    pub signing_key: Arc<SigningKey>,
    http: reqwest::Client,
}

impl FederationClient {
    pub fn new(server_name: String, signing_key: Arc<SigningKey>) -> Self {
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(true) // dev/Complement self-signed certs
            .timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(64)
            .build()
            .expect("build federation http client");
        FederationClient { server_name, signing_key, http }
    }

    /// The `X-Matrix` Authorization header value for a request.
    fn auth_header(&self, destination: &str, method: &str, uri: &str, content: Option<&Value>) -> String {
        let mut obj = json!({
            "method": method.to_uppercase(),
            "uri": uri,
            "origin": self.server_name,
            "destination": destination,
        });
        if let Some(c) = content {
            obj["content"] = c.clone();
        }
        let signed = sign_json(&obj, &self.server_name, &self.signing_key);
        let sig = signed
            .get("signatures")
            .and_then(|s| s.get(&self.server_name))
            .and_then(|s| s.get(&self.signing_key.key_id))
            .and_then(Value::as_str)
            .unwrap_or("");
        format!(
            "X-Matrix origin=\"{}\",destination=\"{destination}\",key=\"{}\",sig=\"{sig}\"",
            self.server_name, self.signing_key.key_id
        )
    }

    /// Perform a signed federation request. Returns an error only on transport
    /// failure; HTTP error statuses are returned as a [`FederationResponse`].
    pub async fn request(
        &self,
        destination: &str,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<FederationResponse, reqwest::Error> {
        let resolved = resolve_server(destination).await;
        let url = format!("https://{}:{}{path}", resolved.host, resolved.port);
        let auth = self.auth_header(destination, method, path, body.as_ref());

        let mut req = self
            .http
            .request(
                method.parse().unwrap_or(reqwest::Method::GET),
                &url,
            )
            .header("Authorization", auth)
            .header("Host", destination)
            .header("Content-Type", "application/json");
        if let Some(b) = &body {
            req = req.json(b);
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Ok(FederationResponse { status, body })
    }

    /// Perform a signed federation GET returning the raw response bytes and
    /// Content-Type (used for media, which is `multipart/mixed`, not JSON).
    pub async fn request_raw(
        &self,
        destination: &str,
        path: &str,
    ) -> Result<RawFederationResponse, reqwest::Error> {
        let resolved = resolve_server(destination).await;
        let url = format!("https://{}:{}{path}", resolved.host, resolved.port);
        let auth = self.auth_header(destination, "GET", path, None);
        let resp = self
            .http
            .get(&url)
            .header("Authorization", auth)
            .header("Host", destination)
            .send()
            .await?;
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = resp.bytes().await?.to_vec();
        Ok(RawFederationResponse { status, content_type, body })
    }
}

/// A federation response with raw bytes (for media transport).
pub struct RawFederationResponse {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}
