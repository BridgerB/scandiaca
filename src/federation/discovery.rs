//! Server discovery — port of strix `src/federation/discovery.ts`.
//!
//! Resolves a Matrix server name to `host:port`: explicit `host:port` →
//! `.well-known/matrix/server` delegation → `host:8448` fallback. SRV records
//! are not yet consulted (deferred).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use serde_json::Value;

use crate::server::now_ms;

/// A resolved federation endpoint.
#[derive(Clone, Debug)]
pub struct ResolvedServer {
    pub host: String,
    pub port: u16,
    pub server_name: String,
}

const CACHE_TTL_MS: i64 = 5 * 60 * 1000;

struct CacheEntry {
    result: ResolvedServer,
    expires_at: i64,
}

fn cache() -> &'static Mutex<HashMap<String, CacheEntry>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Split an `host:port` authority; `None` when there's no explicit numeric port.
fn split_host_port(authority: &str) -> Option<(String, u16)> {
    let colon = authority.rfind(':')?;
    if colon == 0 || authority.ends_with(']') {
        return None;
    }
    let port: u16 = authority[colon + 1..].parse().ok()?;
    Some((authority[..colon].to_string(), port))
}

/// Fetch and parse a JSON document over HTTPS (accepting self-signed certs).
async fn fetch_json(url: &str) -> Option<Value> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;
    let resp = client.get(url).header("Accept", "application/json").send().await.ok()?;
    resp.json::<Value>().await.ok()
}

/// `.well-known/matrix/server` delegation, if advertised.
async fn resolve_well_known(server_name: &str) -> Option<ResolvedServer> {
    let wk = fetch_json(&format!("https://{server_name}/.well-known/matrix/server")).await?;
    let delegated = wk.get("m.server").and_then(Value::as_str)?;
    if delegated.is_empty() {
        return None;
    }
    match split_host_port(delegated) {
        Some((host, port)) => Some(ResolvedServer { host, port, server_name: server_name.to_string() }),
        None => Some(ResolvedServer {
            host: delegated.to_string(),
            port: 8448,
            server_name: server_name.to_string(),
        }),
    }
}

async fn do_resolve(server_name: &str) -> ResolvedServer {
    if let Some((host, port)) = split_host_port(server_name) {
        return ResolvedServer { host, port, server_name: server_name.to_string() };
    }
    if let Some(r) = resolve_well_known(server_name).await {
        return r;
    }
    ResolvedServer { host: server_name.to_string(), port: 8448, server_name: server_name.to_string() }
}

/// Resolve a server name to an endpoint, with a 5-minute cache.
pub async fn resolve_server(server_name: &str) -> ResolvedServer {
    if let Some(entry) = cache().lock().unwrap().get(server_name) {
        if entry.expires_at > now_ms() {
            return entry.result.clone();
        }
    }
    let result = do_resolve(server_name).await;
    cache().lock().unwrap().insert(
        server_name.to_string(),
        CacheEntry { result: result.clone(), expires_at: now_ms() + CACHE_TTL_MS },
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_host_port() {
        assert_eq!(split_host_port("hs1:8448"), Some(("hs1".to_string(), 8448)));
        assert_eq!(split_host_port("example.com"), None);
        assert_eq!(split_host_port("[::1]"), None);
    }
}
