//! Remote signing-key store — port of strix `src/federation/key-store.ts`.

use crate::federation::client::FederationClient;
use crate::server::now_ms;
use crate::signing::verify_json_signature;
use crate::storage::Storage;
use crate::types::federation::ServerKeys;
use crate::types::identifiers::{KeyId, ServerName};

/// Fetch (or serve from cache) a remote server's public key for `key_id`.
/// Returns the unpadded-base64 key, or `None` if it cannot be obtained/verified.
pub async fn get_server_key(
    storage: &dyn Storage,
    server_name: &str,
    key_id: &str,
    client: &FederationClient,
) -> Option<String> {
    let sn = ServerName::from(server_name);
    let kid = KeyId::from(key_id);
    if let Some(cached) = storage.get_server_keys(&sn, &kid).await {
        if cached.valid_until > now_ms() {
            return Some(cached.key);
        }
    }

    let resp = client.request(server_name, "GET", "/_matrix/key/v2/server", None).await.ok()?;
    if resp.status != 200 {
        return None;
    }
    let keys: ServerKeys = serde_json::from_value(resp.body.clone()).ok()?;
    if keys.server_name.as_str() != server_name {
        return None;
    }
    // Self-verify the key response with its first advertised key.
    let first_key_id = keys.verify_keys.keys().next()?.clone();
    let first_key = keys.verify_keys.get(&first_key_id)?.key.as_str().to_string();
    if !verify_json_signature(&resp.body, server_name, &first_key_id, &first_key) {
        return None;
    }
    let requested = keys.verify_keys.get(key_id).map(|v| v.key.as_str().to_string());
    storage.store_server_keys(&sn, keys).await;
    requested
}
