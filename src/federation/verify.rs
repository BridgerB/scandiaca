//! Inbound PDU signature verification — port of strix `src/federation/verify.ts`.

use serde_json::Value;

use crate::errors::{forbidden, MatrixError};
use crate::federation::client::FederationClient;
use crate::federation::key_store::get_server_key;
use crate::ids::domain_of;
use crate::signing::verify_event_signature;
use crate::storage::Storage;

/// Verify `event` carries a valid signature from `server` for one of the key ids
/// it claims. Signatures are checked over the redacted form.
async fn verify_server_signature(
    event: &Value,
    server: &str,
    storage: &dyn Storage,
    client: &FederationClient,
    room_version: Option<&str>,
) -> Result<(), MatrixError> {
    let server_sigs = event
        .get("signatures")
        .and_then(|s| s.get(server))
        .and_then(Value::as_object);
    let Some(server_sigs) = server_sigs.filter(|m| !m.is_empty()) else {
        return Err(forbidden(format!("No signature from {server}")));
    };
    for key_id in server_sigs.keys() {
        if let Some(pub_key) = get_server_key(storage, server, key_id, client).await {
            if verify_event_signature(event, server, key_id, &pub_key, room_version) {
                return Ok(());
            }
        }
    }
    Err(forbidden("Invalid event signature"))
}

/// Check an inbound federation event is correctly signed by its sender's domain
/// (3pid invites exempt), mirroring Synapse's `_check_sigs_on_pdu`. The
/// transaction origin is intentionally not used — verification is driven by the
/// event's own sender.
pub async fn verify_origin_signature(
    event: &Value,
    storage: &dyn Storage,
    client: &FederationClient,
    room_version: Option<&str>,
) -> Result<(), MatrixError> {
    let content = event.get("content");
    let membership = content.and_then(|c| c.get("membership")).and_then(Value::as_str);
    let is_third_party_invite = event.get("type").and_then(Value::as_str) == Some("m.room.member")
        && membership == Some("invite")
        && content.map(|c| c.get("third_party_invite").is_some()).unwrap_or(false);

    if !is_third_party_invite {
        let sender = event.get("sender").and_then(Value::as_str).unwrap_or("");
        verify_server_signature(event, domain_of(sender), storage, client, room_version).await?;
    }
    Ok(())
}
