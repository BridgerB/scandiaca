//! Outbound EDU/PDU dispatch — port of strix `federation/outbound.ts`.
//!
//! EDUs come in two flavours. Transient EDUs (typing/presence) are best-effort:
//! an offline peer simply misses them. Durable EDUs (device-list updates,
//! to-device messages) MUST eventually arrive across a destination outage, so
//! [`deliver_edu_to_destination`] persists-on-failure and replays on recovery
//! via the storage EDU queue; [`flush_all_pending_edus`] sweeps every backlog
//! (startup + periodic timer). PDUs fan out fire-and-forget (no durable queue,
//! matching strix `fanoutEvent`).

use serde_json::{json, Value};

use crate::crypto::generate_token;
use crate::federation::FederationClient;
use crate::server::now_ms;
use crate::storage::interface::Storage;
use crate::types::events::Edu;
use crate::types::identifiers::ServerName;

/// Max EDUs packed into one federation transaction (Synapse uses 100).
const MAX_EDUS_PER_TXN: usize = 100;

fn edu_to_value(edu: &Edu) -> Value {
    json!({ "edu_type": edu.edu_type, "content": edu.content })
}

fn value_to_edu(v: &Value) -> Edu {
    Edu {
        edu_type: v.get("edu_type").and_then(Value::as_str).unwrap_or_default().to_string(),
        content: v.get("content").and_then(Value::as_object).cloned().unwrap_or_default(),
    }
}

/// PUT a freshly-stamped `/send` transaction. Returns the HTTP status (0 on
/// transport error).
async fn send_transaction(
    client: &FederationClient,
    origin: &str,
    dest: &str,
    pdus: Vec<Value>,
    edus: Vec<Value>,
) -> u16 {
    let txn_id = generate_token();
    let body = json!({
        "origin": origin,
        "origin_server_ts": now_ms(),
        "pdus": pdus,
        "edus": edus,
    });
    let path = format!("/_matrix/federation/v1/send/{txn_id}");
    match client.request(dest, "PUT", &path, Some(body)).await {
        Ok(resp) => resp.status,
        Err(_) => 0,
    }
}

/// Durable single-destination EDU delivery (strix `deliverEduToDestination`):
/// drain any backlog for `dest`, batch with the new EDU, deliver; on success
/// delete the delivered persisted entries, on failure persist the new EDU for a
/// later replay.
pub async fn deliver_edu_to_destination(
    storage: &dyn Storage,
    client: &FederationClient,
    origin: &str,
    dest: &str,
    edu: Value,
) {
    let sn = ServerName::from(dest);
    let pending = storage.get_pending_federation_edus(&sn, MAX_EDUS_PER_TXN - 1).await;

    // Persist the new EDU up-front only when there is a backlog; on the common
    // peer-up path we try the fast route and queue only on failure.
    let mut new_entry_id: Option<i64> = None;
    if !pending.is_empty() {
        new_entry_id = Some(storage.enqueue_federation_edu(&sn, value_to_edu(&edu)).await);
    }

    let mut batch: Vec<(Option<i64>, Value)> =
        pending.iter().map(|p| (Some(p.id), edu_to_value(&p.edu))).collect();
    batch.push((new_entry_id, edu.clone()));

    let status = send_transaction(client, origin, dest, vec![], batch.iter().map(|(_, v)| v.clone()).collect()).await;
    let delivered = status != 0 && status < 400;

    if delivered {
        for (id, _) in &batch {
            if let Some(id) = id {
                storage.delete_federation_edu(*id).await;
            }
        }
        return;
    }

    // Failed: make sure the new EDU is persisted for a later replay.
    if new_entry_id.is_none() {
        storage.enqueue_federation_edu(&sn, value_to_edu(&edu)).await;
    }
}

/// Replay queued EDUs for one destination until the queue drains or a send
/// fails (strix `flushPendingEdusForDestination`).
pub async fn flush_pending_edus_for_destination(
    storage: &dyn Storage,
    client: &FederationClient,
    origin: &str,
    dest: &str,
) {
    let sn = ServerName::from(dest);
    loop {
        let pending = storage.get_pending_federation_edus(&sn, MAX_EDUS_PER_TXN).await;
        if pending.is_empty() {
            return;
        }
        let edus: Vec<Value> = pending.iter().map(|p| edu_to_value(&p.edu)).collect();
        let status = send_transaction(client, origin, dest, vec![], edus).await;
        if status == 0 || status >= 400 {
            return; // still unreachable; retry next sweep
        }
        for p in &pending {
            storage.delete_federation_edu(p.id).await;
        }
        if pending.len() < MAX_EDUS_PER_TXN {
            return;
        }
    }
}

/// Sweep every destination with queued EDUs and attempt a replay (strix
/// `flushAllPendingEdus`). Called on startup and on a periodic timer.
pub async fn flush_all_pending_edus(storage: &dyn Storage, client: &FederationClient, origin: &str) {
    for dest in storage.get_pending_federation_destinations().await {
        if dest.as_str() == origin {
            continue;
        }
        flush_pending_edus_for_destination(storage, client, origin, dest.as_str()).await;
    }
}

/// Fan a freshly-created PDU out to every remote server in the room (strix
/// `fanoutEvent`). Best-effort, one transaction per destination; a failing peer
/// simply misses the event (no durable retry queue). `origin` is excluded.
pub async fn fanout_event(
    storage: &dyn Storage,
    client: &FederationClient,
    origin: &str,
    room_id: &crate::types::identifiers::RoomId,
    event: &Value,
) {
    let servers = storage.get_servers_in_room(room_id).await;
    for dest in servers {
        let dest = dest.as_str();
        if dest.is_empty() || dest == origin {
            continue;
        }
        let _ = send_transaction(client, origin, dest, vec![event.clone()], vec![]).await;
    }
}

/// Deliver an EDU to every remote server resident in a room (typing/receipts).
pub async fn fanout_edu_to_room(
    storage: &dyn Storage,
    client: &FederationClient,
    origin: &str,
    room_id: &crate::types::identifiers::RoomId,
    edu: Value,
) {
    for dest in storage.get_servers_in_room(room_id).await {
        let dest = dest.as_str();
        if dest.is_empty() || dest == origin {
            continue;
        }
        deliver_edu_to_destination(storage, client, origin, dest, edu.clone()).await;
    }
}

/// Deliver an EDU to every remote server that shares one of `room_ids` (presence).
pub async fn fanout_edu_to_room_servers(
    storage: &dyn Storage,
    client: &FederationClient,
    origin: &str,
    room_ids: &[crate::types::identifiers::RoomId],
    edu: Value,
) {
    let mut seen = std::collections::HashSet::new();
    for rid in room_ids {
        for dest in storage.get_servers_in_room(rid).await {
            let d = dest.as_str().to_string();
            if d.is_empty() || d == origin || !seen.insert(d.clone()) {
                continue;
            }
            deliver_edu_to_destination(storage, client, origin, &d, edu.clone()).await;
        }
    }
}
