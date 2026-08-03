//! Inbound federation transactions — core port of strix
//! `handlers/federation/transactions.ts` (`putFederationSend`).
//!
//! Per PDU: verify the sender's signature over the redacted form, compute the
//! event id, auth-check against current room state, then persist (state events
//! into room state, others into the timeline) and index relations. Auth-rejected
//! PDUs return an empty `{}` result (Synapse persists-as-rejected) rather than a
//! transaction error. EDUs (typing/receipt/to-device/device-list/presence) are
//! applied best-effort. Gap-filling (get_missing_events) and partial-state are
//! deferred.

use axum::extract::{Path, State};
use axum::response::Json;
use serde_json::{json, Map, Value};

use crate::events::{check_event_auth, compute_event_id, ev_state_key, ev_type};
use crate::middleware::federation_auth::FedAuthBody;
use crate::relations::index_relation;
use crate::server::AppState;
use crate::types::events::ToDeviceEvent;
use crate::types::identifiers::{DeviceId, EventId, RoomId, UserId};

/// `PUT /_matrix/federation/v1/send/{txnId}`.
pub async fn put_federation_send(
    State(st): State<AppState>,
    Path(txn_id): Path<String>,
    auth: FedAuthBody,
) -> Json<Value> {
    let origin = &auth.origin;
    let body = auth.body;

    // Transaction idempotency.
    if st.storage.get_federation_txn(&origin.as_str().into(), &txn_id).await {
        return Json(json!({ "pdus": {} }));
    }
    st.storage.set_federation_txn(&origin.as_str().into(), &txn_id).await;

    let mut pdu_results = Map::new();
    if let Some(pdus) = body.get("pdus").and_then(Value::as_array) {
        for pdu in pdus {
            let room_id = pdu.get("room_id").and_then(Value::as_str).unwrap_or("");
            let room = st.storage.get_room(&RoomId::from(room_id)).await;
            let room_version = room
                .as_ref()
                .map(|r| r.room_version.clone())
                .or_else(|| {
                    if ev_type(pdu) == "m.room.create" {
                        pdu.get("content")
                            .and_then(|c| c.get("room_version"))
                            .and_then(Value::as_str)
                            .map(String::from)
                    } else {
                        None
                    }
                });
            let event_id = compute_event_id(pdu, room_version.as_deref());

            match process_pdu(&st, pdu, &event_id, room.as_ref()).await {
                Ok(()) => {
                    pdu_results.insert(event_id, json!({}));
                }
                Err(rejected) => {
                    // Auth-rejected → empty result (persist-as-rejected); hard
                    // failure → {error}.
                    if rejected {
                        pdu_results.insert(event_id, json!({}));
                    } else {
                        pdu_results.insert(event_id, json!({ "error": "Processing failed" }));
                    }
                }
            }
        }
    }

    if let Some(edus) = body.get("edus").and_then(Value::as_array) {
        for edu in edus {
            process_edu(&st, edu).await;
        }
    }

    Json(json!({ "pdus": pdu_results }))
}

/// Process one inbound PDU. `Err(true)` = auth-rejected, `Err(false)` = hard
/// failure (unknown room, bad signature).
async fn process_pdu(
    st: &AppState,
    pdu: &Value,
    event_id: &str,
    room: Option<&crate::types::internal::RoomState>,
) -> Result<(), bool> {
    let Some(room) = room else {
        return Err(false); // unknown room
    };
    let rid = RoomId::from(room.room_id.as_str());

    // Dedup: already have it.
    let eid = EventId::from(event_id);
    if st.storage.get_event(&eid).await.is_some() {
        return Ok(());
    }

    // Verify the sender's signature over the redacted event.
    let client = st.federation_client.as_ref().ok_or(false)?;
    if crate::federation::verify::verify_origin_signature(pdu, &*st.storage, client, Some(&room.room_version))
        .await
        .is_err()
    {
        return Err(false);
    }

    // Auth-check against current room state.
    if check_event_auth(pdu, room).is_err() {
        return Err(true); // rejected
    }

    // Persist: state events into room state, others onto the timeline.
    if ev_state_key(pdu).is_some() {
        st.storage.set_state_event(&rid, pdu.clone(), &eid).await;
        st.storage
            .update_room_dag(
                &rid,
                (pdu.get("depth").and_then(Value::as_i64).unwrap_or(room.depth) + 1).max(room.depth),
                vec![eid.clone()],
            )
            .await;
    } else {
        st.storage.store_event(pdu.clone(), &eid).await;
        index_relation(&*st.storage, pdu, &eid).await;
        st.storage
            .update_room_dag(
                &rid,
                (pdu.get("depth").and_then(Value::as_i64).unwrap_or(room.depth) + 1).max(room.depth),
                vec![eid.clone()],
            )
            .await;
    }
    Ok(())
}

/// Apply one inbound EDU (best-effort).
async fn process_edu(st: &AppState, edu: &Value) {
    let edu_type = edu.get("edu_type").and_then(Value::as_str).unwrap_or("");
    let content = edu.get("content").cloned().unwrap_or(Value::Null);
    match edu_type {
        "m.typing" => {
            let room_id = content.get("room_id").and_then(Value::as_str).unwrap_or("");
            let user_id = content.get("user_id").and_then(Value::as_str).unwrap_or("");
            let typing = content.get("typing").and_then(Value::as_bool).unwrap_or(false);
            if !room_id.is_empty() && !user_id.is_empty() {
                st.storage
                    .set_typing(&RoomId::from(room_id), &UserId::from(user_id), typing, Some(30000))
                    .await;
            }
        }
        "m.receipt" => {
            // { room_id: { m.read: { user_id: { data: {ts}, event_ids: [...] } } } }
            if let Some(rooms) = content.as_object() {
                for (room_id, by_type) in rooms {
                    let Some(by_type) = by_type.as_object() else { continue };
                    for (rtype, users) in by_type {
                        let Some(users) = users.as_object() else { continue };
                        for (user_id, data) in users {
                            let ts = data.get("data").and_then(|d| d.get("ts")).and_then(Value::as_i64).unwrap_or(0);
                            if let Some(eids) = data.get("event_ids").and_then(Value::as_array) {
                                for eid in eids.iter().filter_map(Value::as_str) {
                                    st.storage
                                        .set_receipt(&RoomId::from(room_id.as_str()), &UserId::from(user_id.as_str()), &EventId::from(eid), rtype, ts, None)
                                        .await;
                                }
                            }
                        }
                    }
                }
            }
        }
        "m.direct_to_device" => {
            let sender = content.get("sender").and_then(Value::as_str).unwrap_or("");
            let event_type = content.get("type").and_then(Value::as_str).unwrap_or("").to_string();
            if let Some(messages) = content.get("messages").and_then(Value::as_object) {
                for (user_id, devices) in messages {
                    let Some(devices) = devices.as_object() else { continue };
                    for (device_id, msg) in devices {
                        let event = ToDeviceEvent {
                            content: msg.as_object().cloned().unwrap_or_default(),
                            sender: sender.into(),
                            event_type: event_type.clone(),
                        };
                        if device_id == "*" {
                            for d in st.storage.get_all_devices(&UserId::from(user_id.as_str())).await {
                                st.storage.send_to_device(&UserId::from(user_id.as_str()), &d.device_id, event.clone()).await;
                            }
                        } else {
                            st.storage
                                .send_to_device(&UserId::from(user_id.as_str()), &DeviceId::from(device_id.as_str()), event.clone())
                                .await;
                        }
                    }
                }
            }
        }
        "m.device_list_update" => {
            if let Some(user_id) = content.get("user_id").and_then(Value::as_str) {
                st.storage.record_device_key_change(&UserId::from(user_id)).await;
            }
        }
        "m.presence" => {
            if let Some(push) = content.get("push").and_then(Value::as_array) {
                for u in push {
                    let user_id = u.get("user_id").and_then(Value::as_str).unwrap_or("");
                    let presence = match u.get("presence").and_then(Value::as_str) {
                        Some("online") => crate::types::ephemeral::PresenceState::Online,
                        Some("unavailable") => crate::types::ephemeral::PresenceState::Unavailable,
                        _ => crate::types::ephemeral::PresenceState::Offline,
                    };
                    if !user_id.is_empty() {
                        st.storage
                            .set_presence(&UserId::from(user_id), presence, u.get("status_msg").and_then(Value::as_str))
                            .await;
                    }
                }
            }
        }
        _ => {}
    }
}
