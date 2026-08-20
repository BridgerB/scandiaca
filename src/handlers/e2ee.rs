//! E2EE key handlers — port of strix `handlers/e2ee.ts` (local paths; remote
//! users over federation arrive with the federation phase).

use std::collections::{BTreeMap, HashSet};
use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::response::Json;
use serde_json::{json, Map, Value};

use crate::errors::{bad_json, MatrixResult};
use crate::ids::domain_of;
use crate::server::{AppState, AuthCtx};
use crate::types::e2ee::DeviceKeys;
use crate::types::identifiers::{DeviceId, KeyId, RoomId, UserId};

/// Process-local monotonic device-list stream counter (strix
/// `deviceListStreamCounter`), stamped into outbound `m.device_list_update`.
static DEVICE_LIST_STREAM: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Notify remote servers sharing a joined room with `user_id` that the user's
/// device list changed, via one `m.device_list_update` EDU per destination
/// (strix `sendDeviceListUpdate`). Fire-and-forget; partial-state device-poke
/// queueing is deferred.
pub async fn send_device_list_update(st: &AppState, user_id: &UserId, device_id: &DeviceId) {
    let Some(fed) = &st.federation_client else { return };

    let mut dests: HashSet<String> = HashSet::new();
    for room_id in st.storage.get_rooms_for_user(user_id).await {
        for rec in st.storage.get_member_events(&room_id).await {
            let membership = rec
                .event
                .get("content")
                .and_then(|c| c.get("membership"))
                .and_then(Value::as_str);
            if membership != Some("join") {
                continue;
            }
            let Some(member) = rec.event.get("state_key").and_then(Value::as_str) else { continue };
            let server = domain_of(member);
            if !server.is_empty() && server != st.server_name.as_ref() {
                dests.insert(server.to_string());
            }
        }
    }
    if dests.is_empty() {
        return;
    }

    let stream_id = DEVICE_LIST_STREAM.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    let mut content = json!({
        "user_id": user_id.as_str(),
        "device_id": device_id.as_str(),
        "stream_id": stream_id,
        "prev_id": if stream_id > 1 { json!([stream_id - 1]) } else { json!([]) },
        "deleted": false,
    });
    if let Some(keys) = st.storage.get_device_keys(user_id, device_id).await {
        content["keys"] = serde_json::to_value(keys).unwrap_or(Value::Null);
    }
    if let Some(device) = st.storage.get_device(user_id, device_id).await {
        if let Some(name) = device.display_name {
            content["device_display_name"] = json!(name);
        }
    }
    let edu = json!({ "edu_type": "m.device_list_update", "content": content });
    for dest in dests {
        crate::federation::outbound::deliver_edu_to_destination(&*st.storage, fed, &st.server_name, &dest, edu.clone()).await;
    }
}

/// After a LOCAL user joins `room_id`, announce their device list to the room's
/// resident remote servers via one `m.device_list_update` EDU per device — so a
/// server that did not previously share a room with the user learns their devices
/// (TestDeviceListsUpdateOverFederationOnRoomJoin). Mirrors strix
/// `notifyDeviceListUpdateOnJoin`. Fire-and-forget.
pub async fn notify_device_list_update_on_join(st: &AppState, room_id: &RoomId, user_id: &UserId) {
    let Some(fed) = &st.federation_client else { return };
    // Only the joining user's own server announces that user's devices.
    if domain_of(user_id.as_str()) != st.server_name.as_ref() {
        return;
    }
    let dests: Vec<String> = st
        .storage
        .get_servers_in_room(room_id)
        .await
        .into_iter()
        .map(|s| s.as_str().to_string())
        .filter(|s| !s.is_empty() && s != st.server_name.as_ref())
        .collect();
    if dests.is_empty() {
        return;
    }
    for device in st.storage.get_all_devices(user_id).await {
        let device_id = device.device_id;
        let stream_id = DEVICE_LIST_STREAM.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        let mut content = json!({
            "user_id": user_id.as_str(),
            "device_id": device_id.as_str(),
            "stream_id": stream_id,
            "prev_id": [],
            "deleted": false,
        });
        if let Some(name) = device.display_name {
            content["device_display_name"] = json!(name);
        }
        if let Some(keys) = st.storage.get_device_keys(user_id, &device_id).await {
            content["keys"] = serde_json::to_value(keys).unwrap_or(Value::Null);
        }
        let edu = json!({ "edu_type": "m.device_list_update", "content": content });
        for dest in &dests {
            crate::federation::outbound::deliver_edu_to_destination(&*st.storage, fed, &st.server_name, dest, edu.clone()).await;
        }
    }
}

/// `POST /_matrix/client/v3/keys/upload`.
pub async fn post_keys_upload(
    State(st): State<AppState>,
    auth: AuthCtx,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let mut device_keys_changed = false;
    if let Some(dk) = body.get("device_keys") {
        let device_keys: DeviceKeys = serde_json::from_value(dk.clone())
            .map_err(|_| bad_json("device_keys must include algorithms, keys and signatures"))?;
        if device_keys.user_id.as_str() != auth.user_id.as_str()
            || device_keys.device_id.as_str() != auth.device_id.as_str()
        {
            return Err(bad_json("device_keys user_id/device_id must match authenticated user"));
        }
        st.storage
            .set_device_keys(&auth.user_id, &auth.device_id, device_keys)
            .await;
        device_keys_changed = true;
    }

    if let Some(otks) = body.get("one_time_keys").and_then(Value::as_object) {
        if !otks.is_empty() {
            st.storage
                .add_one_time_keys(&auth.user_id, &auth.device_id, to_keyid_map(otks))
                .await;
        }
    }
    if let Some(fbs) = body.get("fallback_keys").and_then(Value::as_object) {
        if !fbs.is_empty() {
            st.storage
                .set_fallback_keys(&auth.user_id, &auth.device_id, to_keyid_map(fbs))
                .await;
        }
    }

    // Notify remote servers sharing a room that this user's device list changed.
    if device_keys_changed {
        send_device_list_update(&st, &auth.user_id, &auth.device_id).await;
    }

    let counts = st.storage.get_one_time_key_counts(&auth.user_id, &auth.device_id).await;
    Ok(Json(json!({ "one_time_key_counts": counts })))
}

/// `POST /_matrix/client/v3/keys/query`.
pub async fn post_keys_query(
    State(st): State<AppState>,
    _auth: AuthCtx,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let Some(request) = body.get("device_keys").and_then(Value::as_object) else {
        return Err(bad_json("Missing device_keys field"));
    };
    let requester = _auth.user_id.as_str();

    let mut device_keys = Map::new();
    let mut master_keys = Map::new();
    let mut self_signing_keys = Map::new();
    let mut user_signing_keys = Map::new();

    // Split requested users by homeserver: local users are served from our
    // store; users on other servers are federated one request per destination
    // (strix `postKeysQuery`). The device-list tracking/caching optimization is
    // deferred — we always do an on-demand /user/keys/query for remote users.
    let mut remote_by_dest: HashMap<String, Map<String, Value>> = HashMap::new();

    for (target, device_ids) in request {
        let dest = domain_of(target).to_string();
        let is_local = st.federation_client.is_none() || dest == *st.server_name;
        if !is_local {
            remote_by_dest.entry(dest).or_default().insert(target.clone(), device_ids.clone());
            continue;
        }

        let uid = UserId::from(target.as_str());
        let ids = device_ids.as_array().ok_or_else(|| {
            bad_json(format!("device_keys for {target} must be an array of device IDs"))
        })?;

        let mut user_devices = Map::new();
        if ids.is_empty() {
            for (did, keys) in st.storage.get_all_device_keys(&uid).await {
                user_devices.insert(did.as_str().to_string(), with_display_name(&st, &uid, &did, keys).await);
            }
        } else {
            for did_val in ids {
                let Some(did_str) = did_val.as_str() else { continue };
                let did = DeviceId::from(did_str);
                if let Some(keys) = st.storage.get_device_keys(&uid, &did).await {
                    user_devices.insert(did_str.to_string(), with_display_name(&st, &uid, &did, keys).await);
                }
            }
        }
        device_keys.insert(target.clone(), Value::Object(user_devices));

        let cross = st.storage.get_cross_signing_keys(&uid).await;
        if let Some(mk) = cross.master_key {
            master_keys.insert(target.clone(), serde_json::to_value(mk).unwrap_or(Value::Null));
        }
        if let Some(ssk) = cross.self_signing_key {
            self_signing_keys.insert(target.clone(), serde_json::to_value(ssk).unwrap_or(Value::Null));
        }
        if target == requester {
            if let Some(usk) = cross.user_signing_key {
                user_signing_keys.insert(target.clone(), serde_json::to_value(usk).unwrap_or(Value::Null));
            }
        }
    }

    // Federate remote users: one request per destination, merging results.
    // Per-destination errors are recorded in `failures` and don't abort.
    let mut failures = Map::new();
    if let Some(fed) = &st.federation_client {
        for (dest, group) in remote_by_dest {
            let req_body = json!({ "device_keys": Value::Object(group) });
            match fed.request(&dest, "POST", "/_matrix/federation/v1/user/keys/query", Some(req_body)).await {
                Ok(resp) if resp.status == 200 => {
                    if let Some(dk) = resp.body.get("device_keys").and_then(Value::as_object) {
                        for (u, keys) in dk {
                            device_keys.insert(u.clone(), keys.clone());
                        }
                    }
                    if let Some(mk) = resp.body.get("master_keys").and_then(Value::as_object) {
                        for (u, k) in mk {
                            master_keys.insert(u.clone(), k.clone());
                        }
                    }
                    if let Some(ssk) = resp.body.get("self_signing_keys").and_then(Value::as_object) {
                        for (u, k) in ssk {
                            self_signing_keys.insert(u.clone(), k.clone());
                        }
                    }
                }
                Ok(resp) => {
                    failures.insert(dest, json!({ "message": format!("status {}", resp.status) }));
                }
                Err(e) => {
                    failures.insert(dest, json!({ "message": e.to_string() }));
                }
            }
        }
    }

    let mut resp = json!({ "device_keys": device_keys });
    if !master_keys.is_empty() {
        resp["master_keys"] = Value::Object(master_keys);
    }
    if !self_signing_keys.is_empty() {
        resp["self_signing_keys"] = Value::Object(self_signing_keys);
    }
    if !user_signing_keys.is_empty() {
        resp["user_signing_keys"] = Value::Object(user_signing_keys);
    }
    if !failures.is_empty() {
        resp["failures"] = Value::Object(failures);
    }
    Ok(Json(resp))
}

/// `POST /_matrix/client/v3/keys/claim`.
pub async fn post_keys_claim(
    State(st): State<AppState>,
    _auth: AuthCtx,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let Some(request) = body.get("one_time_keys").and_then(Value::as_object) else {
        return Err(bad_json("Missing one_time_keys field"));
    };
    let mut one_time_keys = Map::new();
    let mut remote_by_dest: HashMap<String, Map<String, Value>> = HashMap::new();

    for (target, devices) in request {
        let dest = domain_of(target).to_string();
        let is_local = st.federation_client.is_none() || dest == *st.server_name;
        if !is_local {
            remote_by_dest.entry(dest).or_default().insert(target.clone(), devices.clone());
            continue;
        }
        let uid = UserId::from(target.as_str());
        let Some(devices) = devices.as_object() else { continue };
        let mut user_keys = Map::new();
        for (device_id, algorithm) in devices {
            let Some(algo) = algorithm.as_str() else { continue };
            if let Some(claimed) = st
                .storage
                .claim_one_time_key(&uid, &DeviceId::from(device_id.as_str()), algo)
                .await
            {
                let mut km = Map::new();
                km.insert(claimed.key_id.as_str().to_string(), claimed.key);
                user_keys.insert(device_id.clone(), Value::Object(km));
            }
        }
        if !user_keys.is_empty() {
            one_time_keys.insert(target.clone(), Value::Object(user_keys));
        }
    }

    // Federate remote claims: one request per destination, merging results.
    if let Some(fed) = &st.federation_client {
        for (dest, group) in remote_by_dest {
            let req_body = json!({ "one_time_keys": Value::Object(group) });
            if let Ok(resp) = fed
                .request(&dest, "POST", "/_matrix/federation/v1/user/keys/claim", Some(req_body))
                .await
            {
                if resp.status == 200 {
                    if let Some(otk) = resp.body.get("one_time_keys").and_then(Value::as_object) {
                        for (u, keys) in otk {
                            one_time_keys.insert(u.clone(), keys.clone());
                        }
                    }
                }
            }
        }
    }
    Ok(Json(json!({ "one_time_keys": one_time_keys })))
}

/// `PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}`.
pub async fn put_send_to_device(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((event_type, _txn_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let Some(messages) = body.get("messages").and_then(Value::as_object) else {
        return Err(bad_json("Missing messages field"));
    };
    // Remote targets are forwarded to their owning server via an
    // `m.direct_to_device` EDU (strix `putSendToDevice`); the `*` wildcard is
    // left intact for the destination to expand against its own device list.
    let mut remote_by_dest: HashMap<String, Map<String, Value>> = HashMap::new();
    for (target, devices) in messages {
        let dest = domain_of(target).to_string();
        let is_local = st.federation_client.is_none() || dest == *st.server_name;
        if !is_local {
            remote_by_dest.entry(dest).or_default().insert(target.clone(), devices.clone());
            continue;
        }
        let uid = UserId::from(target.as_str());
        let Some(devices) = devices.as_object() else { continue };
        for (device_id, content) in devices {
            let content_obj = content.as_object().cloned().unwrap_or_default();
            let event = crate::types::events::ToDeviceEvent {
                content: content_obj,
                sender: auth.user_id.clone(),
                event_type: event_type.clone(),
            };
            if device_id == "*" {
                for device in st.storage.get_all_devices(&uid).await {
                    st.storage.send_to_device(&uid, &device.device_id, event.clone()).await;
                }
            } else {
                st.storage
                    .send_to_device(&uid, &DeviceId::from(device_id.as_str()), event.clone())
                    .await;
            }
        }
    }

    // Deliver one `m.direct_to_device` EDU per remote destination (best-effort;
    // durable replay deferred).
    if let Some(fed) = &st.federation_client {
        for (dest, group) in remote_by_dest {
            let edu = json!({
                "edu_type": "m.direct_to_device",
                "content": {
                    "sender": auth.user_id.as_str(),
                    "type": event_type,
                    "message_id": crate::crypto::generate_token(),
                    "messages": Value::Object(group),
                },
            });
            crate::federation::outbound::deliver_edu_to_destination(&*st.storage, fed, &st.server_name, &dest, edu).await;
        }
    }
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v3/keys/changes`.
pub async fn get_keys_changes(
    State(st): State<AppState>,
    auth: AuthCtx,
    Query(params): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let from: i64 = params.get("from").and_then(|s| s.parse().ok())
        .ok_or_else(|| bad_json("Missing 'from' query parameter"))?;
    let to: i64 = params.get("to").and_then(|s| s.parse().ok())
        .ok_or_else(|| bad_json("Missing 'to' query parameter"))?;

    let changed_in_window: HashSet<String> = st
        .storage
        .get_changed_device_users(from, to)
        .await
        .into_iter()
        .map(|u| u.as_str().to_string())
        .collect();

    let joined: Vec<_> = st
        .storage
        .get_rooms_for_user_with_membership(&auth.user_id)
        .await
        .into_iter()
        .filter(|r| r.membership == "join")
        .map(|r| r.room_id)
        .collect();

    let mut shared: HashSet<String> = HashSet::new();
    for room_id in &joined {
        for m in st.storage.get_member_events(room_id).await {
            if m.event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("join") {
                if let Some(sk) = m.event.get("state_key").and_then(Value::as_str) {
                    if sk != auth.user_id.as_str() {
                        shared.insert(sk.to_string());
                    }
                }
            }
        }
    }

    let mut changed_set: HashSet<String> = HashSet::new();
    let mut left: Vec<String> = Vec::new();
    for u in &changed_in_window {
        if shared.contains(u) {
            changed_set.insert(u.clone());
        } else if u != auth.user_id.as_str() {
            left.push(u.clone());
        }
    }
    // Users who newly joined a shared room in (from, to].
    for room_id in &joined {
        let window = st.storage.get_events_by_room_since(room_id, from, 100_000).await;
        for er in window.events {
            if er.event.get("type").and_then(Value::as_str) == Some("m.room.member")
                && er.event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("join")
            {
                if let Some(sk) = er.event.get("state_key").and_then(Value::as_str) {
                    if sk != auth.user_id.as_str() {
                        changed_set.insert(sk.to_string());
                    }
                }
            }
        }
    }

    Ok(Json(json!({
        "changed": changed_set.into_iter().collect::<Vec<_>>(),
        "left": left,
    })))
}

fn to_keyid_map(obj: &Map<String, Value>) -> BTreeMap<KeyId, Value> {
    obj.iter().map(|(k, v)| (KeyId::from(k.as_str()), v.clone())).collect()
}

/// Serialize device keys to JSON, folding the device's display name into
/// `unsigned.device_display_name` (strix `withDeviceDisplayName`).
pub(crate) async fn with_display_name(st: &AppState, user_id: &UserId, device_id: &DeviceId, keys: DeviceKeys) -> Value {
    let mut v = serde_json::to_value(keys).unwrap_or(Value::Null);
    if let Some(device) = st.storage.get_device(user_id, device_id).await {
        if let Some(name) = device.display_name {
            if let Some(obj) = v.as_object_mut() {
                let unsigned = obj.entry("unsigned").or_insert_with(|| json!({}));
                if let Some(u) = unsigned.as_object_mut() {
                    u.insert("device_display_name".to_string(), json!(name));
                }
            }
        }
    }
    v
}
