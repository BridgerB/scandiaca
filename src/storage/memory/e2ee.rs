//! `E2eeStore` for the in-memory backend: device keys, one-time/fallback keys,
//! cross-signing, key backup, to-device, and the device-key-change stream.

use std::collections::{BTreeMap, HashSet};

use async_trait::async_trait;
use serde_json::Value;

use super::{record_device_key_change as bump_device_change, KeyBackupVersionEntry, MemoryStorage};
use crate::storage::interface::{
    E2eeStore, KeyBackupCount, KeyBackupVersionInfo, OneTimeKeyClaim, SignatureFailure,
};
use crate::types::e2ee::{CrossSigningKeys, DeviceKeys, KeyBackupData};
use crate::types::events::ToDeviceEvent;
use crate::types::identifiers::{DeviceId, KeyId, UserId};
use crate::types::json::JsonObject;

fn dk(user_id: &UserId, device_id: &DeviceId) -> String {
    format!("{user_id}\u{1f}{device_id}")
}

/// JS-compatible string hash used for the key-backup etag (strix
/// `computeBackupEtag`): `hash = ((hash << 5) - hash + codeUnit) | 0`, then
/// `String(Math.abs(hash))`. Iterates sorted rooms/sessions for a stable result.
fn compute_backup_etag(
    rooms: Option<&BTreeMap<String, BTreeMap<String, KeyBackupData>>>,
) -> String {
    let Some(rooms) = rooms else {
        return "0".to_string();
    };
    let mut hash: i32 = 0;
    for (room_id, sessions) in rooms {
        for session_id in sessions.keys() {
            for unit in format!("{room_id}{session_id}").encode_utf16() {
                let h = hash;
                hash = h.wrapping_shl(5).wrapping_sub(h).wrapping_add(unit as i32);
            }
        }
    }
    (i64::from(hash)).abs().to_string()
}

fn backup_count(rooms: Option<&BTreeMap<String, BTreeMap<String, KeyBackupData>>>) -> i64 {
    rooms
        .map(|r| r.values().map(|s| s.len() as i64).sum())
        .unwrap_or(0)
}

/// Merge a backup key per the rule: verified > lower first_message_index >
/// lower forwarded_count.
fn merge_backup_key(
    rooms: &mut BTreeMap<String, BTreeMap<String, KeyBackupData>>,
    room_id: &str,
    session_id: &str,
    new_data: KeyBackupData,
) {
    let sessions = rooms.entry(room_id.to_string()).or_default();
    let replace = match sessions.get(session_id) {
        None => true,
        Some(existing) => {
            if new_data.is_verified != existing.is_verified {
                new_data.is_verified
            } else if new_data.first_message_index != existing.first_message_index {
                new_data.first_message_index < existing.first_message_index
            } else {
                new_data.forwarded_count < existing.forwarded_count
            }
        }
    };
    if replace {
        sessions.insert(session_id.to_string(), new_data);
    }
}

#[async_trait]
impl E2eeStore for MemoryStorage {
    async fn set_device_keys(&self, user_id: &UserId, device_id: &DeviceId, keys: DeviceKeys) {
        {
            let mut s = self.write();
            s.device_keys.insert(dk(user_id, device_id), keys);
            bump_device_change(&mut s, user_id.as_str());
        }
        self.wake_waiters();
    }

    async fn get_device_keys(&self, user_id: &UserId, device_id: &DeviceId) -> Option<DeviceKeys> {
        self.read()
            .device_keys
            .get(&dk(user_id, device_id))
            .cloned()
    }

    async fn get_all_device_keys(&self, user_id: &UserId) -> BTreeMap<DeviceId, DeviceKeys> {
        let prefix = format!("{user_id}\u{1f}");
        self.read()
            .device_keys
            .iter()
            .filter_map(|(k, v)| {
                k.strip_prefix(&prefix)
                    .map(|d| (DeviceId::from(d), v.clone()))
            })
            .collect()
    }

    async fn delete_device_keys(&self, user_id: &UserId) {
        let prefix = format!("{user_id}\u{1f}");
        self.write()
            .device_keys
            .retain(|k, _| !k.starts_with(&prefix));
    }

    async fn record_device_key_change(&self, user_id: &UserId) {
        {
            let mut s = self.write();
            bump_device_change(&mut s, user_id.as_str());
        }
        self.wake_waiters();
    }

    async fn get_changed_device_users(&self, since: i64, until: i64) -> Vec<UserId> {
        let s = self.read();
        let mut seen: HashSet<&str> = HashSet::new();
        let mut order: Vec<UserId> = Vec::new();
        for entry in &s.device_list_stream {
            if entry.stream_pos > since
                && entry.stream_pos <= until
                && seen.insert(entry.user_id.as_str())
            {
                order.push(entry.user_id.clone().into());
            }
        }
        order
    }

    async fn add_one_time_keys(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
        keys: BTreeMap<KeyId, Value>,
    ) {
        let mk = dk(user_id, device_id);
        let mut s = self.write();
        let otks = s.one_time_keys.entry(mk).or_default();
        for (key_id, key) in keys {
            otks.insert(key_id.to_string(), key);
        }
    }

    async fn claim_one_time_key(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
        algorithm: &str,
    ) -> Option<OneTimeKeyClaim> {
        let mk = dk(user_id, device_id);
        let prefix = format!("{algorithm}:");
        let mut s = self.write();
        // Prefer a real one-time key (consumed on claim).
        if let Some(otks) = s.one_time_keys.get_mut(&mk) {
            if let Some(key_id) = otks.keys().find(|k| k.starts_with(&prefix)).cloned() {
                let key = otks.remove(&key_id).unwrap();
                return Some(OneTimeKeyClaim {
                    key_id: key_id.into(),
                    key,
                });
            }
        }
        // Fall back to the (reusable) fallback key.
        if let Some(fbs) = s.fallback_keys.get(&mk) {
            if let Some((key_id, key)) = fbs.iter().find(|(k, _)| k.starts_with(&prefix)) {
                return Some(OneTimeKeyClaim {
                    key_id: key_id.clone().into(),
                    key: key.clone(),
                });
            }
        }
        None
    }

    async fn get_one_time_key_counts(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> BTreeMap<String, i64> {
        let s = self.read();
        let mut counts: BTreeMap<String, i64> = BTreeMap::new();
        if let Some(otks) = s.one_time_keys.get(&dk(user_id, device_id)) {
            for key_id in otks.keys() {
                let algo = key_id.split(':').next().unwrap_or("").to_string();
                *counts.entry(algo).or_insert(0) += 1;
            }
        }
        counts
    }

    async fn set_fallback_keys(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
        keys: BTreeMap<KeyId, Value>,
    ) {
        let map = keys.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        self.write()
            .fallback_keys
            .insert(dk(user_id, device_id), map);
    }

    async fn get_fallback_key_types(&self, user_id: &UserId, device_id: &DeviceId) -> Vec<String> {
        let s = self.read();
        let Some(fbs) = s.fallback_keys.get(&dk(user_id, device_id)) else {
            return Vec::new();
        };
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for key_id in fbs.keys() {
            let algo = key_id.split(':').next().unwrap_or("").to_string();
            if seen.insert(algo.clone()) {
                out.push(algo);
            }
        }
        out
    }

    async fn set_cross_signing_keys(&self, user_id: &UserId, keys: CrossSigningKeys) {
        let mut s = self.write();
        let existing = s.cross_signing_keys.entry(user_id.to_string()).or_default();
        if keys.master_key.is_some() {
            existing.master_key = keys.master_key;
        }
        if keys.self_signing_key.is_some() {
            existing.self_signing_key = keys.self_signing_key;
        }
        if keys.user_signing_key.is_some() {
            existing.user_signing_key = keys.user_signing_key;
        }
    }

    async fn get_cross_signing_keys(&self, user_id: &UserId) -> CrossSigningKeys {
        self.read()
            .cross_signing_keys
            .get(user_id.as_str())
            .cloned()
            .unwrap_or_default()
    }

    async fn store_cross_signing_signatures(
        &self,
        user_id: &UserId,
        signatures: BTreeMap<String, BTreeMap<String, JsonObject>>,
    ) -> BTreeMap<String, BTreeMap<String, SignatureFailure>> {
        let mut failures: BTreeMap<String, BTreeMap<String, SignatureFailure>> = BTreeMap::new();
        let mut s = self.write();

        for (target_user, key_map) in signatures {
            for (key_id, signed_object) in key_map {
                let mut fail = |code: &str, msg: &str| {
                    failures.entry(target_user.clone()).or_default().insert(
                        key_id.clone(),
                        SignatureFailure {
                            errcode: code.to_string(),
                            error: msg.to_string(),
                        },
                    );
                };

                let Some(signed_sigs) = signed_object
                    .get("signatures")
                    .and_then(Value::as_object)
                    .cloned()
                else {
                    fail("M_INVALID_SIGNATURE", "Missing signatures field");
                    continue;
                };

                // Authorization: only own devices or other users' master keys.
                if target_user != user_id.as_str() {
                    let is_master = s
                        .cross_signing_keys
                        .get(&target_user)
                        .and_then(|c| c.master_key.as_ref())
                        .map(|mk| {
                            mk.keys
                                .keys()
                                .any(|k| k == &key_id || k.ends_with(&format!(":{key_id}")))
                        })
                        .unwrap_or(false);
                    if !is_master {
                        fail(
                            "M_FORBIDDEN",
                            "Can only sign own devices or other users' master keys",
                        );
                        continue;
                    }
                }

                // Apply to a device key first.
                if let Some(device) = s
                    .device_keys
                    .get_mut(&format!("{target_user}\u{1f}{key_id}"))
                {
                    apply_signatures(&mut device.signatures, &signed_sigs);
                    continue;
                }

                // Otherwise apply to the matching cross-signing key.
                let mut matched = false;
                if let Some(cross) = s.cross_signing_keys.get_mut(&target_user) {
                    for key in [
                        cross.master_key.as_mut(),
                        cross.self_signing_key.as_mut(),
                        cross.user_signing_key.as_mut(),
                    ]
                    .into_iter()
                    .flatten()
                    {
                        if key
                            .keys
                            .keys()
                            .any(|k| k == &key_id || k.ends_with(&format!(":{key_id}")))
                        {
                            let sigs = key.signatures.get_or_insert_with(Default::default);
                            apply_signatures(sigs, &signed_sigs);
                            matched = true;
                            break;
                        }
                    }
                }
                if !matched {
                    fail("M_NOT_FOUND", "Key not found");
                }
            }
        }
        failures
    }

    async fn create_key_backup_version(
        &self,
        user_id: &UserId,
        algorithm: &str,
        auth_data: JsonObject,
    ) -> String {
        let mut s = self.write();
        s.key_backup_counter += 1;
        let version = s.key_backup_counter.to_string();
        s.key_backup_versions
            .entry(user_id.to_string())
            .or_default()
            .push(KeyBackupVersionEntry {
                version: version.clone(),
                algorithm: algorithm.to_string(),
                auth_data,
            });
        version
    }

    async fn get_key_backup_version(
        &self,
        user_id: &UserId,
        version: Option<&str>,
    ) -> Option<KeyBackupVersionInfo> {
        let s = self.read();
        let versions = s.key_backup_versions.get(user_id.as_str())?;
        let v = match version {
            Some(want) => versions.iter().find(|b| b.version == want)?,
            None => versions.last()?,
        };
        let backup_key = format!("{user_id}\u{1f}{}", v.version);
        let rooms = s.key_backup_data.get(&backup_key);
        Some(KeyBackupVersionInfo {
            version: v.version.clone(),
            algorithm: v.algorithm.clone(),
            auth_data: v.auth_data.clone(),
            count: backup_count(rooms),
            etag: compute_backup_etag(rooms),
        })
    }

    async fn update_key_backup_version(
        &self,
        user_id: &UserId,
        version: &str,
        auth_data: JsonObject,
    ) -> bool {
        let mut s = self.write();
        let Some(versions) = s.key_backup_versions.get_mut(user_id.as_str()) else {
            return false;
        };
        match versions.iter_mut().find(|b| b.version == version) {
            Some(v) => {
                v.auth_data = auth_data;
                true
            }
            None => false,
        }
    }

    async fn delete_key_backup_version(&self, user_id: &UserId, version: &str) -> bool {
        let mut s = self.write();
        let removed = match s.key_backup_versions.get_mut(user_id.as_str()) {
            Some(versions) => {
                let before = versions.len();
                versions.retain(|b| b.version != version);
                versions.len() != before
            }
            None => false,
        };
        if removed {
            s.key_backup_data
                .remove(&format!("{user_id}\u{1f}{version}"));
        }
        removed
    }

    async fn put_key_backup_keys(
        &self,
        user_id: &UserId,
        version: &str,
        room_id: Option<&RoomId>,
        session_id: Option<&str>,
        keys: Value,
    ) -> Option<KeyBackupCount> {
        let mut s = self.write();
        let current_version = {
            let versions = s.key_backup_versions.get(user_id.as_str())?;
            versions.last()?.version.clone()
        };
        if current_version != version {
            return None;
        }
        let backup_key = format!("{user_id}\u{1f}{version}");
        let rooms = s.key_backup_data.entry(backup_key).or_default();

        match (room_id, session_id) {
            (Some(rid), Some(sid)) => {
                if let Ok(data) = serde_json::from_value::<KeyBackupData>(keys) {
                    merge_backup_key(rooms, rid.as_str(), sid, data);
                }
            }
            (Some(rid), None) => {
                if let Some(sessions) = keys.get("sessions").and_then(Value::as_object) {
                    for (sid, dval) in sessions {
                        if let Ok(data) = serde_json::from_value::<KeyBackupData>(dval.clone()) {
                            merge_backup_key(rooms, rid.as_str(), sid, data);
                        }
                    }
                }
            }
            _ => {
                if let Some(rooms_obj) = keys.get("rooms").and_then(Value::as_object) {
                    for (rid, rdata) in rooms_obj {
                        if let Some(sessions) = rdata.get("sessions").and_then(Value::as_object) {
                            for (sid, dval) in sessions {
                                if let Ok(data) =
                                    serde_json::from_value::<KeyBackupData>(dval.clone())
                                {
                                    merge_backup_key(rooms, rid, sid, data);
                                }
                            }
                        }
                    }
                }
            }
        }
        let rooms_ref = Some(&*rooms);
        Some(KeyBackupCount {
            count: backup_count(rooms_ref),
            etag: compute_backup_etag(rooms_ref),
        })
    }

    async fn get_key_backup_keys(
        &self,
        user_id: &UserId,
        version: &str,
        room_id: Option<&RoomId>,
        session_id: Option<&str>,
    ) -> Option<Value> {
        let s = self.read();
        let backup_key = format!("{user_id}\u{1f}{version}");
        let rooms = s.key_backup_data.get(&backup_key);

        match (room_id, session_id) {
            (Some(rid), Some(sid)) => rooms
                .and_then(|r| r.get(rid.as_str()))
                .and_then(|sessions| sessions.get(sid))
                .map(|data| serde_json::to_value(data).unwrap_or(Value::Null)),
            (Some(rid), None) => {
                let sessions: BTreeMap<String, &KeyBackupData> = rooms
                    .and_then(|r| r.get(rid.as_str()))
                    .map(|s| s.iter().map(|(k, v)| (k.clone(), v)).collect())
                    .unwrap_or_default();
                Some(serde_json::json!({ "sessions": sessions }))
            }
            _ => {
                let mut out = serde_json::Map::new();
                if let Some(rooms) = rooms {
                    for (rid, sessions) in rooms {
                        out.insert(rid.clone(), serde_json::json!({ "sessions": sessions }));
                    }
                }
                Some(serde_json::json!({ "rooms": Value::Object(out) }))
            }
        }
    }

    async fn delete_key_backup_keys(
        &self,
        user_id: &UserId,
        version: &str,
        room_id: Option<&RoomId>,
        session_id: Option<&str>,
    ) -> Option<KeyBackupCount> {
        let mut s = self.write();
        let exists = s
            .key_backup_versions
            .get(user_id.as_str())
            .map(|vs| vs.iter().any(|v| v.version == version))
            .unwrap_or(false);
        if !exists {
            return None;
        }
        let backup_key = format!("{user_id}\u{1f}{version}");
        let Some(rooms) = s.key_backup_data.get_mut(&backup_key) else {
            return Some(KeyBackupCount {
                count: 0,
                etag: "0".to_string(),
            });
        };
        match (room_id, session_id) {
            (Some(rid), Some(sid)) => {
                if let Some(sessions) = rooms.get_mut(rid.as_str()) {
                    sessions.remove(sid);
                    if sessions.is_empty() {
                        rooms.remove(rid.as_str());
                    }
                }
            }
            (Some(rid), None) => {
                rooms.remove(rid.as_str());
            }
            _ => rooms.clear(),
        }
        let rooms_ref = Some(&*rooms);
        Some(KeyBackupCount {
            count: backup_count(rooms_ref),
            etag: compute_backup_etag(rooms_ref),
        })
    }

    async fn send_to_device(&self, user_id: &UserId, device_id: &DeviceId, event: ToDeviceEvent) {
        {
            let mut s = self.write();
            s.to_device_inbox
                .entry(dk(user_id, device_id))
                .or_default()
                .push(event);
        }
        self.wake_waiters();
    }

    async fn get_to_device_messages(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> Vec<ToDeviceEvent> {
        self.read()
            .to_device_inbox
            .get(&dk(user_id, device_id))
            .cloned()
            .unwrap_or_default()
    }

    async fn clear_to_device_messages(&self, user_id: &UserId, device_id: &DeviceId) {
        self.write().to_device_inbox.remove(&dk(user_id, device_id));
    }
}

use crate::types::e2ee::Signatures;
use crate::types::identifiers::RoomId;

/// Merge `signed_sigs` (`signer -> { keyId: sig }`) into a key's signature map.
fn apply_signatures(target: &mut Signatures, signed_sigs: &serde_json::Map<String, Value>) {
    for (signer, sigs) in signed_sigs {
        if let Some(sigs) = sigs.as_object() {
            let entry = target.entry(signer.clone()).or_default();
            for (key_id, sig) in sigs {
                if let Some(sig) = sig.as_str() {
                    entry.insert(key_id.clone(), sig.to_string());
                }
            }
        }
    }
}
