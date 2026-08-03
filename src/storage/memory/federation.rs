//! `FederationStore` for the in-memory backend: remote keys, auth chain/state,
//! partial state, transaction dedup, the durable EDU queue, room import,
//! 3PID verification, and login tokens.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use super::{next_stream, record_event_delete, MemoryStorage, PersistOp, TimelineEntry};
use crate::events::{compute_event_id, ev_state_key, ev_type, make_state_key, membership_of};
use crate::ids::domain_of;
use crate::storage::interface::{
    DevicePoke, FederationStore, PartialStateRecord, PartialStateRoom, Pdu, PendingEdu,
    ServerKeyRecord, TokenUser, VerificationSession, PENDING_FEDERATION_EDU_CAP,
};
use crate::types::events::Edu;
use crate::types::federation::ServerKeys;
use crate::types::identifiers::{DeviceId, EventId, KeyId, RoomId, ServerName, Timestamp, UserId};
use crate::types::internal::{RoomState, StateEvents};
use crate::types::room_versions::RoomVersion;

#[async_trait]
impl FederationStore for MemoryStorage {
    async fn store_server_keys(&self, server_name: &ServerName, keys: ServerKeys) {
        let mut s = self.write();
        for (key_id, val) in &keys.verify_keys {
            s.server_keys_cache.insert(
                format!("{server_name}\u{1f}{key_id}"),
                ServerKeyRecord {
                    key: val.key.clone(),
                    valid_until: keys.valid_until_ts,
                },
            );
        }
    }

    async fn get_server_keys(
        &self,
        server_name: &ServerName,
        key_id: &KeyId,
    ) -> Option<ServerKeyRecord> {
        self.read()
            .server_keys_cache
            .get(&format!("{server_name}\u{1f}{key_id}"))
            .cloned()
    }

    async fn get_auth_chain(&self, event_ids: &[EventId]) -> Vec<Pdu> {
        let s = self.read();
        let mut visited: HashSet<String> = HashSet::new();
        let mut result: Vec<Pdu> = Vec::new();
        let mut queue: VecDeque<String> = event_ids.iter().map(|e| e.to_string()).collect();
        while let Some(id) = queue.pop_front() {
            if !visited.insert(id.clone()) {
                continue;
            }
            let Some(event) = s.events_by_id.get(&id) else {
                continue;
            };
            result.push((**event).clone());
            for auth_id in event
                .get("auth_events")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(aid) = auth_id.as_str() {
                    if !visited.contains(aid) {
                        queue.push_back(aid.to_string());
                    }
                }
            }
        }
        result
    }

    async fn get_servers_in_room(&self, room_id: &RoomId) -> Vec<ServerName> {
        let s = self.read();
        let Some(room) = s.rooms_by_id.get(room_id.as_str()) else {
            return Vec::new();
        };
        let mut seen: HashSet<String> = HashSet::new();
        let mut servers: Vec<ServerName> = Vec::new();
        for (key, event) in &room.state_events {
            if let Some(state_key) = key.strip_prefix("m.room.member\u{1f}") {
                if matches!(
                    membership_of(event),
                    Some("join") | Some("invite") | Some("knock")
                ) {
                    let server = domain_of(state_key);
                    if seen.insert(server.to_string()) {
                        servers.push(server.into());
                    }
                }
            }
        }
        if let Some(ps) = s.partial_state.get(room_id.as_str()) {
            for srv in &ps.servers {
                if seen.insert(srv.to_string()) {
                    servers.push(srv.clone());
                }
            }
        }
        servers
    }

    async fn get_state_at_event(
        &self,
        room_id: &RoomId,
        _event_id: &EventId,
    ) -> Option<StateEvents> {
        self.read()
            .rooms_by_id
            .get(room_id.as_str())
            .map(|r| r.state_events.clone())
    }

    async fn mark_room_partial_state(
        &self,
        room_id: &RoomId,
        servers: Vec<ServerName>,
        join_event_id: &EventId,
    ) {
        self.write().partial_state.insert(
            room_id.to_string(),
            PartialStateRecord {
                servers,
                join_event_id: join_event_id.clone(),
            },
        );
    }

    async fn clear_room_partial_state(&self, room_id: &RoomId) {
        {
            let mut s = self.write();
            s.partial_state.remove(room_id.as_str());
            let pos = next_stream(&mut s);
            s.un_partial_stated_at.insert(room_id.to_string(), pos);
        }
        // Wakes both /sync waiters and any wait_for_partial_state_clear loops.
        self.wake_waiters();
    }

    async fn get_room_partial_state(&self, room_id: &RoomId) -> Option<PartialStateRecord> {
        self.read().partial_state.get(room_id.as_str()).cloned()
    }

    async fn get_all_partial_state_rooms(&self) -> Vec<PartialStateRoom> {
        self.read()
            .partial_state
            .iter()
            .map(|(room_id, v)| PartialStateRoom {
                room_id: room_id.clone().into(),
                servers: v.servers.clone(),
                join_event_id: v.join_event_id.clone(),
            })
            .collect()
    }

    async fn wait_for_partial_state_clear(&self, room_id: &RoomId, timeout_ms: u64) {
        if !self.read().partial_state.contains_key(room_id.as_str()) {
            return;
        }
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            let notified = self.notifier().notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !self.read().partial_state.contains_key(room_id.as_str()) {
                return;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return;
            }
            if tokio::time::timeout(remaining, notified).await.is_err() {
                return;
            }
        }
    }

    async fn record_partial_state_event(&self, room_id: &RoomId, event_id: &EventId) {
        let mut s = self.write();
        let set = s
            .partial_state_events
            .entry(room_id.to_string())
            .or_default();
        if !set.iter().any(|e| e == event_id.as_str()) {
            set.push(event_id.to_string());
        }
    }

    async fn take_partial_state_events(&self, room_id: &RoomId) -> Vec<EventId> {
        self.write()
            .partial_state_events
            .remove(room_id.as_str())
            .map(|v| v.into_iter().map(Into::into).collect())
            .unwrap_or_default()
    }

    async fn record_partial_state_device_poke(
        &self,
        room_id: &RoomId,
        user_id: &UserId,
        device_id: &DeviceId,
    ) {
        let poke = DevicePoke {
            user_id: user_id.clone(),
            device_id: device_id.clone(),
        };
        let mut s = self.write();
        let set = s
            .partial_state_pokes
            .entry(room_id.to_string())
            .or_default();
        if !set
            .iter()
            .any(|p| p.user_id == poke.user_id && p.device_id == poke.device_id)
        {
            set.push(poke);
        }
    }

    async fn take_partial_state_device_pokes(&self, room_id: &RoomId) -> Vec<DevicePoke> {
        self.write()
            .partial_state_pokes
            .remove(room_id.as_str())
            .unwrap_or_default()
    }

    async fn delete_event(&self, event_id: &EventId) {
        let mut s = self.write();
        let Some(event) = s.events_by_id.remove(event_id.as_str()) else {
            return;
        };
        record_event_delete(&mut s, event_id.as_str());
        let Some(room_id) = event
            .get("room_id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
        else {
            return;
        };
        if let Some(tl) = s.room_timeline.get_mut(&room_id) {
            tl.retain(|e| e.event_id != event_id.as_str());
        }
        if let Some(state_key) = ev_state_key(&event) {
            let key = make_state_key(ev_type(&event), state_key);
            if let Some(room) = s.rooms_by_id.get_mut(&room_id) {
                let matches = room
                    .state_events
                    .get(&key)
                    .map(|cur| compute_event_id(cur, Some(&room.room_version)) == event_id.as_str())
                    .unwrap_or(false);
                if matches {
                    room.state_events.remove(&key);
                    room.state_event_ids.remove(&key);
                }
            }
        }
    }

    async fn unreject_event(&self, _event_id: &EventId) {
        // Memory backend is destructive on delete; nothing to un-reject.
    }

    async fn get_room_un_partial_stated_at(&self, room_id: &RoomId) -> Option<i64> {
        self.read()
            .un_partial_stated_at
            .get(room_id.as_str())
            .copied()
    }

    async fn set_state_event_historical(&self, room_id: &RoomId, event: Pdu, event_id: &EventId) {
        let mut s = self.write();
        let data = std::sync::Arc::new(event.clone());
        s.events_by_id.insert(event_id.to_string(), std::sync::Arc::clone(&data));
        if s.persist_enabled {
            s.pending_persist.push(PersistOp::Upsert {
                event_id: event_id.to_string(),
                room_id: Some(room_id.as_str().to_string()),
                stream_pos: None,
                data,
            });
        }
        let key = make_state_key(ev_type(&event), ev_state_key(&event).unwrap_or(""));
        if let Some(room) = s.rooms_by_id.get_mut(room_id.as_str()) {
            room.state_event_ids.insert(key.clone(), event_id.to_string());
            room.state_events.insert(key, event);
        }
    }

    async fn get_federation_txn(&self, origin: &ServerName, txn_id: &str) -> bool {
        self.read()
            .federation_txns
            .contains(&format!("{origin}\u{1f}{txn_id}"))
    }

    async fn set_federation_txn(&self, origin: &ServerName, txn_id: &str) {
        self.write()
            .federation_txns
            .insert(format!("{origin}\u{1f}{txn_id}"));
    }

    async fn enqueue_federation_edu(&self, destination: &ServerName, edu: Edu) -> i64 {
        let mut s = self.write();
        s.pending_federation_edu_counter += 1;
        let id = s.pending_federation_edu_counter;
        let queue = s
            .pending_federation_edus
            .entry(destination.to_string())
            .or_default();
        queue.push(PendingEdu { id, edu });
        if queue.len() > PENDING_FEDERATION_EDU_CAP {
            let drop_count = queue.len() - PENDING_FEDERATION_EDU_CAP;
            queue.drain(0..drop_count);
            eprintln!(
                "pendingFederationEdus: dropped {drop_count} EDU(s) for {destination} (queue cap {PENDING_FEDERATION_EDU_CAP} exceeded)"
            );
        }
        id
    }

    async fn get_pending_federation_edus(
        &self,
        destination: &ServerName,
        limit: usize,
    ) -> Vec<PendingEdu> {
        self.read()
            .pending_federation_edus
            .get(destination.as_str())
            .map(|q| q.iter().take(limit).cloned().collect())
            .unwrap_or_default()
    }

    async fn delete_federation_edu(&self, id: i64) {
        let mut s = self.write();
        let mut empty_dest: Option<String> = None;
        for (dest, queue) in s.pending_federation_edus.iter_mut() {
            if let Some(idx) = queue.iter().position(|e| e.id == id) {
                queue.remove(idx);
                if queue.is_empty() {
                    empty_dest = Some(dest.clone());
                }
                break;
            }
        }
        if let Some(dest) = empty_dest {
            s.pending_federation_edus.remove(&dest);
        }
    }

    async fn get_pending_federation_destinations(&self) -> Vec<ServerName> {
        self.read()
            .pending_federation_edus
            .keys()
            .map(|k| k.clone().into())
            .collect()
    }

    async fn store_verification_token(&self, session_id: &str, data: VerificationSession) {
        self.write()
            .verification_sessions
            .insert(session_id.to_string(), data);
    }

    async fn get_verification_session(&self, session_id: &str) -> Option<VerificationSession> {
        self.read().verification_sessions.get(session_id).cloned()
    }

    async fn validate_verification_token(&self, session_id: &str, token: &str) -> bool {
        let mut s = self.write();
        match s.verification_sessions.get_mut(session_id) {
            Some(session) if session.token == token => {
                session.validated = true;
                true
            }
            _ => false,
        }
    }

    async fn store_login_token(&self, token: &str, user_id: &UserId, expires_at: Timestamp) {
        self.write().login_tokens.insert(
            token.to_string(),
            TokenUser {
                user_id: user_id.clone(),
                expires_at,
            },
        );
    }

    async fn get_login_token(&self, token: &str) -> Option<TokenUser> {
        self.read().login_tokens.get(token).cloned()
    }

    async fn delete_login_token(&self, token: &str) {
        self.write().login_tokens.remove(token);
    }

    async fn import_room_state(
        &self,
        room_id: &RoomId,
        room_version: RoomVersion,
        state_events: Vec<Pdu>,
        auth_chain: Vec<Pdu>,
    ) {
        {
            let mut s = self.write();
            let persist_enabled = s.persist_enabled;
            let mut ops: Vec<PersistOp> = Vec::new();
            let rv = Some(room_version.as_str());
            for event in &auth_chain {
                let id = compute_event_id(event, rv);
                let data = std::sync::Arc::new(event.clone());
                s.events_by_id.insert(id.clone(), std::sync::Arc::clone(&data));
                if persist_enabled {
                    ops.push(PersistOp::Upsert {
                        event_id: id,
                        room_id: event.get("room_id").and_then(|v| v.as_str()).map(str::to_string),
                        stream_pos: None,
                        data,
                    });
                }
            }

            let mut state_map: StateEvents = BTreeMap::new();
            let mut state_id_map: BTreeMap<String, String> = BTreeMap::new();
            let mut max_depth: i64 = 0;
            let mut extremities: Vec<EventId> = Vec::new();
            let mut timeline_entries: Vec<TimelineEntry> = Vec::new();

            for event in &state_events {
                let id = compute_event_id(event, rv);
                let data = std::sync::Arc::new(event.clone());
                s.events_by_id.insert(id.clone(), std::sync::Arc::clone(&data));
                let sk = make_state_key(ev_type(event), ev_state_key(event).unwrap_or(""));
                state_id_map.insert(sk.clone(), id.clone());
                state_map.insert(sk, event.clone());
                let pos = next_stream(&mut s);
                if persist_enabled {
                    ops.push(PersistOp::Upsert {
                        event_id: id.clone(),
                        room_id: Some(room_id.as_str().to_string()),
                        stream_pos: Some(pos),
                        data,
                    });
                }
                timeline_entries.push(TimelineEntry {
                    event_id: id.clone(),
                    stream_pos: pos,
                });
                let depth = event.get("depth").and_then(|v| v.as_i64()).unwrap_or(0);
                if depth > max_depth {
                    max_depth = depth;
                }
                extremities = vec![id.into()];
            }

            s.room_timeline
                .entry(room_id.to_string())
                .or_default()
                .extend(timeline_entries);
            s.rooms_by_id.insert(
                room_id.to_string(),
                RoomState {
                    room_id: room_id.clone(),
                    room_version,
                    state_events: state_map,
                    depth: max_depth + 1,
                    forward_extremities: extremities,
                    state_event_ids: state_id_map,
                },
            );
            if persist_enabled {
                s.pending_persist.extend(ops);
            }
        }
        self.wake_waiters();
    }
}
