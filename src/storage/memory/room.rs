//! `RoomStore` for the in-memory backend.

use async_trait::async_trait;
use serde_json::{Map, Value};

use super::{record_event_update, store_event_locked, AliasEntry, MemoryStorage, TimelineEntry};
use crate::events::{compute_event_id, ev_state_key, ev_type, make_state_key, membership_of};
use crate::storage::interface::{
    AliasRecord, Direction, EventRecord, EventsPage, Pdu, RoomStore, StoredEvent, Visibility,
};
use crate::types::identifiers::{DeviceId, EventId, RoomAlias, RoomId, ServerName, UserId};
use crate::types::internal::RoomState;

#[async_trait]
impl RoomStore for MemoryStorage {
    async fn create_room(&self, state: RoomState) {
        let mut s = self.write();
        let rid = state.room_id.to_string();
        s.rooms_by_id.insert(rid.clone(), state);
        s.room_timeline.entry(rid).or_default();
    }

    async fn get_room(&self, room_id: &RoomId) -> Option<RoomState> {
        self.read().rooms_by_id.get(room_id.as_str()).cloned()
    }

    async fn get_rooms_for_user(&self, user_id: &UserId) -> Vec<RoomId> {
        let key = make_state_key("m.room.member", user_id.as_str());
        self.read()
            .rooms_by_id
            .values()
            .filter(|r| r.state_events.get(&key).and_then(membership_of) == Some("join"))
            .map(|r| r.room_id.clone())
            .collect()
    }

    async fn update_room_dag(
        &self,
        room_id: &RoomId,
        depth: i64,
        forward_extremities: Vec<EventId>,
    ) {
        if let Some(room) = self.write().rooms_by_id.get_mut(room_id.as_str()) {
            room.depth = depth;
            room.forward_extremities = forward_extremities;
        }
    }

    async fn store_event(&self, event: Pdu, event_id: &EventId) {
        {
            let mut s = self.write();
            store_event_locked(&mut s, event, event_id.as_str());
        }
        self.wake_waiters();
    }

    async fn commit_timeline_event(
        &self,
        event: Pdu,
        event_id: &EventId,
        room_id: &RoomId,
        new_depth: i64,
        forward_extremities: Vec<EventId>,
        txn_key: &str,
    ) {
        {
            let mut s = self.write();
            store_event_locked(&mut s, event, event_id.as_str());
            if let Some(room) = s.rooms_by_id.get_mut(room_id.as_str()) {
                room.depth = new_depth;
                room.forward_extremities = forward_extremities;
            }
            s.txn_map.insert(txn_key.to_string(), event_id.to_string());
        }
        self.wake_waiters();
    }

    async fn update_event(&self, event_id: &EventId, event: Pdu) {
        let mut s = self.write();
        let data = std::sync::Arc::new(event);
        s.events_by_id.insert(event_id.to_string(), std::sync::Arc::clone(&data));
        record_event_update(&mut s, event_id.as_str(), data);
    }

    async fn get_event(&self, event_id: &EventId) -> Option<StoredEvent> {
        self.read()
            .events_by_id
            .get(event_id.as_str())
            .map(|e| StoredEvent {
                event: (**e).clone(),
                event_id: event_id.clone(),
                rejected: false,
            })
    }

    async fn get_events_by_room(
        &self,
        room_id: &RoomId,
        limit: usize,
        from: Option<i64>,
        direction: Direction,
    ) -> EventsPage {
        let s = self.read();
        let Some(timeline) = s.room_timeline.get(room_id.as_str()) else {
            return EventsPage::default();
        };
        let from_pos = from.unwrap_or(match direction {
            Direction::Forward => 0,
            Direction::Backward => s.stream_counter + 1,
        });
        let mut filtered: Vec<&TimelineEntry> = match direction {
            Direction::Forward => timeline
                .iter()
                .filter(|e| e.stream_pos > from_pos)
                .collect(),
            Direction::Backward => {
                let mut v: Vec<&TimelineEntry> = timeline
                    .iter()
                    .filter(|e| e.stream_pos < from_pos)
                    .collect();
                v.reverse();
                v
            }
        };
        filtered.truncate(limit);
        let end = filtered.last().map(|e| e.stream_pos);
        let events = filtered
            .iter()
            .filter_map(|e| {
                s.events_by_id.get(&e.event_id).map(|ev| EventRecord {
                    event: (**ev).clone(),
                    event_id: e.event_id.clone().into(),
                })
            })
            .collect();
        EventsPage { events, end }
    }

    async fn get_stream_position(&self) -> i64 {
        self.read().stream_counter
    }

    async fn get_state_event(
        &self,
        room_id: &RoomId,
        event_type: &str,
        state_key: &str,
    ) -> Option<EventRecord> {
        let s = self.read();
        let room = s.rooms_by_id.get(room_id.as_str())?;
        let event = room
            .state_events
            .get(&make_state_key(event_type, state_key))?;
        Some(EventRecord {
            event: event.clone(),
            event_id: compute_event_id(event, Some(&room.room_version)).into(),
        })
    }

    async fn get_all_state(&self, room_id: &RoomId) -> Vec<EventRecord> {
        let s = self.read();
        match s.rooms_by_id.get(room_id.as_str()) {
            Some(room) => room
                .state_events
                .values()
                .map(|e| EventRecord {
                    event: e.clone(),
                    event_id: compute_event_id(e, Some(&room.room_version)).into(),
                })
                .collect(),
            None => Vec::new(),
        }
    }

    async fn set_state_event(&self, room_id: &RoomId, event: Pdu, event_id: &EventId) {
        {
            let mut s = self.write();
            let Some(room_version) = s
                .rooms_by_id
                .get(room_id.as_str())
                .map(|r| r.room_version.clone())
            else {
                return;
            };
            let key = make_state_key(ev_type(&event), ev_state_key(&event).unwrap_or(""));

            // Stamp prev_content/prev_sender/replaces_state when replacing a
            // different event of the same (type, state_key). `unsigned` is excluded
            // from the hash, so this does not change the event ID.
            let prev_stamp = s
                .rooms_by_id
                .get(room_id.as_str())
                .and_then(|r| r.state_events.get(&key))
                .map(|prev| {
                    (
                        prev.get("content")
                            .cloned()
                            .unwrap_or(Value::Object(Map::new())),
                        prev.get("sender").cloned().unwrap_or(Value::Null),
                        compute_event_id(prev, Some(&room_version)),
                    )
                });

            let mut event = event;
            if let Some((prev_content, prev_sender, prev_id)) = prev_stamp {
                if prev_id != event_id.as_str() {
                    if let Some(obj) = event.as_object_mut() {
                        let unsigned = obj
                            .entry("unsigned")
                            .or_insert_with(|| Value::Object(Map::new()));
                        if let Some(u) = unsigned.as_object_mut() {
                            u.insert("prev_content".to_string(), prev_content);
                            u.insert("prev_sender".to_string(), prev_sender);
                            u.insert("replaces_state".to_string(), Value::String(prev_id));
                        }
                    }
                }
            }

            if let Some(room) = s.rooms_by_id.get_mut(room_id.as_str()) {
                room.state_event_ids.insert(key.clone(), event_id.as_str().to_string());
                room.state_events.insert(key, event.clone());
            }
            store_event_locked(&mut s, event, event_id.as_str());
        }
        self.wake_waiters();
    }

    async fn get_member_events(&self, room_id: &RoomId) -> Vec<EventRecord> {
        let s = self.read();
        match s.rooms_by_id.get(room_id.as_str()) {
            Some(room) => room
                .state_events
                .iter()
                .filter(|(k, _)| k.starts_with("m.room.member\u{1f}"))
                .map(|(_, e)| EventRecord {
                    event: e.clone(),
                    event_id: compute_event_id(e, Some(&room.room_version)).into(),
                })
                .collect(),
            None => Vec::new(),
        }
    }

    async fn get_txn_event_id(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
        txn_id: &str,
    ) -> Option<EventId> {
        let key = format!("{user_id}|{device_id}|{txn_id}");
        self.read().txn_map.get(&key).map(|s| s.clone().into())
    }

    async fn set_txn_event_id(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
        txn_id: &str,
        event_id: &EventId,
    ) {
        let key = format!("{user_id}|{device_id}|{txn_id}");
        self.write().txn_map.insert(key, event_id.to_string());
    }

    async fn create_room_alias(
        &self,
        room_alias: &RoomAlias,
        room_id: &RoomId,
        servers: Vec<ServerName>,
        creator: &UserId,
    ) {
        self.write().aliases.insert(
            room_alias.to_string(),
            AliasEntry {
                room_id: room_id.to_string(),
                servers: servers.into_iter().map(|s| s.to_string()).collect(),
                creator: creator.to_string(),
            },
        );
    }

    async fn delete_room_alias(&self, room_alias: &RoomAlias) -> bool {
        self.write().aliases.remove(room_alias.as_str()).is_some()
    }

    async fn get_room_by_alias(&self, room_alias: &RoomAlias) -> Option<AliasRecord> {
        self.read()
            .aliases
            .get(room_alias.as_str())
            .map(|e| AliasRecord {
                room_id: e.room_id.clone().into(),
                servers: e.servers.iter().map(|s| s.clone().into()).collect(),
            })
    }

    async fn get_aliases_for_room(&self, room_id: &RoomId) -> Vec<RoomAlias> {
        self.read()
            .aliases
            .iter()
            .filter(|(_, e)| e.room_id == room_id.as_str())
            .map(|(a, _)| a.clone().into())
            .collect()
    }

    async fn get_alias_creator(&self, room_alias: &RoomAlias) -> Option<UserId> {
        self.read()
            .aliases
            .get(room_alias.as_str())
            .map(|e| e.creator.clone().into())
    }

    async fn set_room_visibility(&self, room_id: &RoomId, visibility: Visibility) {
        let mut s = self.write();
        match visibility {
            Visibility::Public => {
                s.public_rooms.insert(room_id.to_string());
            }
            Visibility::Private => {
                s.public_rooms.remove(room_id.as_str());
            }
        }
    }

    async fn get_room_visibility(&self, room_id: &RoomId) -> Visibility {
        if self.read().public_rooms.contains(room_id.as_str()) {
            Visibility::Public
        } else {
            Visibility::Private
        }
    }

    async fn get_public_room_ids(&self) -> Vec<RoomId> {
        self.read()
            .public_rooms
            .iter()
            .map(|r| r.clone().into())
            .collect()
    }
}
