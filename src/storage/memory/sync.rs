//! `SyncStore` for the in-memory backend.

use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;

use super::{MemoryStorage, TimelineEntry};
use crate::events::{event_to_stripped_state, make_state_key, membership_of, INVITE_STATE_TYPES};
use crate::storage::interface::{EventsSince, RoomMembership, StreamEventRecord, SyncStore};
use crate::types::identifiers::{RoomId, UserId};

#[async_trait]
impl SyncStore for MemoryStorage {
    async fn get_rooms_for_user_with_membership(&self, user_id: &UserId) -> Vec<RoomMembership> {
        let key = make_state_key("m.room.member", user_id.as_str());
        self.read()
            .rooms_by_id
            .values()
            .filter_map(|r| {
                r.state_events
                    .get(&key)
                    .and_then(membership_of)
                    .map(|m| RoomMembership {
                        room_id: r.room_id.clone(),
                        membership: m.to_string(),
                    })
            })
            .collect()
    }

    async fn get_events_by_room_since(
        &self,
        room_id: &RoomId,
        since: i64,
        limit: usize,
    ) -> EventsSince {
        let s = self.read();
        let Some(timeline) = s.room_timeline.get(room_id.as_str()) else {
            return EventsSince::default();
        };
        let filtered: Vec<&TimelineEntry> =
            timeline.iter().filter(|e| e.stream_pos > since).collect();
        let limited = filtered.len() > limit;
        let sliced: &[&TimelineEntry] = if limited {
            &filtered[filtered.len() - limit..]
        } else {
            &filtered[..]
        };
        let events = sliced
            .iter()
            .filter_map(|e| {
                s.events_by_id.get(&e.event_id).map(|ev| StreamEventRecord {
                    event: (**ev).clone(),
                    event_id: e.event_id.clone().into(),
                    stream_pos: e.stream_pos,
                })
            })
            .collect();
        EventsSince { events, limited }
    }

    async fn get_stripped_state(&self, room_id: &RoomId) -> Vec<Value> {
        let s = self.read();
        match s.rooms_by_id.get(room_id.as_str()) {
            Some(room) => room
                .state_events
                .iter()
                .filter(|(k, _)| {
                    let etype = k.split('\u{1f}').next().unwrap_or("");
                    INVITE_STATE_TYPES.contains(&etype)
                })
                .map(|(_, e)| event_to_stripped_state(e))
                .collect(),
            None => Vec::new(),
        }
    }

    async fn wait_for_events(&self, since: i64, timeout_ms: u64) {
        if timeout_ms == 0 {
            return;
        }
        // Register interest BEFORE checking the counter so a wake between the
        // check and the await is not lost.
        let notified = self.notifier().notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.read().stream_counter > since {
            return;
        }
        let _ = tokio::time::timeout(Duration::from_millis(timeout_ms), notified).await;
    }
}
