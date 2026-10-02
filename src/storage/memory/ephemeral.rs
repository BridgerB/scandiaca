//! `EphemeralStore` (typing, receipts, presence) for the in-memory backend.
//!
//! Typing uses lazy expiry: `set_typing` stores an expiry timestamp and
//! `get_typing_users` filters out expired entries. strix uses active timers that
//! also wake `/sync` on expiry; the observable typing set is identical, only the
//! proactive expiry-wake differs.

use async_trait::async_trait;

use super::{next_stream, now_ms, MemoryStorage, ReceiptInternal};
use crate::storage::interface::{
    collapse_receipts_msc4102, EphemeralStore, PresenceRecord, ReceiptRecord,
};
use crate::types::ephemeral::PresenceState;
use crate::types::identifiers::{EventId, RoomId, Timestamp, UserId};

const TYPING_DEFAULT_MS: i64 = 30_000;
const TYPING_MAX_MS: i64 = 120_000;

#[async_trait]
impl EphemeralStore for MemoryStorage {
    async fn set_typing(
        &self,
        room_id: &RoomId,
        user_id: &UserId,
        typing: bool,
        timeout: Option<i64>,
    ) {
        let now = now_ms();
        let ms = timeout.unwrap_or(TYPING_DEFAULT_MS).min(TYPING_MAX_MS);
        {
            let mut s = self.write();
            let changed = {
                let room_typing = s.typing.entry(room_id.to_string()).or_default();
                let was_typing = room_typing
                    .get(user_id.as_str())
                    .map(|&exp| exp > now)
                    .unwrap_or(false);
                if typing {
                    room_typing.insert(user_id.to_string(), now + ms);
                } else {
                    room_typing.remove(user_id.as_str());
                }
                was_typing != typing
            };
            if changed {
                let pos = next_stream(&mut s);
                s.typing_changed_at.insert(room_id.to_string(), pos);
            }
        }
        self.wake_waiters();
    }

    async fn get_typing_users(&self, room_id: &RoomId) -> Vec<UserId> {
        let now = now_ms();
        self.read()
            .typing
            .get(room_id.as_str())
            .map(|m| {
                m.iter()
                    .filter(|(_, &exp)| exp > now)
                    .map(|(u, _)| u.clone().into())
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn get_typing_changed_at(&self, room_id: &RoomId) -> i64 {
        self.read()
            .typing_changed_at
            .get(room_id.as_str())
            .copied()
            .unwrap_or(0)
    }

    async fn set_receipt(
        &self,
        room_id: &RoomId,
        user_id: &UserId,
        event_id: &EventId,
        receipt_type: &str,
        ts: Timestamp,
        thread_id: Option<&str>,
    ) {
        {
            let mut s = self.write();
            // Key by (user, receipt_type, thread) so unthreaded and per-thread
            // receipts coexist. Empty string is the "no thread" sentinel.
            let key = format!(
                "{user_id}\u{1f}{receipt_type}\u{1f}{}",
                thread_id.unwrap_or("")
            );
            s.receipts.entry(room_id.to_string()).or_default().insert(
                key,
                ReceiptInternal {
                    event_id: event_id.to_string(),
                    ts,
                    thread_id: thread_id.map(str::to_string),
                },
            );
        }
        self.wake_waiters();
    }

    async fn get_receipts(&self, room_id: &RoomId) -> Vec<ReceiptRecord> {
        let s = self.read();
        let Some(room_receipts) = s.receipts.get(room_id.as_str()) else {
            return Vec::new();
        };
        let rows: Vec<ReceiptRecord> = room_receipts
            .iter()
            .map(|(key, value)| {
                let mut parts = key.split('\u{1f}');
                let user_id = parts.next().unwrap_or("");
                let receipt_type = parts.next().unwrap_or("");
                ReceiptRecord {
                    event_id: value.event_id.clone().into(),
                    receipt_type: receipt_type.to_string(),
                    user_id: user_id.into(),
                    ts: value.ts,
                    thread_id: value.thread_id.clone(),
                }
            })
            .collect();
        collapse_receipts_msc4102(rows)
    }

    async fn set_presence(
        &self,
        user_id: &UserId,
        presence: PresenceState,
        status_msg: Option<&str>,
    ) {
        {
            let mut s = self.write();
            let pos = next_stream(&mut s);
            s.presence.insert(
                user_id.to_string(),
                PresenceRecord {
                    presence,
                    status_msg: status_msg.map(str::to_string),
                    last_active_ts: Some(now_ms()),
                },
            );
            s.presence_changed_at.insert(user_id.to_string(), pos);
        }
        self.wake_waiters();
    }

    async fn get_presence(&self, user_id: &UserId) -> Option<PresenceRecord> {
        self.read().presence.get(user_id.as_str()).cloned()
    }

    async fn get_presence_changed_at(&self, user_id: &UserId) -> i64 {
        self.read()
            .presence_changed_at
            .get(user_id.as_str())
            .copied()
            .unwrap_or(0)
    }
}
