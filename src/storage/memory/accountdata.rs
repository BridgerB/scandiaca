//! `AccountDataStore` for the in-memory backend.
//!
//! MSC3391 deletions leave an empty-content tombstone with a fresh stream
//! position: excluded from initial sync, included in incremental sync.

use async_trait::async_trait;
use serde_json::Map;

use super::{next_stream, AccountDataInternal, MemoryStorage};
use crate::storage::interface::{AccountDataEntry, AccountDataStore, RoomAccountDataEntry};
use crate::types::identifiers::{RoomId, UserId};
use crate::types::json::JsonObject;

fn room_key(user_id: &UserId, room_id: &RoomId) -> String {
    format!("{user_id}\u{1f}{room_id}")
}

#[async_trait]
impl AccountDataStore for MemoryStorage {
    async fn get_global_account_data(
        &self,
        user_id: &UserId,
        data_type: &str,
    ) -> Option<JsonObject> {
        self.read()
            .global_account_data
            .get(user_id.as_str())
            .and_then(|m| m.get(data_type))
            .map(|e| e.content.clone())
    }

    async fn set_global_account_data(
        &self,
        user_id: &UserId,
        data_type: &str,
        content: JsonObject,
    ) {
        {
            let mut s = self.write();
            let pos = next_stream(&mut s);
            s.global_account_data
                .entry(user_id.to_string())
                .or_default()
                .insert(
                    data_type.to_string(),
                    AccountDataInternal {
                        content,
                        stream_pos: pos,
                    },
                );
        }
        self.wake_waiters();
    }

    async fn delete_global_account_data(&self, user_id: &UserId, data_type: &str) {
        {
            let mut s = self.write();
            let pos = next_stream(&mut s);
            s.global_account_data
                .entry(user_id.to_string())
                .or_default()
                .insert(
                    data_type.to_string(),
                    AccountDataInternal {
                        content: Map::new(),
                        stream_pos: pos,
                    },
                );
        }
        self.wake_waiters();
    }

    async fn get_all_global_account_data(&self, user_id: &UserId) -> Vec<AccountDataEntry> {
        self.read()
            .global_account_data
            .get(user_id.as_str())
            .map(|m| {
                m.iter()
                    .filter(|(_, v)| !v.content.is_empty())
                    .map(|(t, v)| AccountDataEntry {
                        data_type: t.clone(),
                        content: v.content.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn get_global_account_data_since(
        &self,
        user_id: &UserId,
        since: i64,
    ) -> Vec<AccountDataEntry> {
        self.read()
            .global_account_data
            .get(user_id.as_str())
            .map(|m| {
                m.iter()
                    .filter(|(_, v)| v.stream_pos > since)
                    .map(|(t, v)| AccountDataEntry {
                        data_type: t.clone(),
                        content: v.content.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn get_room_account_data(
        &self,
        user_id: &UserId,
        room_id: &RoomId,
        data_type: &str,
    ) -> Option<JsonObject> {
        self.read()
            .room_account_data
            .get(&room_key(user_id, room_id))
            .and_then(|m| m.get(data_type))
            .map(|e| e.content.clone())
    }

    async fn set_room_account_data(
        &self,
        user_id: &UserId,
        room_id: &RoomId,
        data_type: &str,
        content: JsonObject,
    ) {
        let key = room_key(user_id, room_id);
        {
            let mut s = self.write();
            let pos = next_stream(&mut s);
            s.room_account_data.entry(key).or_default().insert(
                data_type.to_string(),
                AccountDataInternal {
                    content,
                    stream_pos: pos,
                },
            );
        }
        self.wake_waiters();
    }

    async fn delete_room_account_data(&self, user_id: &UserId, room_id: &RoomId, data_type: &str) {
        let key = room_key(user_id, room_id);
        {
            let mut s = self.write();
            let pos = next_stream(&mut s);
            s.room_account_data.entry(key).or_default().insert(
                data_type.to_string(),
                AccountDataInternal {
                    content: Map::new(),
                    stream_pos: pos,
                },
            );
        }
        self.wake_waiters();
    }

    async fn get_all_room_account_data(
        &self,
        user_id: &UserId,
        room_id: &RoomId,
    ) -> Vec<AccountDataEntry> {
        self.read()
            .room_account_data
            .get(&room_key(user_id, room_id))
            .map(|m| {
                m.iter()
                    .filter(|(_, v)| !v.content.is_empty())
                    .map(|(t, v)| AccountDataEntry {
                        data_type: t.clone(),
                        content: v.content.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn get_room_account_data_since(
        &self,
        user_id: &UserId,
        since: i64,
    ) -> Vec<RoomAccountDataEntry> {
        let prefix = format!("{user_id}\u{1f}");
        let s = self.read();
        let mut out = Vec::new();
        for (key, data_map) in &s.room_account_data {
            let Some(room_id) = key.strip_prefix(&prefix) else {
                continue;
            };
            for (t, v) in data_map {
                if v.stream_pos > since {
                    out.push(RoomAccountDataEntry {
                        room_id: room_id.into(),
                        data_type: t.clone(),
                        content: v.content.clone(),
                    });
                }
            }
        }
        out
    }
}
