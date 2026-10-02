//! `MediaStore` (media + filters) for the in-memory backend.

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha2::{Digest, Sha256};

use super::{MediaEntry, MemoryStorage};
use crate::storage::interface::{MediaStore, MediaWithData};
use crate::types::identifiers::{ServerName, UserId};
use crate::types::internal::StoredMedia;
use crate::types::json::JsonObject;

fn media_key(origin: &str, media_id: &str) -> String {
    format!("{origin}/{media_id}")
}

#[async_trait]
impl MediaStore for MemoryStorage {
    async fn store_media(&self, media: StoredMedia, data: Vec<u8>) {
        let key = media_key(media.origin.as_str(), &media.media_id);
        self.write().media.insert(
            key,
            MediaEntry {
                metadata: media,
                data,
            },
        );
    }

    async fn get_media(&self, server_name: &ServerName, media_id: &str) -> Option<MediaWithData> {
        self.read()
            .media
            .get(&media_key(server_name.as_str(), media_id))
            .map(|e| MediaWithData {
                metadata: e.metadata.clone(),
                data: e.data.clone(),
            })
    }

    async fn reserve_media(&self, media: StoredMedia) {
        let key = media_key(media.origin.as_str(), &media.media_id);
        self.write().media.insert(
            key,
            MediaEntry {
                metadata: media,
                data: Vec::new(),
            },
        );
    }

    async fn update_media_content(
        &self,
        server_name: &ServerName,
        media_id: &str,
        content_type: &str,
        file_name: Option<&str>,
        data: Vec<u8>,
    ) -> bool {
        let hash = STANDARD.encode(Sha256::digest(&data));
        let mut s = self.write();
        let Some(entry) = s.media.get_mut(&media_key(server_name.as_str(), media_id)) else {
            return false;
        };
        entry.metadata.content_type = content_type.to_string();
        entry.metadata.upload_name = file_name.map(str::to_string);
        entry.metadata.file_size = data.len() as i64;
        entry.metadata.content_hash = hash;
        entry.data = data;
        true
    }

    async fn create_filter(&self, user_id: &UserId, filter: JsonObject) -> String {
        let mut s = self.write();
        s.filter_counter += 1;
        let filter_id = s.filter_counter.to_string();
        s.filters
            .entry(user_id.to_string())
            .or_default()
            .insert(filter_id.clone(), filter);
        filter_id
    }

    async fn get_filter(&self, user_id: &UserId, filter_id: &str) -> Option<JsonObject> {
        self.read()
            .filters
            .get(user_id.as_str())
            .and_then(|m| m.get(filter_id))
            .cloned()
    }
}
