//! The `Storage` trait — port of strix `src/storage/interface.ts`.
//!
//! strix uses one ~260-method `Storage` interface. The Rust port splits it into
//! cohesive `#[async_trait]` sub-traits (one per domain, each implementable in
//! its own file per backend) composed into a single [`Storage`] supertrait,
//! handled as `Arc<dyn Storage>`. This keeps the surface navigable and makes
//! adding the Postgres backend (the real scale target) an isolated change.
//!
//! PDUs and EDUs are carried as [`serde_json::Value`] / [`Edu`], consistent with
//! the engine; polymorphic key-backup shapes and `string | OneTimeKey` unions
//! are `Value` to keep signatures tractable.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::types::e2ee::{CrossSigningKeys, DeviceKeys, KeyBackupData};
use crate::types::ephemeral::PresenceState;
use crate::types::events::{Edu, ToDeviceEvent};
use crate::types::federation::ServerKeys;
use crate::types::identifiers::{
    AccessToken, DeviceId, EventId, KeyId, RefreshToken, RoomAlias, RoomId, ServerName, Timestamp,
    UserId,
};
use crate::types::internal::{RoomState, StateEvents, StoredMedia, StoredSession, UserAccount};
use crate::types::json::JsonObject;
use crate::types::push::Pusher;
use crate::types::room_versions::RoomVersion;
use crate::types::user::{Device, UserProfile};

/// A Persistent Data Unit, carried as raw JSON.
pub type Pdu = Value;

/// Maximum pending outbound EDUs retained per destination (strix
/// `PENDING_FEDERATION_EDU_CAP`).
pub const PENDING_FEDERATION_EDU_CAP: usize = 1000;

// ---------------------------------------------------------------------------
// Small enums and record structs returned/accepted by the trait
// ---------------------------------------------------------------------------

/// Timeline pagination direction (`"b"` / `"f"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Backward,
    Forward,
}

/// Room directory visibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    Public,
    Private,
}

/// Which thread roots to return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadInclude {
    All,
    Participated,
}

/// An event with its ID.
#[derive(Clone, Debug)]
pub struct EventRecord {
    pub event: Pdu,
    pub event_id: EventId,
}

/// A stored event, with the rejected flag (kept for the DAG, hidden from
/// state/sync, served as 404 by `/event`).
#[derive(Clone, Debug)]
pub struct StoredEvent {
    pub event: Pdu,
    pub event_id: EventId,
    pub rejected: bool,
}

/// A page of room events.
#[derive(Clone, Debug, Default)]
pub struct EventsPage {
    pub events: Vec<EventRecord>,
    pub end: Option<i64>,
}

/// An event with its stream position.
#[derive(Clone, Debug)]
pub struct StreamEventRecord {
    pub event: Pdu,
    pub event_id: EventId,
    pub stream_pos: i64,
}

/// Incremental-sync events for one room.
#[derive(Clone, Debug, Default)]
pub struct EventsSince {
    pub events: Vec<StreamEventRecord>,
    pub limited: bool,
}

/// A room a user is in, with the user's membership there.
#[derive(Clone, Debug)]
pub struct RoomMembership {
    pub room_id: RoomId,
    pub membership: String,
}

/// One account-data entry.
#[derive(Clone, Debug)]
pub struct AccountDataEntry {
    pub data_type: String,
    pub content: JsonObject,
}

/// One room-scoped account-data entry.
#[derive(Clone, Debug)]
pub struct RoomAccountDataEntry {
    pub room_id: RoomId,
    pub data_type: String,
    pub content: JsonObject,
}

/// A read/fully-read receipt.
#[derive(Clone, Debug)]
pub struct ReceiptRecord {
    pub event_id: EventId,
    pub receipt_type: String,
    pub user_id: UserId,
    pub ts: Timestamp,
    pub thread_id: Option<String>,
}

/// A user's presence record.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PresenceRecord {
    pub presence: PresenceState,
    pub status_msg: Option<String>,
    pub last_active_ts: Option<Timestamp>,
}

/// Resolved alias → room.
#[derive(Clone, Debug)]
pub struct AliasRecord {
    pub room_id: RoomId,
    pub servers: Vec<ServerName>,
}

/// Media metadata + bytes.
#[derive(Clone, Debug)]
pub struct MediaWithData {
    pub metadata: StoredMedia,
    pub data: Vec<u8>,
}

/// A claimed one-time key (`key` is `string | OneTimeKey`).
#[derive(Clone, Debug)]
pub struct OneTimeKeyClaim {
    pub key_id: KeyId,
    pub key: Value,
}

/// Key-backup version metadata.
#[derive(Clone, Debug)]
pub struct KeyBackupVersionInfo {
    pub version: String,
    pub algorithm: String,
    pub auth_data: JsonObject,
    pub count: i64,
    pub etag: String,
}

/// Result of a key-backup put/delete.
#[derive(Clone, Debug)]
pub struct KeyBackupCount {
    pub count: i64,
    pub etag: String,
}

/// One signature-upload failure (`storeCrossSigningSignatures`).
#[derive(Clone, Debug)]
pub struct SignatureFailure {
    pub errcode: String,
    pub error: String,
}

/// An annotation (reaction) count.
#[derive(Clone, Debug)]
pub struct AnnotationCount {
    pub annotation_type: String,
    pub key: String,
    pub count: i64,
}

/// A thread summary.
#[derive(Clone, Debug)]
pub struct ThreadSummary {
    pub latest_event: EventRecord,
    pub count: i64,
    pub current_user_participated: bool,
}

/// Paginated related events.
#[derive(Clone, Debug, Default)]
pub struct RelatedEvents {
    pub events: Vec<EventRecord>,
    pub next_batch: Option<String>,
}

/// Paginated thread roots.
#[derive(Clone, Debug, Default)]
pub struct ThreadRoots {
    pub events: Vec<EventRecord>,
    pub next_batch: Option<String>,
}

/// Search results.
#[derive(Clone, Debug, Default)]
pub struct SearchResults {
    pub events: Vec<StreamEventRecord>,
    pub count: i64,
    pub next_batch: Option<String>,
}

/// A user-directory match.
#[derive(Clone, Debug)]
pub struct UserDirectoryEntry {
    pub user_id: UserId,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

/// A registered 3PID.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ThreePidRecord {
    pub medium: String,
    pub address: String,
    pub added_at: Timestamp,
}

/// A cached remote server key.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ServerKeyRecord {
    pub key: String,
    pub valid_until: i64,
}

/// Partial-state record for a room.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PartialStateRecord {
    pub servers: Vec<ServerName>,
    pub join_event_id: EventId,
}

/// A partial-state room (for startup resume).
#[derive(Clone, Debug)]
pub struct PartialStateRoom {
    pub room_id: RoomId,
    pub servers: Vec<ServerName>,
    pub join_event_id: EventId,
}

/// A queued device-list poke.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DevicePoke {
    pub user_id: UserId,
    pub device_id: DeviceId,
}

/// A pending outbound EDU with its row id.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PendingEdu {
    pub id: i64,
    pub edu: Edu,
}

/// A token → (user, expiry) record (OpenID / login tokens).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TokenUser {
    pub user_id: UserId,
    pub expires_at: Timestamp,
}

/// A 3PID verification session.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VerificationSession {
    pub medium: String,
    pub address: String,
    pub client_secret: String,
    pub send_attempt: i64,
    pub token: String,
    pub validated: bool,
    pub user_id: Option<String>,
}

/// A UIAA session's completed stages.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct UiaaSession {
    pub completed: Vec<String>,
}

// ---------------------------------------------------------------------------
// Domain sub-traits
// ---------------------------------------------------------------------------

/// Users, sessions/devices, UIAA, account, profile, 3PIDs.
#[async_trait]
pub trait AccountStore: Send + Sync {
    async fn create_user(&self, account: UserAccount);
    async fn get_user_by_localpart(&self, localpart: &str) -> Option<UserAccount>;
    async fn get_user_by_id(&self, user_id: &UserId) -> Option<UserAccount>;

    async fn create_session(&self, session: StoredSession);
    async fn get_session_by_access_token(&self, token: &AccessToken) -> Option<StoredSession>;
    async fn get_session_by_refresh_token(&self, token: &RefreshToken) -> Option<StoredSession>;
    async fn get_sessions_by_user(&self, user_id: &UserId) -> Vec<StoredSession>;
    async fn delete_session(&self, token: &AccessToken);
    async fn delete_all_sessions(&self, user_id: &UserId);
    async fn rotate_token(
        &self,
        old_access_token: &AccessToken,
        new_access_token: &AccessToken,
        new_refresh_token: Option<&RefreshToken>,
        expires_at: Option<Timestamp>,
    ) -> Option<StoredSession>;
    async fn touch_session(&self, token: &AccessToken, ip: &str, user_agent: &str);

    async fn create_uiaa_session(&self, session_id: &str);
    async fn get_uiaa_session(&self, session_id: &str) -> Option<UiaaSession>;
    async fn add_uiaa_completed(&self, session_id: &str, stage_type: &str);
    async fn delete_uiaa_session(&self, session_id: &str);

    async fn get_device(&self, user_id: &UserId, device_id: &DeviceId) -> Option<Device>;
    async fn get_all_devices(&self, user_id: &UserId) -> Vec<Device>;
    async fn update_device_display_name(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
        display_name: &str,
    );
    async fn delete_device_session(&self, user_id: &UserId, device_id: &DeviceId);

    async fn update_password(&self, user_id: &UserId, new_password_hash: &str);
    async fn deactivate_user(&self, user_id: &UserId);

    async fn get_profile(&self, user_id: &UserId) -> Option<UserProfile>;
    async fn set_display_name(&self, user_id: &UserId, displayname: Option<&str>);
    async fn set_avatar_url(&self, user_id: &UserId, avatar_url: Option<&str>);

    async fn get_three_pids(&self, user_id: &UserId) -> Vec<ThreePidRecord>;
    async fn add_three_pid(&self, user_id: &UserId, medium: &str, address: &str);
    async fn delete_three_pid(&self, user_id: &UserId, medium: &str, address: &str);
}

/// Rooms, events, state, members, txn idempotency, aliases, directory.
#[async_trait]
pub trait RoomStore: Send + Sync {
    async fn create_room(&self, state: RoomState);
    async fn get_room(&self, room_id: &RoomId) -> Option<RoomState>;
    async fn get_rooms_for_user(&self, user_id: &UserId) -> Vec<RoomId>;
    /// Advance a room's DAG head (depth + forward extremities) after appending an
    /// event. strix mutates the shared `RoomState` in place; the Rust port
    /// persists it explicitly because `get_room` returns a clone.
    async fn update_room_dag(
        &self,
        room_id: &RoomId,
        depth: i64,
        forward_extremities: Vec<EventId>,
    );

    async fn store_event(&self, event: Pdu, event_id: &EventId);

    /// Commit a freshly-built timeline event in a **single** write-lock: store
    /// the event, advance the room's DAG head (`depth`/`forward_extremities`),
    /// and record transaction idempotency. Folding these three mutations into one
    /// lock acquisition (instead of `store_event` + `update_room_dag` +
    /// `set_txn_event_id`) cuts lock churn/contention on the hot send path.
    /// `txn_key` is the full idempotency key `"{user}|{device}|{scoped_txn}"`.
    #[allow(clippy::too_many_arguments)]
    async fn commit_timeline_event(
        &self,
        event: Pdu,
        event_id: &EventId,
        room_id: &RoomId,
        new_depth: i64,
        forward_extremities: Vec<EventId>,
        txn_key: &str,
    );

    async fn update_event(&self, event_id: &EventId, event: Pdu);
    async fn get_event(&self, event_id: &EventId) -> Option<StoredEvent>;
    async fn get_events_by_room(
        &self,
        room_id: &RoomId,
        limit: usize,
        from: Option<i64>,
        direction: Direction,
    ) -> EventsPage;
    async fn get_stream_position(&self) -> i64;

    async fn get_state_event(
        &self,
        room_id: &RoomId,
        event_type: &str,
        state_key: &str,
    ) -> Option<EventRecord>;
    async fn get_all_state(&self, room_id: &RoomId) -> Vec<EventRecord>;
    async fn set_state_event(&self, room_id: &RoomId, event: Pdu, event_id: &EventId);

    async fn get_member_events(&self, room_id: &RoomId) -> Vec<EventRecord>;

    async fn get_txn_event_id(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
        txn_id: &str,
    ) -> Option<EventId>;
    async fn set_txn_event_id(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
        txn_id: &str,
        event_id: &EventId,
    );

    async fn create_room_alias(
        &self,
        room_alias: &RoomAlias,
        room_id: &RoomId,
        servers: Vec<ServerName>,
        creator: &UserId,
    );
    async fn delete_room_alias(&self, room_alias: &RoomAlias) -> bool;
    async fn get_room_by_alias(&self, room_alias: &RoomAlias) -> Option<AliasRecord>;
    async fn get_aliases_for_room(&self, room_id: &RoomId) -> Vec<RoomAlias>;
    async fn get_alias_creator(&self, room_alias: &RoomAlias) -> Option<UserId>;

    async fn set_room_visibility(&self, room_id: &RoomId, visibility: Visibility);
    async fn get_room_visibility(&self, room_id: &RoomId) -> Visibility;
    async fn get_public_room_ids(&self) -> Vec<RoomId>;
}

/// Sync queries.
#[async_trait]
pub trait SyncStore: Send + Sync {
    async fn get_rooms_for_user_with_membership(&self, user_id: &UserId) -> Vec<RoomMembership>;
    async fn get_events_by_room_since(
        &self,
        room_id: &RoomId,
        since: i64,
        limit: usize,
    ) -> EventsSince;
    /// Invite/knock stripped state. Raw `Value` so the MSC4311 full-`m.room.create`
    /// special case keeps its extra fields (see `event_to_stripped_state`).
    async fn get_stripped_state(&self, room_id: &RoomId) -> Vec<Value>;
    async fn wait_for_events(&self, since: i64, timeout_ms: u64);
}

/// Global and room account data.
#[async_trait]
pub trait AccountDataStore: Send + Sync {
    async fn get_global_account_data(
        &self,
        user_id: &UserId,
        data_type: &str,
    ) -> Option<JsonObject>;
    async fn set_global_account_data(&self, user_id: &UserId, data_type: &str, content: JsonObject);
    async fn delete_global_account_data(&self, user_id: &UserId, data_type: &str);
    async fn get_all_global_account_data(&self, user_id: &UserId) -> Vec<AccountDataEntry>;
    async fn get_global_account_data_since(
        &self,
        user_id: &UserId,
        since: i64,
    ) -> Vec<AccountDataEntry>;

    async fn get_room_account_data(
        &self,
        user_id: &UserId,
        room_id: &RoomId,
        data_type: &str,
    ) -> Option<JsonObject>;
    async fn set_room_account_data(
        &self,
        user_id: &UserId,
        room_id: &RoomId,
        data_type: &str,
        content: JsonObject,
    );
    async fn delete_room_account_data(&self, user_id: &UserId, room_id: &RoomId, data_type: &str);
    async fn get_all_room_account_data(
        &self,
        user_id: &UserId,
        room_id: &RoomId,
    ) -> Vec<AccountDataEntry>;
    async fn get_room_account_data_since(
        &self,
        user_id: &UserId,
        since: i64,
    ) -> Vec<RoomAccountDataEntry>;
}

/// Typing, receipts, presence (process-local ephemerals).
#[async_trait]
pub trait EphemeralStore: Send + Sync {
    async fn set_typing(
        &self,
        room_id: &RoomId,
        user_id: &UserId,
        typing: bool,
        timeout: Option<i64>,
    );
    async fn get_typing_users(&self, room_id: &RoomId) -> Vec<UserId>;
    async fn get_typing_changed_at(&self, room_id: &RoomId) -> i64;

    async fn set_receipt(
        &self,
        room_id: &RoomId,
        user_id: &UserId,
        event_id: &EventId,
        receipt_type: &str,
        ts: Timestamp,
        thread_id: Option<&str>,
    );
    async fn get_receipts(&self, room_id: &RoomId) -> Vec<ReceiptRecord>;

    async fn set_presence(
        &self,
        user_id: &UserId,
        presence: PresenceState,
        status_msg: Option<&str>,
    );
    async fn get_presence(&self, user_id: &UserId) -> Option<PresenceRecord>;
    async fn get_presence_changed_at(&self, user_id: &UserId) -> i64;
}

/// Media and filters.
#[async_trait]
pub trait MediaStore: Send + Sync {
    async fn store_media(&self, media: StoredMedia, data: Vec<u8>);
    async fn get_media(&self, server_name: &ServerName, media_id: &str) -> Option<MediaWithData>;
    async fn reserve_media(&self, media: StoredMedia);
    async fn update_media_content(
        &self,
        server_name: &ServerName,
        media_id: &str,
        content_type: &str,
        file_name: Option<&str>,
        data: Vec<u8>,
    ) -> bool;

    async fn create_filter(&self, user_id: &UserId, filter: JsonObject) -> String;
    async fn get_filter(&self, user_id: &UserId, filter_id: &str) -> Option<JsonObject>;
}

/// E2EE: device keys, one-time/fallback keys, cross-signing, key backup,
/// to-device, the device-key-change stream.
#[async_trait]
pub trait E2eeStore: Send + Sync {
    async fn set_device_keys(&self, user_id: &UserId, device_id: &DeviceId, keys: DeviceKeys);
    async fn get_device_keys(&self, user_id: &UserId, device_id: &DeviceId) -> Option<DeviceKeys>;
    async fn get_all_device_keys(&self, user_id: &UserId) -> BTreeMap<DeviceId, DeviceKeys>;
    async fn delete_device_keys(&self, user_id: &UserId);

    async fn record_device_key_change(&self, user_id: &UserId);
    async fn get_changed_device_users(&self, since: i64, until: i64) -> Vec<UserId>;

    async fn add_one_time_keys(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
        keys: BTreeMap<KeyId, Value>,
    );
    async fn claim_one_time_key(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
        algorithm: &str,
    ) -> Option<OneTimeKeyClaim>;
    async fn get_one_time_key_counts(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> BTreeMap<String, i64>;

    async fn set_fallback_keys(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
        keys: BTreeMap<KeyId, Value>,
    );
    async fn get_fallback_key_types(&self, user_id: &UserId, device_id: &DeviceId) -> Vec<String>;

    async fn set_cross_signing_keys(&self, user_id: &UserId, keys: CrossSigningKeys);
    async fn get_cross_signing_keys(&self, user_id: &UserId) -> CrossSigningKeys;
    async fn store_cross_signing_signatures(
        &self,
        user_id: &UserId,
        signatures: BTreeMap<String, BTreeMap<String, JsonObject>>,
    ) -> BTreeMap<String, BTreeMap<String, SignatureFailure>>;

    async fn create_key_backup_version(
        &self,
        user_id: &UserId,
        algorithm: &str,
        auth_data: JsonObject,
    ) -> String;
    async fn get_key_backup_version(
        &self,
        user_id: &UserId,
        version: Option<&str>,
    ) -> Option<KeyBackupVersionInfo>;
    async fn update_key_backup_version(
        &self,
        user_id: &UserId,
        version: &str,
        auth_data: JsonObject,
    ) -> bool;
    async fn delete_key_backup_version(&self, user_id: &UserId, version: &str) -> bool;
    async fn put_key_backup_keys(
        &self,
        user_id: &UserId,
        version: &str,
        room_id: Option<&RoomId>,
        session_id: Option<&str>,
        keys: Value,
    ) -> Option<KeyBackupCount>;
    async fn get_key_backup_keys(
        &self,
        user_id: &UserId,
        version: &str,
        room_id: Option<&RoomId>,
        session_id: Option<&str>,
    ) -> Option<Value>;
    async fn delete_key_backup_keys(
        &self,
        user_id: &UserId,
        version: &str,
        room_id: Option<&RoomId>,
        session_id: Option<&str>,
    ) -> Option<KeyBackupCount>;

    async fn send_to_device(&self, user_id: &UserId, device_id: &DeviceId, event: ToDeviceEvent);
    async fn get_to_device_messages(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> Vec<ToDeviceEvent>;
    async fn clear_to_device_messages(&self, user_id: &UserId, device_id: &DeviceId);

    /// Key-backup merge rule shared by SQL backends (verified > lower
    /// first_message_index > lower forwarded_count).
    fn should_replace_backup_key(
        &self,
        existing: &KeyBackupData,
        incoming: &KeyBackupData,
    ) -> bool {
        if incoming.is_verified != existing.is_verified {
            return incoming.is_verified;
        }
        if incoming.first_message_index != existing.first_message_index {
            return incoming.first_message_index < existing.first_message_index;
        }
        incoming.forwarded_count < existing.forwarded_count
    }
}

/// Pushers, relations, reports, OpenID, user directory, threads, search.
#[async_trait]
pub trait MessagingStore: Send + Sync {
    async fn get_pushers(&self, user_id: &UserId) -> Vec<Pusher>;
    async fn set_pusher(&self, user_id: &UserId, pusher: Pusher);
    async fn delete_pusher(&self, user_id: &UserId, app_id: &str, pushkey: &str);
    async fn delete_pusher_by_key(&self, app_id: &str, pushkey: &str);

    async fn store_relation(
        &self,
        event_id: &EventId,
        room_id: &RoomId,
        rel_type: &str,
        target_event_id: &EventId,
        key: Option<&str>,
    );
    #[allow(clippy::too_many_arguments)]
    async fn get_related_events(
        &self,
        room_id: &RoomId,
        event_id: &EventId,
        rel_type: Option<&str>,
        event_type: Option<&str>,
        limit: Option<usize>,
        from: Option<&str>,
        direction: Direction,
    ) -> RelatedEvents;
    async fn get_annotation_counts(&self, event_id: &EventId) -> Vec<AnnotationCount>;
    async fn get_latest_edit(&self, event_id: &EventId, sender: &UserId) -> Option<EventRecord>;
    async fn get_thread_summary(
        &self,
        event_id: &EventId,
        user_id: &UserId,
    ) -> Option<ThreadSummary>;

    async fn store_report(
        &self,
        user_id: &UserId,
        room_id: &RoomId,
        event_id: &EventId,
        score: Option<i64>,
        reason: Option<&str>,
    );

    async fn store_open_id_token(&self, token: &str, user_id: &UserId, expires_at: Timestamp);
    async fn get_open_id_token(&self, token: &str) -> Option<TokenUser>;

    async fn search_user_directory(
        &self,
        search_term: &str,
        limit: usize,
    ) -> Vec<UserDirectoryEntry>;

    async fn get_thread_roots(
        &self,
        room_id: &RoomId,
        user_id: &UserId,
        include: ThreadInclude,
        limit: usize,
        from: Option<&str>,
    ) -> ThreadRoots;

    async fn search_room_events(
        &self,
        room_ids: &[RoomId],
        search_term: &str,
        keys: &[String],
        limit: usize,
        from: Option<&str>,
    ) -> SearchResults;
}

/// Federation: remote keys, auth chain/state, partial state, txn dedup, the
/// durable EDU queue, room import, 3PID verification, and login tokens.
#[async_trait]
pub trait FederationStore: Send + Sync {
    async fn store_server_keys(&self, server_name: &ServerName, keys: ServerKeys);
    async fn get_server_keys(
        &self,
        server_name: &ServerName,
        key_id: &KeyId,
    ) -> Option<ServerKeyRecord>;

    async fn get_auth_chain(&self, event_ids: &[EventId]) -> Vec<Pdu>;
    async fn get_servers_in_room(&self, room_id: &RoomId) -> Vec<ServerName>;
    async fn get_state_at_event(&self, room_id: &RoomId, event_id: &EventId)
        -> Option<StateEvents>;

    async fn mark_room_partial_state(
        &self,
        room_id: &RoomId,
        servers: Vec<ServerName>,
        join_event_id: &EventId,
    );
    async fn clear_room_partial_state(&self, room_id: &RoomId);
    async fn get_room_partial_state(&self, room_id: &RoomId) -> Option<PartialStateRecord>;
    async fn get_all_partial_state_rooms(&self) -> Vec<PartialStateRoom>;
    async fn wait_for_partial_state_clear(&self, room_id: &RoomId, timeout_ms: u64);
    async fn record_partial_state_event(&self, room_id: &RoomId, event_id: &EventId);
    async fn take_partial_state_events(&self, room_id: &RoomId) -> Vec<EventId>;
    async fn record_partial_state_device_poke(
        &self,
        room_id: &RoomId,
        user_id: &UserId,
        device_id: &DeviceId,
    );
    async fn take_partial_state_device_pokes(&self, room_id: &RoomId) -> Vec<DevicePoke>;
    async fn delete_event(&self, event_id: &EventId);
    async fn unreject_event(&self, event_id: &EventId);
    async fn get_room_un_partial_stated_at(&self, room_id: &RoomId) -> Option<i64>;
    async fn set_state_event_historical(&self, room_id: &RoomId, event: Pdu, event_id: &EventId);

    async fn get_federation_txn(&self, origin: &ServerName, txn_id: &str) -> bool;
    async fn set_federation_txn(&self, origin: &ServerName, txn_id: &str);

    async fn enqueue_federation_edu(&self, destination: &ServerName, edu: Edu) -> i64;
    async fn get_pending_federation_edus(
        &self,
        destination: &ServerName,
        limit: usize,
    ) -> Vec<PendingEdu>;
    async fn delete_federation_edu(&self, id: i64);
    async fn get_pending_federation_destinations(&self) -> Vec<ServerName>;

    async fn store_verification_token(&self, session_id: &str, data: VerificationSession);
    async fn get_verification_session(&self, session_id: &str) -> Option<VerificationSession>;
    async fn validate_verification_token(&self, session_id: &str, token: &str) -> bool;

    async fn store_login_token(&self, token: &str, user_id: &UserId, expires_at: Timestamp);
    async fn get_login_token(&self, token: &str) -> Option<TokenUser>;
    async fn delete_login_token(&self, token: &str);

    async fn import_room_state(
        &self,
        room_id: &RoomId,
        room_version: RoomVersion,
        state_events: Vec<Pdu>,
        auth_chain: Vec<Pdu>,
    );
}

/// The full storage interface: every backend implements all sub-traits.
pub trait Storage:
    AccountStore
    + RoomStore
    + SyncStore
    + AccountDataStore
    + EphemeralStore
    + MediaStore
    + E2eeStore
    + MessagingStore
    + FederationStore
    + Send
    + Sync
{
}

impl<T> Storage for T where
    T: AccountStore
        + RoomStore
        + SyncStore
        + AccountDataStore
        + EphemeralStore
        + MediaStore
        + E2eeStore
        + MessagingStore
        + FederationStore
        + Send
        + Sync
{
}

/// Apply the MSC4102 read-receipt preference rule: collapse to one record per
/// `(user, receipt_type, event_id)`, preferring the unthreaded receipt.
pub fn collapse_receipts_msc4102(rows: Vec<ReceiptRecord>) -> Vec<ReceiptRecord> {
    let mut by_key: BTreeMap<String, ReceiptRecord> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    for row in rows {
        let key = format!(
            "{}\u{1f}{}\u{1f}{}",
            row.user_id, row.receipt_type, row.event_id
        );
        match by_key.get(&key) {
            Some(existing) if !(existing.thread_id.is_some() && row.thread_id.is_none()) => {
                // Keep the existing (already unthreaded, or both threaded).
            }
            _ => {
                if !by_key.contains_key(&key) {
                    order.push(key.clone());
                }
                by_key.insert(key, row);
            }
        }
    }
    order
        .into_iter()
        .filter_map(|k| by_key.remove(&k))
        .collect()
}
