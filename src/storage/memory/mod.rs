//! In-memory storage backend — port of strix `src/storage/memory.ts`.
//!
//! All state lives in one `RwLock<MemState>`; methods lock, mutate synchronously,
//! and drop the guard before any `.await`. The long-poll `wait_for_events` uses a
//! [`tokio::sync::Notify`] woken by [`MemoryStorage::wake_waiters`] whenever the
//! monotonic stream counter advances. Nothing is persisted — it is the test
//! substrate and the behavioural reference for the SQL backends.
//!
//! Note vs strix: strix keeps the same `UserAccount` object in two maps (shared
//! by reference). The Rust port keeps `users_by_id` as the source of truth plus a
//! `localpart_index`, so in-place updates (password, profile, deactivate) cannot
//! desync.

mod account;
mod accountdata;
mod e2ee;
mod ephemeral;
mod federation;
mod media;
mod messaging;
mod room;
mod sync;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Condvar, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use tokio::sync::Notify;

use crate::storage::interface::{
    DevicePoke, PartialStateRecord, PendingEdu, PresenceRecord, ServerKeyRecord, ThreePidRecord,
    TokenUser, UiaaSession, VerificationSession,
};
use crate::types::e2ee::{CrossSigningKeys, DeviceKeys, KeyBackupData};
use crate::types::events::ToDeviceEvent;
use crate::types::internal::{RoomState, StoredMedia, StoredSession, UserAccount};
use crate::types::json::JsonObject;
use crate::types::push::Pusher;

/// Unix time in milliseconds (strix `Date.now()`).
pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// --- internal entry records ------------------------------------------------

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct TimelineEntry {
    pub event_id: String,
    pub stream_pos: i64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct AliasEntry {
    pub room_id: String,
    pub servers: Vec<String>,
    pub creator: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct AccountDataInternal {
    pub content: JsonObject,
    pub stream_pos: i64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct ReceiptInternal {
    pub event_id: String,
    pub ts: i64,
    pub thread_id: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct MediaEntry {
    pub metadata: StoredMedia,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct DeviceListEntry {
    pub user_id: String,
    pub stream_pos: i64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct KeyBackupVersionEntry {
    pub version: String,
    pub algorithm: String,
    pub auth_data: JsonObject,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct RelationInternal {
    pub event_id: String,
    pub rel_type: String,
    pub key: Option<String>,
    pub sender: String,
    pub event_type: String,
    pub stream_pos: i64,
}

// Reports are write-only in the Storage interface (strix has `store_report` but
// no reader), so these fields are intentionally never read back.
#[allow(dead_code)]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct ReportInternal {
    pub user_id: String,
    pub room_id: String,
    pub event_id: String,
    pub score: Option<i64>,
    pub reason: Option<String>,
    pub ts: i64,
}

/// The complete in-memory state. Field visibility is module-private; descendant
/// modules (the per-domain impls) access these directly.
#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct MemState {
    // Monotonic counters.
    pub stream_counter: i64,
    pub filter_counter: i64,

    // Account.
    pub users_by_id: HashMap<String, UserAccount>,
    pub localpart_index: HashMap<String, String>,
    pub sessions_by_token: HashMap<String, StoredSession>,
    pub refresh_index: HashMap<String, String>,
    pub uiaa_sessions: HashMap<String, UiaaSession>,
    pub three_pids: HashMap<String, Vec<ThreePidRecord>>,

    // Rooms / events.
    pub rooms_by_id: HashMap<String, RoomState>,
    // Events are the ever-growing data. They are **excluded from the snapshot**
    // (`serde(skip)`) and persisted *incrementally* by the SQLite backend — each
    // new event is one appended row, drained off the request path by the writer
    // thread. This keeps the periodic snapshot small and constant-sized, so the
    // writer never re-serializes/re-writes tens of MB every flush (the cause of
    // the tail latency spikes). Bodies are `Arc`-wrapped and the maps are
    // persistent (`im`) so the in-memory clone the writer takes is also O(1).
    #[serde(skip)]
    pub events_by_id: im::HashMap<String, Arc<Value>>,
    #[serde(skip)]
    pub room_timeline: HashMap<String, im::Vector<TimelineEntry>>,
    /// Incremental persistence ops accumulated since the last flush (drained by
    /// the SQLite writer thread). Only populated when [`Self::persist_enabled`].
    #[serde(skip)]
    pub pending_persist: Vec<PersistOp>,
    /// Whether to record `pending_persist` ops (true only for the SQLite backend;
    /// the pure in-memory backend never persists, so it skips the bookkeeping).
    #[serde(skip)]
    pub persist_enabled: bool,
    // Transaction idempotency (one entry per event sent → grows unboundedly).
    // `im` for O(1) clone, and excluded from the snapshot: re-serializing 100k+
    // entries every flush is needless churn, and idempotency is best-effort
    // (it holds within a run; a rare cross-restart retry may duplicate an event).
    #[serde(skip)]
    pub txn_map: im::HashMap<String, String>,
    pub aliases: HashMap<String, AliasEntry>,
    pub public_rooms: HashSet<String>,

    // Account data.
    pub global_account_data: HashMap<String, HashMap<String, AccountDataInternal>>,
    pub room_account_data: HashMap<String, HashMap<String, AccountDataInternal>>,

    // Ephemeral.
    pub receipts: HashMap<String, HashMap<String, ReceiptInternal>>,
    pub typing: HashMap<String, HashMap<String, i64>>,
    pub typing_changed_at: HashMap<String, i64>,
    pub presence: HashMap<String, PresenceRecord>,
    pub presence_changed_at: HashMap<String, i64>,

    // Media / filters.
    pub media: HashMap<String, MediaEntry>,
    pub filters: HashMap<String, HashMap<String, JsonObject>>,

    // E2EE.
    pub device_keys: HashMap<String, DeviceKeys>,
    pub device_list_stream: Vec<DeviceListEntry>,
    // Insertion-ordered so claims are FIFO by upload time (TestKeyClaimOrdering).
    pub one_time_keys: HashMap<String, Vec<(String, Value)>>,
    pub fallback_keys: HashMap<String, BTreeMap<String, Value>>,
    pub cross_signing_keys: HashMap<String, CrossSigningKeys>,
    pub key_backup_versions: HashMap<String, Vec<KeyBackupVersionEntry>>,
    // Inner maps are BTreeMaps so the etag hash iterates in a deterministic
    // (sorted) order — strix relies on insertion-order Map iteration, which does
    // not translate; sorted order keeps the etag stable for given content.
    pub key_backup_data: HashMap<String, BTreeMap<String, BTreeMap<String, KeyBackupData>>>,
    pub key_backup_counter: i64,
    pub to_device_inbox: HashMap<String, Vec<ToDeviceEvent>>,

    // Messaging.
    pub pushers: HashMap<String, Vec<Pusher>>,
    pub relations: HashMap<String, Vec<RelationInternal>>,
    pub reports: Vec<ReportInternal>,
    pub open_id_tokens: HashMap<String, TokenUser>,

    // Federation.
    pub server_keys_cache: HashMap<String, ServerKeyRecord>,
    pub federation_txns: HashSet<String>,
    pub pending_federation_edus: HashMap<String, Vec<PendingEdu>>,
    pub pending_federation_edu_counter: i64,
    pub verification_sessions: HashMap<String, VerificationSession>,
    pub login_tokens: HashMap<String, TokenUser>,

    // Partial state.
    pub partial_state: HashMap<String, PartialStateRecord>,
    pub partial_state_events: HashMap<String, Vec<String>>,
    pub partial_state_pokes: HashMap<String, Vec<DevicePoke>>,
    pub un_partial_stated_at: HashMap<String, i64>,
}

/// An incremental persistence operation for the SQLite events table, recorded on
/// every event mutation and drained by the writer thread.
#[derive(Clone)]
pub enum PersistOp {
    /// Insert (or, on event-ID conflict, update the body of) a stored event.
    /// `room_id`/`stream_pos` are used only on first insert; a redaction that
    /// re-stores an existing event carries `None` and only its body changes.
    Upsert {
        event_id: String,
        room_id: Option<String>,
        stream_pos: Option<i64>,
        data: Arc<Value>,
    },
    /// Delete a stored event.
    Delete { event_id: String },
}

/// Advance and return the monotonic stream counter (strix `++streamCounter`).
pub(crate) fn next_stream(state: &mut MemState) -> i64 {
    state.stream_counter += 1;
    state.stream_counter
}

/// Record that a user's device list changed (strix `recordDeviceKeyChange`):
/// advance the stream and append to the device-list change stream.
pub(crate) fn record_device_key_change(state: &mut MemState, user_id: &str) {
    let pos = next_stream(state);
    state.device_list_stream.push(DeviceListEntry {
        user_id: user_id.to_string(),
        stream_pos: pos,
    });
}

/// Persist an event and, if its room has a timeline, advance the stream and
/// append a timeline entry (strix `storeEvent`, minus the waiter wake — callers
/// call [`MemoryStorage::wake_waiters`] after releasing the lock).
pub(crate) fn store_event_locked(state: &mut MemState, event: Value, event_id: &str) {
    let room_id = event
        .get("room_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    let data = Arc::new(event);
    state.events_by_id.insert(event_id.to_string(), Arc::clone(&data));
    let mut stream_pos = None;
    if let Some(rid) = &room_id {
        if state.room_timeline.contains_key(rid) {
            let pos = next_stream(state);
            state
                .room_timeline
                .get_mut(rid)
                .unwrap()
                .push_back(TimelineEntry {
                    event_id: event_id.to_string(),
                    stream_pos: pos,
                });
            stream_pos = Some(pos);
        }
    }
    if state.persist_enabled {
        state.pending_persist.push(PersistOp::Upsert {
            event_id: event_id.to_string(),
            room_id,
            stream_pos,
            data,
        });
    }
}

/// Record an incremental event-body update (redaction) for persistence. Keeps
/// the existing row's `room_id`/`stream_pos` (only the body changes).
pub(crate) fn record_event_update(state: &mut MemState, event_id: &str, data: Arc<Value>) {
    if state.persist_enabled {
        state.pending_persist.push(PersistOp::Upsert {
            event_id: event_id.to_string(),
            room_id: None,
            stream_pos: None,
            data,
        });
    }
}

/// Record an incremental event deletion for persistence.
pub(crate) fn record_event_delete(state: &mut MemState, event_id: &str) {
    if state.persist_enabled {
        state.pending_persist.push(PersistOp::Delete { event_id: event_id.to_string() });
    }
}

/// A persistence backend. The SQLite backend implements this to receive a
/// cheap `mark_dirty` on every mutation (off the request hot path) and a
/// synchronous `flush` used by a background writer and on shutdown.
pub(crate) trait Persist: Send + Sync {
    /// Signal that state changed; must be cheap and non-blocking (no I/O).
    fn mark_dirty(&self);
    /// Serialize + persist `state` synchronously. Called by the background
    /// writer thread and once more when the storage drops.
    fn flush(&self, state: &MemState);
    /// Signal the background writer thread to exit (called on storage drop, so
    /// the writer's SQLite connection is released promptly).
    fn shutdown(&self);
}

/// A dirty flag + shutdown flag + condvar the SQLite backend's writer thread
/// waits on. Lets a mutation wake the writer without any I/O on the request path.
#[derive(Default)]
pub(crate) struct PersistSignal {
    inner: Mutex<SignalState>,
    cv: Condvar,
}

#[derive(Default)]
struct SignalState {
    dirty: bool,
    shutdown: bool,
}

impl PersistSignal {
    /// Mark dirty and wake the writer (cheap, non-blocking).
    pub(crate) fn wake(&self) {
        self.inner.lock().expect("persist signal poisoned").dirty = true;
        self.cv.notify_one();
    }

    /// Ask the writer thread to exit and wake it.
    pub(crate) fn shutdown(&self) {
        self.inner.lock().expect("persist signal poisoned").shutdown = true;
        self.cv.notify_one();
    }

    /// Block until dirty or shutdown, clearing the dirty flag. Returns `false`
    /// when the writer should exit (shutdown requested).
    pub(crate) fn wait_and_clear(&self) -> bool {
        let mut s = self.inner.lock().expect("persist signal poisoned");
        while !s.dirty && !s.shutdown {
            s = self.cv.wait(s).expect("persist signal poisoned");
        }
        s.dirty = false;
        !s.shutdown
    }
}

/// The in-memory storage backend. State lives behind an `Arc<RwLock<_>>` so a
/// persistence backend's background writer thread can share read access. An
/// optional [`Persist`] lets the SQLite backend snapshot state off the hot path.
pub struct MemoryStorage {
    state: Arc<RwLock<MemState>>,
    notify: Notify,
    persist: Option<Arc<dyn Persist>>,
    /// Background writer thread handle (SQLite backend only), joined on drop.
    writer: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        MemoryStorage {
            state: Arc::new(RwLock::new(MemState::default())),
            notify: Notify::new(),
            persist: None,
            writer: std::sync::Mutex::new(None),
        }
    }

    /// Build a backend around shared (loaded-from-disk) state plus a persistence
    /// backend and its background writer thread. Mutations `mark_dirty` (cheap);
    /// the writer does the actual serialization + disk write off the request path.
    pub(crate) fn with_persistence(
        state: Arc<RwLock<MemState>>,
        persist: Arc<dyn Persist>,
        writer: std::thread::JoinHandle<()>,
    ) -> Self {
        MemoryStorage {
            state,
            notify: Notify::new(),
            persist: Some(persist),
            writer: std::sync::Mutex::new(Some(writer)),
        }
    }

    pub(crate) fn read(&self) -> RwLockReadGuard<'_, MemState> {
        self.state.read().expect("memory storage lock poisoned")
    }

    /// Acquire the write lock. On drop the guard cheaply marks the persistence
    /// backend dirty (if any) — the actual write happens on a background thread,
    /// so mutations never block on serialization or disk I/O.
    pub(crate) fn write(&self) -> MutGuard<'_> {
        MutGuard {
            guard: Some(self.state.write().expect("memory storage lock poisoned")),
            storage: self,
        }
    }

    /// Wake every in-flight long-poll waiter (strix `wakeWaiters`). Persistence
    /// is handled by [`MutGuard`] on write-lock drop, not here.
    pub(crate) fn wake_waiters(&self) {
        self.notify.notify_waiters();
    }

    /// Borrow the long-poll notifier (used by `SyncStore::wait_for_events`).
    pub(crate) fn notifier(&self) -> &Notify {
        &self.notify
    }
}

/// A write guard over [`MemState`] that persists through to the storage's
/// [`PersistFn`] (if configured) when it drops. Behaves like the underlying
/// `RwLockWriteGuard` via `Deref`/`DerefMut`.
pub(crate) struct MutGuard<'a> {
    guard: Option<RwLockWriteGuard<'a, MemState>>,
    storage: &'a MemoryStorage,
}

impl std::ops::Deref for MutGuard<'_> {
    type Target = MemState;
    fn deref(&self) -> &MemState {
        self.guard.as_ref().expect("guard present until drop")
    }
}

impl std::ops::DerefMut for MutGuard<'_> {
    fn deref_mut(&mut self) -> &mut MemState {
        self.guard.as_mut().expect("guard present until drop")
    }
}

impl Drop for MutGuard<'_> {
    fn drop(&mut self) {
        // Release the write lock first, then just mark the persistence backend
        // dirty. This is cheap and non-blocking: the background writer thread
        // does the (O(n)) serialization + disk write, so a mutation never blocks
        // the async request path on I/O.
        self.guard.take();
        if let Some(persist) = &self.storage.persist {
            persist.mark_dirty();
        }
    }
}

impl Drop for MemoryStorage {
    fn drop(&mut self) {
        // Final synchronous flush so the last mutations are durable across a
        // clean shutdown/restart even if the background writer hasn't caught up
        // (keeps the sqlite reopen-persistence contract intact), then stop the
        // writer thread and join it so its SQLite connection is released before
        // this returns (otherwise a reopen of the same file would conflict).
        if let Some(persist) = &self.persist {
            {
                let guard = self.state.read().expect("memory storage lock poisoned");
                persist.flush(&guard);
            }
            persist.shutdown();
        }
        if let Some(handle) = self.writer.lock().expect("writer lock poisoned").take() {
            let _ = handle.join();
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Construct an in-memory storage backend (strix `createMemoryStorage`).
pub fn create_memory_storage() -> MemoryStorage {
    MemoryStorage::new()
}
