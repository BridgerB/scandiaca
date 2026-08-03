//! SQLite storage backend.
//!
//! strix's `sqlite.ts` is a fully per-row relational store. This Rust port is a
//! **hybrid**: it reuses the proven in-memory backend as the working set, and
//! persists in two parts, both off the request hot path on a background writer
//! thread:
//!
//! - **Events** (the ever-growing data) are written *incrementally* — each new
//!   event is one appended row in the `events` table, and redactions/deletes are
//!   single-row updates/deletes. Events are excluded from the snapshot blob.
//! - **Everything else** (rooms/current-state, accounts, account data, e2ee,
//!   pushers, …) is bounded and low-churn, so it is snapshotted as a single
//!   JSON blob.
//!
//! This means the writer never re-serializes or re-writes tens of MB every flush
//! (the earlier full-state snapshot did, which starved a CPU/disk and produced
//! tall tail-latency spikes). Mutations only append cheap ops to
//! `MemState::pending_persist` and flip a dirty flag; the writer debounces,
//! drains the ops (a brief O(1) lock hold), then applies them + writes the small
//! snapshot with the lock released. A final synchronous flush on drop keeps
//! reopen-durability intact.

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use rusqlite::Connection;
use serde_json::Value;

use crate::storage::memory::{
    MemState, MemoryStorage, Persist, PersistOp, PersistSignal, TimelineEntry,
};

/// Debounce window: after the writer is woken it waits this long so a burst of
/// mutations collapses into a single batch instead of one write each. A crash
/// loses at most this window of writes; a clean shutdown flushes.
const FLUSH_DEBOUNCE: Duration = Duration::from_millis(200);

/// Checkpoint the WAL once this many bytes of events have been written since the
/// last checkpoint. Large enough that checkpoints are rare (keeping their fsync
/// stall off the common path), small enough to bound WAL growth for
/// long-running servers.
const WAL_CHECKPOINT_BYTES: usize = 256 * 1024 * 1024;

/// SQLite persistence backend: a connection + a dirty signal.
struct SqlitePersister {
    conn: Mutex<Connection>,
    signal: PersistSignal,
}

impl SqlitePersister {
    /// Apply a batch of incremental event ops in a single transaction. Returns
    /// the approximate number of bytes written (used to pace WAL checkpoints).
    fn apply_ops(&self, ops: &[PersistOp]) -> usize {
        if ops.is_empty() {
            return 0;
        }
        let mut conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return 0,
        };
        let tx = match conn.transaction() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("sqlite: begin txn failed: {e}");
                return 0;
            }
        };
        let mut bytes_written = 0usize;
        for op in ops {
            let res = match op {
                PersistOp::Upsert { event_id, room_id, stream_pos, data } => {
                    let bytes = serde_json::to_vec(&**data).unwrap_or_default();
                    bytes_written += bytes.len() + event_id.len() + 32;
                    // On event-ID conflict only the body changes (a redaction);
                    // room_id/stream_pos from the original insert are preserved.
                    tx.execute(
                        "INSERT INTO events (event_id, room_id, stream_pos, data) VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(event_id) DO UPDATE SET data = excluded.data",
                        rusqlite::params![event_id, room_id, stream_pos, bytes],
                    )
                }
                PersistOp::Delete { event_id } => {
                    tx.execute("DELETE FROM events WHERE event_id = ?1", rusqlite::params![event_id])
                }
            };
            if let Err(e) = res {
                eprintln!("sqlite: event op failed: {e}");
            }
        }
        if let Err(e) = tx.commit() {
            eprintln!("sqlite: commit failed: {e}");
        }
        bytes_written
    }

    /// Fold the WAL back into the main database and truncate it. Called by the
    /// writer thread only when the WAL has grown past a threshold, so the fsync
    /// stall it causes is rare (auto-checkpoint is disabled to keep checkpoints
    /// off the frequent-flush cadence — they were the tail-latency spikes).
    fn checkpoint(&self) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        }
    }

    /// Serialize + write the (small, events-excluded) state snapshot blob.
    fn write_snapshot(&self, state: &MemState) {
        let bytes = match serde_json::to_vec(state) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("sqlite: snapshot serialize failed: {e}");
                return;
            }
        };
        if let Ok(conn) = self.conn.lock() {
            if let Err(e) = conn.execute(
                "INSERT OR REPLACE INTO snapshot (id, data) VALUES (0, ?1)",
                rusqlite::params![bytes],
            ) {
                eprintln!("sqlite: snapshot write failed: {e}");
            }
        }
    }
}

impl Persist for SqlitePersister {
    fn mark_dirty(&self) {
        self.signal.wake();
    }

    /// Synchronous flush used on drop: apply any remaining queued ops, snapshot,
    /// and fold the WAL back into the DB so a reopen doesn't replay a large WAL.
    fn flush(&self, state: &MemState) {
        self.apply_ops(&state.pending_persist);
        self.write_snapshot(state);
        self.checkpoint();
    }

    fn shutdown(&self) {
        self.signal.shutdown();
    }
}

/// Open (or create) a SQLite-backed store at `path`, loading any prior snapshot
/// + events and spawning the background incremental writer.
pub fn create_sqlite_storage(path: &str) -> MemoryStorage {
    let conn = Connection::open(path).expect("open sqlite database");
    conn.execute_batch(
        // WAL + synchronous=NORMAL: fsync at checkpoints rather than every commit
        // (durable across app crashes; matches strix's default). Cuts per-flush
        // fsync stalls on the writer thread.
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA wal_autocheckpoint=0;
         CREATE TABLE IF NOT EXISTS snapshot (id INTEGER PRIMARY KEY, data BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS events (
             event_id TEXT PRIMARY KEY,
             room_id TEXT,
             stream_pos INTEGER,
             data BLOB NOT NULL
         );",
    )
    .expect("init sqlite schema");

    // Load the (small) snapshot: everything except events.
    let loaded: Option<Vec<u8>> = conn
        .query_row("SELECT data FROM snapshot WHERE id = 0", [], |r| r.get(0))
        .ok();
    let mut state = match loaded {
        Some(bytes) => serde_json::from_slice::<MemState>(&bytes).unwrap_or_else(|e| {
            eprintln!("sqlite: failed to deserialize snapshot ({e}); starting empty");
            MemState::default()
        }),
        None => MemState::default(),
    };
    state.persist_enabled = true;

    // Rebuild events + per-room timelines from the events table (ordered by
    // stream position so each room's timeline is reconstructed in order; rows
    // with NULL room_id/stream_pos are non-timeline events → events_by_id only).
    {
        let mut stmt = conn
            .prepare("SELECT event_id, room_id, stream_pos, data FROM events ORDER BY stream_pos")
            .expect("prepare events load");
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                ))
            })
            .expect("query events");
        for row in rows.flatten() {
            let (event_id, room_id, stream_pos, data) = row;
            if let Ok(val) = serde_json::from_slice::<Value>(&data) {
                state.events_by_id.insert(event_id.clone(), Arc::new(val));
                if let (Some(rid), Some(pos)) = (room_id, stream_pos) {
                    state
                        .room_timeline
                        .entry(rid)
                        .or_default()
                        .push_back(TimelineEntry { event_id, stream_pos: pos });
                }
            }
        }
    }

    let state = Arc::new(RwLock::new(state));
    let persister = Arc::new(SqlitePersister { conn: Mutex::new(conn), signal: PersistSignal::default() });

    // Background writer: on each wake, debounce to batch a burst, then drain the
    // queued event ops + take an O(1) snapshot clone under a brief write lock,
    // and apply/write with the lock released — so neither the (now small)
    // snapshot nor the incremental event writes block message sends.
    let writer = {
        let state = Arc::clone(&state);
        let persister = Arc::clone(&persister);
        std::thread::spawn(move || {
            let mut wal_bytes: usize = 0;
            while persister.signal.wait_and_clear() {
                std::thread::sleep(FLUSH_DEBOUNCE);
                let (ops, snapshot) = {
                    let mut guard = state.write().expect("memory storage lock poisoned");
                    let ops = std::mem::take(&mut guard.pending_persist);
                    (ops, guard.clone())
                };
                wal_bytes += persister.apply_ops(&ops);
                persister.write_snapshot(&snapshot);
                // Checkpoint only when the WAL has grown large, so the fsync stall
                // is rare rather than every few seconds. Bounds the WAL for
                // long-running use without spiking the common path.
                if wal_bytes >= WAL_CHECKPOINT_BYTES {
                    persister.checkpoint();
                    wal_bytes = 0;
                }
            }
        })
    };

    MemoryStorage::with_persistence(state, persister as Arc<dyn Persist>, writer)
}
