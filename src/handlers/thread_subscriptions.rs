//! MSC4306 thread subscriptions — port of strix `handlers/thread-subscriptions.ts`.
//!
//! A user subscribes to a thread manually or automatically (in response to
//! activity). Subscriptions are process-local (the Storage trait is not
//! extended), matching strix. Endpoints:
//!   PUT/GET/DELETE
//!   /_matrix/client/unstable/io.element.msc4306/rooms/{roomId}/thread/{root}/subscription

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{LazyLock, Mutex};

use axum::extract::{Path, State};
use axum::response::Json;
use serde_json::{json, Value};

use crate::errors::{not_found, MatrixError, MatrixResult};
use crate::extract::OptionalJson;
use crate::server::{AppState, AuthCtx};
use crate::storage::Direction;
use crate::types::identifiers::{EventId, RoomId};

#[derive(Default, Clone)]
struct ThreadState {
    /// `Some(automatic)` when subscribed; `None` when not.
    subscription: Option<bool>,
    /// Timeline length recorded at the most recent unsubscribe; an automatic
    /// subscription whose cause predates this conflicts.
    unsubscribed_at: Option<usize>,
}

static STORE: LazyLock<Mutex<HashMap<String, ThreadState>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static BUMP: AtomicI64 = AtomicI64::new(0);

/// Advance the monotonic bump counter above the current stream position.
fn next_bump(stream_pos: i64) {
    loop {
        let cur = BUMP.load(Ordering::SeqCst);
        let next = cur.max(stream_pos) + 1;
        if BUMP.compare_exchange(cur, next, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            break;
        }
    }
}

fn skey(user: &str, room: &str, root: &str) -> String {
    format!("{user}\u{1f}{room}\u{1f}{root}")
}

async fn require_thread_root(st: &AppState, room_id: &str, root: &str) -> MatrixResult<()> {
    match st.storage.get_event(&EventId::from(root)).await {
        Some(e) if e.event.get("room_id").and_then(Value::as_str) == Some(room_id) => Ok(()),
        _ => Err(not_found("Thread root event not found")),
    }
}

/// (ordinal of `event_id` in the room timeline, total events).
async fn timeline_info(st: &AppState, room_id: &RoomId, event_id: Option<&str>) -> (Option<usize>, usize) {
    let page = st.storage.get_events_by_room(room_id, 100000, Some(0), Direction::Forward).await;
    let ordinal = event_id.and_then(|eid| page.events.iter().position(|e| e.event_id.as_str() == eid));
    (ordinal, page.events.len())
}

/// `PUT .../thread/{root}/subscription`.
pub async fn put_thread_subscription(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((room_id, root)): Path<(String, String)>,
    OptionalJson(body): OptionalJson,
) -> MatrixResult<Json<Value>> {
    require_thread_root(&st, &room_id, &root).await?;
    let rid = RoomId::from(room_id.as_str());
    let k = skey(auth.user_id.as_str(), &room_id, &root);

    if let Some(cause) = body.get("automatic").filter(|v| !v.is_null()) {
        // Automatic subscription: `automatic` is the cause event id.
        let Some(cause_id) = cause.as_str() else {
            return Err(MatrixError::new("M_BAD_JSON", "`automatic` must be an event ID string", 400));
        };
        let cause_ev = st.storage.get_event(&EventId::from(cause_id)).await;
        let in_thread = cause_ev
            .as_ref()
            .map(|e| {
                e.event.get("room_id").and_then(Value::as_str) == Some(room_id.as_str())
                    && e.event
                        .get("content")
                        .and_then(|c| c.get("m.relates_to"))
                        .map(|r| {
                            r.get("rel_type").and_then(Value::as_str) == Some("m.thread")
                                && r.get("event_id").and_then(Value::as_str) == Some(root.as_str())
                        })
                        .unwrap_or(false)
            })
            .unwrap_or(false);
        if !in_thread {
            return Err(MatrixError::new(
                "IO.ELEMENT.MSC4306.M_NOT_IN_THREAD",
                "The cause event is not part of the specified thread",
                400,
            ));
        }

        let existing = STORE.lock().unwrap().get(&k).cloned().unwrap_or_default();
        // Refuse an automatic subscription whose cause predates a later unsubscribe.
        if let Some(unsub_at) = existing.unsubscribed_at {
            let (ordinal, _) = timeline_info(&st, &rid, Some(cause_id)).await;
            if let Some(ord) = ordinal {
                if ord < unsub_at {
                    return Err(MatrixError::new(
                        "IO.ELEMENT.MSC4306.M_CONFLICTING_UNSUBSCRIPTION",
                        "A more recent unsubscription conflicts with this automatic subscription",
                        409,
                    ));
                }
            }
        }
        // Automatic never overwrites an existing subscription.
        if existing.subscription.is_some() {
            return Ok(Json(json!({})));
        }
        next_bump(st.storage.get_stream_position().await);
        let mut store = STORE.lock().unwrap();
        store.entry(k).or_default().subscription = Some(true);
        return Ok(Json(json!({})));
    }

    // Manual subscription: (re)set and clear any prior unsubscribe marker.
    next_bump(st.storage.get_stream_position().await);
    STORE.lock().unwrap().insert(k, ThreadState { subscription: Some(false), unsubscribed_at: None });
    Ok(Json(json!({})))
}

/// `GET .../thread/{root}/subscription`.
pub async fn get_thread_subscription(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((room_id, root)): Path<(String, String)>,
) -> MatrixResult<Json<Value>> {
    require_thread_root(&st, &room_id, &root).await?;
    let k = skey(auth.user_id.as_str(), &room_id, &root);
    let sub = STORE.lock().unwrap().get(&k).and_then(|s| s.subscription);
    match sub {
        Some(automatic) => Ok(Json(json!({ "automatic": automatic }))),
        None => Err(not_found("Not subscribed to this thread")),
    }
}

/// `DELETE .../thread/{root}/subscription`.
pub async fn delete_thread_subscription(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((room_id, root)): Path<(String, String)>,
) -> MatrixResult<Json<Value>> {
    require_thread_root(&st, &room_id, &root).await?;
    let rid = RoomId::from(room_id.as_str());
    let (_, total) = timeline_info(&st, &rid, None).await;
    let k = skey(auth.user_id.as_str(), &room_id, &root);
    let mut store = STORE.lock().unwrap();
    let e = store.entry(k).or_default();
    e.subscription = None;
    e.unsubscribed_at = Some(total);
    Ok(Json(json!({})))
}
