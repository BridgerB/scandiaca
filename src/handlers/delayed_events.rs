//! MSC4140 — Delayed events ("cancellable delayed events"), port of strix
//! `handlers/delayed-events.ts`.
//!
//! A client schedules an event by adding `?org.matrix.msc4140.delay=<ms>` to a
//! normal send/state PUT; instead of sending immediately we register a pending
//! "delayed event" and return a `delay_id`. The event fires when the timer
//! elapses or the client POSTs `{action: "send"}`; the client can also `cancel`
//! or `restart` it. Pending events are persisted to the scheduling user's global
//! account data so they survive a restart (rehydrated on the next GET).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::response::Json;
use serde_json::{json, Map, Value};

use crate::errors::{bad_json, invalid_param, not_found, MatrixResult};
use crate::events::{
    build_event, check_event_auth, get_membership, select_auth_events, BuildEventParams,
};
use crate::room_ops::require_joined_room;
use crate::server::{now_ms, AppState, AuthCtx};
use crate::types::identifiers::{EventId, RoomId, UserId};

const ACCOUNT_DATA_TYPE: &str = "org.matrix.msc4140.delayed_events";
const SEP: char = '\u{1f}';

#[derive(Clone)]
struct DelayedEvent {
    delay_id: String,
    user_id: String,
    device_id: String,
    room_id: String,
    event_type: String,
    state_key: Option<String>,
    content: Map<String, Value>,
    delay_ms: i64,
    running_since: i64,
    send_at: i64,
}

/// Pending delayed events, keyed by delay_id.
static REGISTRY: LazyLock<Mutex<HashMap<String, DelayedEvent>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// Live timer abort handles, keyed by delay_id.
static TIMERS: LazyLock<Mutex<HashMap<String, tokio::task::AbortHandle>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
/// (room\x1ftype\x1fstate_key) -> delay_id, so scheduling a new delayed state
/// event supersedes a pending one for the same state.
static STATE_INDEX: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static DELAY_COUNTER: AtomicU64 = AtomicU64::new(0);

fn new_delay_id() -> String {
    format!("{}_{}", now_ms(), DELAY_COUNTER.fetch_add(1, Ordering::SeqCst))
}

fn state_triple(room_id: &str, event_type: &str, state_key: &str) -> String {
    format!("{room_id}{SEP}{event_type}{SEP}{state_key}")
}

/// Parse the `org.matrix.msc4140.delay` query value from a raw query string.
/// Returns `Ok(None)` when absent, `Err` when present but not a positive integer.
pub fn delay_param(raw_query: &Option<String>) -> MatrixResult<Option<i64>> {
    let Some(raw) = raw_query.as_deref() else { return Ok(None) };
    for kv in raw.split('&') {
        if let Some(v) = kv.strip_prefix("org.matrix.msc4140.delay=") {
            let n: i64 = v
                .parse()
                .map_err(|_| invalid_param("'org.matrix.msc4140.delay' must be a positive integer"))?;
            if n <= 0 {
                return Err(invalid_param("'org.matrix.msc4140.delay' must be a positive integer"));
            }
            return Ok(Some(n));
        }
    }
    Ok(None)
}

// --- persistence (per-user global account data) ----------------------------

async fn load_persisted(st: &AppState, user_id: &str) -> Map<String, Value> {
    st.storage
        .get_global_account_data(&UserId::from(user_id), ACCOUNT_DATA_TYPE)
        .await
        .and_then(|d| d.get("events").and_then(Value::as_object).cloned())
        .unwrap_or_default()
}

async fn save_persisted(st: &AppState, user_id: &str, events: Map<String, Value>) {
    let mut m = Map::new();
    m.insert("events".to_string(), Value::Object(events));
    st.storage.set_global_account_data(&UserId::from(user_id), ACCOUNT_DATA_TYPE, m).await;
}

async fn persist(st: &AppState, de: &DelayedEvent) {
    let mut events = load_persisted(st, &de.user_id).await;
    let mut entry = Map::new();
    entry.insert("delay_id".to_string(), json!(de.delay_id));
    entry.insert("device_id".to_string(), json!(de.device_id));
    entry.insert("room_id".to_string(), json!(de.room_id));
    entry.insert("type".to_string(), json!(de.event_type));
    entry.insert("content".to_string(), Value::Object(de.content.clone()));
    entry.insert("delay".to_string(), json!(de.delay_ms));
    entry.insert("running_since".to_string(), json!(de.running_since));
    entry.insert("send_at".to_string(), json!(de.send_at));
    if let Some(sk) = &de.state_key {
        entry.insert("state_key".to_string(), json!(sk));
    }
    events.insert(de.delay_id.clone(), Value::Object(entry));
    save_persisted(st, &de.user_id, events).await;
}

async fn unpersist(st: &AppState, user_id: &str, delay_id: &str) {
    let mut events = load_persisted(st, user_id).await;
    if events.remove(delay_id).is_some() {
        save_persisted(st, user_id, events).await;
    }
}

// --- registry / timers -----------------------------------------------------

/// Remove an entry from the registry + state index, returning it. When `abort`
/// is set the pending timer is cancelled — the timer task itself passes `false`
/// so it does not cancel its own (running) future.
fn take_entry(delay_id: &str, abort: bool) -> Option<DelayedEvent> {
    let de = REGISTRY.lock().unwrap().remove(delay_id)?;
    if let Some(handle) = TIMERS.lock().unwrap().remove(delay_id) {
        if abort {
            handle.abort();
        }
    }
    if let Some(sk) = &de.state_key {
        let triple = state_triple(&de.room_id, &de.event_type, sk);
        let mut idx = STATE_INDEX.lock().unwrap();
        if idx.get(&triple).map(|v| v == &de.delay_id).unwrap_or(false) {
            idx.remove(&triple);
        }
    }
    Some(de)
}

/// Arm (or re-arm) a timer for `de` that fires at `de.send_at`.
fn arm(st: &AppState, de: &DelayedEvent) {
    let remaining = (de.send_at - now_ms()).max(0) as u64;
    let st2 = st.clone();
    let id = de.delay_id.clone();
    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(remaining)).await;
        // Fire without aborting our own timer handle.
        if let Some(de) = take_entry(&id, false) {
            unpersist(&st2, &de.user_id, &de.delay_id).await;
            fire_event(&st2, &de).await;
        }
    })
    .abort_handle();
    TIMERS.lock().unwrap().insert(de.delay_id.clone(), handle);
}

/// Build + auth + store a fired delayed event (same path as a normal send).
/// Failures are swallowed — a delayed event firing after its sender left simply
/// does not get sent. Mirrors strix `fireDelayedEvent` (no federation fan-out).
async fn fire_event(st: &AppState, de: &DelayedEvent) {
    let rid = RoomId::from(de.room_id.as_str());
    let Some(room) = st.storage.get_room(&rid).await else { return };
    if get_membership(&room, &de.user_id) != Some("join") {
        return;
    }
    let auth_events =
        select_auth_events(&de.event_type, de.state_key.as_deref(), &room, &de.user_id, Some(&de.content));
    let (event, event_id) = build_event(BuildEventParams {
        room_id: &de.room_id,
        sender: &de.user_id,
        event_type: &de.event_type,
        content: Value::Object(de.content.clone()),
        state_key: de.state_key.as_deref(),
        depth: room.depth,
        prev_events: room.forward_extremities.iter().map(|e| e.as_str().to_string()).collect(),
        auth_events,
        redacts: None,
        unsigned: None,
        server_name: &st.server_name,
        signing_key: Some(st.signing_key.as_ref()),
        room_version: Some(&room.room_version),
        origin_server_ts: None,
    });
    if serde_json::to_vec(&event).map(|v| v.len()).unwrap_or(0) > 65536 {
        return;
    }
    if check_event_auth(&event, &room).is_err() {
        return;
    }
    let eid = EventId::from(event_id.as_str());
    if de.state_key.is_some() {
        st.storage.set_state_event(&rid, event.clone(), &eid).await;
    } else {
        st.storage.store_event(event.clone(), &eid).await;
        crate::relations::index_relation(&*st.storage, &event, &eid).await;
    }
    st.storage.update_room_dag(&rid, room.depth + 1, vec![eid]).await;
}

/// Register a pending delayed event and arm its timer; returns the delay_id.
#[allow(clippy::too_many_arguments)]
async fn schedule(
    st: &AppState,
    user_id: &str,
    device_id: &str,
    room_id: &str,
    event_type: &str,
    state_key: Option<String>,
    content: Map<String, Value>,
    delay_ms: i64,
) -> String {
    // A new delayed state event supersedes any pending one for the same state.
    if let Some(sk) = &state_key {
        let prev = STATE_INDEX.lock().unwrap().get(&state_triple(room_id, event_type, sk)).cloned();
        if let Some(prev_id) = prev {
            if let Some(prev_de) = take_entry(&prev_id, true) {
                unpersist(st, &prev_de.user_id, &prev_de.delay_id).await;
            }
        }
    }

    let delay_id = new_delay_id();
    let now = now_ms();
    let de = DelayedEvent {
        delay_id: delay_id.clone(),
        user_id: user_id.to_string(),
        device_id: device_id.to_string(),
        room_id: room_id.to_string(),
        event_type: event_type.to_string(),
        state_key: state_key.clone(),
        content,
        delay_ms,
        running_since: now,
        send_at: now + delay_ms,
    };
    REGISTRY.lock().unwrap().insert(delay_id.clone(), de.clone());
    if let Some(sk) = &state_key {
        STATE_INDEX.lock().unwrap().insert(state_triple(room_id, event_type, sk), delay_id.clone());
    }
    arm(st, &de);
    persist(st, &de).await;
    delay_id
}

/// Rehydrate a user's persisted delayed events into the registry (re-arming
/// timers), so pending events survive a restart.
async fn rehydrate(st: &AppState, user_id: &str) {
    for (_, v) in load_persisted(st, user_id).await {
        let Some(o) = v.as_object() else { continue };
        let delay_id = o.get("delay_id").and_then(Value::as_str).unwrap_or("").to_string();
        if delay_id.is_empty() || REGISTRY.lock().unwrap().contains_key(&delay_id) {
            continue;
        }
        let de = DelayedEvent {
            delay_id: delay_id.clone(),
            user_id: user_id.to_string(),
            device_id: o.get("device_id").and_then(Value::as_str).unwrap_or("").to_string(),
            room_id: o.get("room_id").and_then(Value::as_str).unwrap_or("").to_string(),
            event_type: o.get("type").and_then(Value::as_str).unwrap_or("").to_string(),
            state_key: o.get("state_key").and_then(Value::as_str).map(String::from),
            content: o.get("content").and_then(Value::as_object).cloned().unwrap_or_default(),
            delay_ms: o.get("delay").and_then(Value::as_i64).unwrap_or(0),
            running_since: o.get("running_since").and_then(Value::as_i64).unwrap_or(0),
            send_at: o.get("send_at").and_then(Value::as_i64).unwrap_or(0),
        };
        REGISTRY.lock().unwrap().insert(delay_id.clone(), de.clone());
        if let Some(sk) = &de.state_key {
            STATE_INDEX.lock().unwrap().insert(state_triple(&de.room_id, &de.event_type, sk), delay_id.clone());
        }
        arm(st, &de);
    }
}

fn require_object(content: &Value) -> MatrixResult<Map<String, Value>> {
    content.as_object().cloned().ok_or_else(|| bad_json("Event content must be a JSON object"))
}

// --- entry points from the send/state PUT handlers -------------------------

/// `PUT .../rooms/{roomId}/send/{eventType}/{txnId}?org.matrix.msc4140.delay=N`.
/// Idempotent per (user, device, room, txnId).
pub async fn schedule_message(
    st: &AppState,
    auth: &AuthCtx,
    room_id: &str,
    event_type: &str,
    txn_id: &str,
    delay_ms: i64,
    content: &Value,
) -> MatrixResult<Json<Value>> {
    let scoped = format!("delayed {room_id} {txn_id}");
    if let Some(existing) = st.storage.get_txn_event_id(&auth.user_id, &auth.device_id, &scoped).await {
        return Ok(Json(json!({ "delay_id": existing.as_str() })));
    }
    let content = require_object(content)?;
    require_joined_room(&*st.storage, &RoomId::from(room_id), auth.user_id.as_str()).await?;
    let delay_id = schedule(
        st,
        auth.user_id.as_str(),
        auth.device_id.as_str(),
        room_id,
        event_type,
        None,
        content,
        delay_ms,
    )
    .await;
    st.storage
        .set_txn_event_id(&auth.user_id, &auth.device_id, &scoped, &EventId::from(delay_id.as_str()))
        .await;
    Ok(Json(json!({ "delay_id": delay_id })))
}

/// `PUT .../rooms/{roomId}/state/{eventType}/{stateKey}?org.matrix.msc4140.delay=N`.
pub async fn schedule_state(
    st: &AppState,
    auth: &AuthCtx,
    room_id: &str,
    event_type: &str,
    state_key: &str,
    delay_ms: i64,
    content: &Value,
) -> MatrixResult<Json<Value>> {
    let content = require_object(content)?;
    require_joined_room(&*st.storage, &RoomId::from(room_id), auth.user_id.as_str()).await?;
    let delay_id = schedule(
        st,
        auth.user_id.as_str(),
        auth.device_id.as_str(),
        room_id,
        event_type,
        Some(state_key.to_string()),
        content,
        delay_ms,
    )
    .await;
    Ok(Json(json!({ "delay_id": delay_id })))
}

/// `GET /_matrix/client/unstable/org.matrix.msc4140/delayed_events`.
pub async fn get_delayed_events(State(st): State<AppState>, auth: AuthCtx) -> MatrixResult<Json<Value>> {
    rehydrate(&st, auth.user_id.as_str()).await;
    let mut list: Vec<DelayedEvent> = REGISTRY
        .lock()
        .unwrap()
        .values()
        .filter(|de| de.user_id == auth.user_id.as_str())
        .cloned()
        .collect();
    list.sort_by_key(|de| de.send_at);
    let delayed_events: Vec<Value> = list
        .iter()
        .map(|de| {
            let mut e = Map::new();
            e.insert("delay_id".to_string(), json!(de.delay_id));
            e.insert("room_id".to_string(), json!(de.room_id));
            e.insert("type".to_string(), json!(de.event_type));
            e.insert("content".to_string(), Value::Object(de.content.clone()));
            e.insert("delay".to_string(), json!(de.delay_ms));
            e.insert("running_since".to_string(), json!(de.running_since));
            if let Some(sk) = &de.state_key {
                e.insert("state_key".to_string(), json!(sk));
            }
            Value::Object(e)
        })
        .collect();
    Ok(Json(json!({ "delayed_events": delayed_events })))
}

/// `POST /_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delayId}/{action}`
/// where action is send|cancel|restart. Keyed purely by delay_id (no auth),
/// matching the Complement test; unknown ids/actions 404.
pub async fn post_delayed_event_action(
    State(st): State<AppState>,
    Path((delay_id, action)): Path<(String, String)>,
) -> MatrixResult<Json<Value>> {
    if action != "send" && action != "cancel" && action != "restart" {
        return Err(not_found("Unknown delayed event action"));
    }
    if !REGISTRY.lock().unwrap().contains_key(&delay_id) {
        return Err(not_found("No delayed event found with that delay_id"));
    }

    match action.as_str() {
        "cancel" => {
            if let Some(de) = take_entry(&delay_id, true) {
                unpersist(&st, &de.user_id, &de.delay_id).await;
            }
        }
        "restart" => {
            let de = REGISTRY.lock().unwrap().get(&delay_id).cloned();
            if let Some(mut de) = de {
                if let Some(handle) = TIMERS.lock().unwrap().remove(&delay_id) {
                    handle.abort();
                }
                let now = now_ms();
                de.running_since = now;
                de.send_at = now + de.delay_ms;
                REGISTRY.lock().unwrap().insert(delay_id.clone(), de.clone());
                arm(&st, &de);
                persist(&st, &de).await;
            }
        }
        _ => {
            if let Some(de) = take_entry(&delay_id, true) {
                unpersist(&st, &de.user_id, &de.delay_id).await;
                fire_event(&st, &de).await;
            }
        }
    }
    Ok(Json(json!({})))
}
