//! Storage-aware room operations — the parts of strix `events.ts` that depend on
//! `Storage` (deferred out of the pure Phase-2 engine): `sendStateEvent`,
//! `requireJoinedRoom`, and friends.
//!
//! Note vs strix: strix mutates the shared `RoomState` object in place so the
//! running auth context and storage stay in sync automatically. The Rust port
//! threads an [`EventContext`] (a local mirror) and persists DAG-head changes via
//! [`crate::storage::RoomStore::update_room_dag`].

use serde_json::Value;

use crate::canonical_json::canonical_json;
use crate::errors::{not_joined, room_not_found, MatrixError};
use crate::events::{
    build_event, check_event_auth, compute_event_id, ev_sender, get_membership, make_state_key,
    select_auth_events, BuildEventParams,
};
use crate::signing::SigningKey;
use crate::storage::Storage;
use crate::types::identifiers::{EventId, RoomId, UserId};
use crate::types::internal::RoomState;

/// Running context for building a chain of events into a room.
pub struct EventContext {
    pub room_state: RoomState,
    pub depth: i64,
    pub prev_events: Vec<String>,
}

impl EventContext {
    pub fn new(room_state: RoomState) -> Self {
        EventContext {
            room_state,
            depth: 0,
            prev_events: Vec::new(),
        }
    }
}

/// Build, authorize, persist, and apply a state event, advancing `ctx`
/// (strix `sendStateEvent`). Returns the new event ID. De-duplicates an
/// identical (type, state_key, sender, content) state event.
#[allow(clippy::too_many_arguments)]
pub async fn send_state_event(
    storage: &dyn Storage,
    server_name: &str,
    ctx: &mut EventContext,
    sender: &str,
    event_type: &str,
    state_key: &str,
    content: Value,
    signing_key: Option<&SigningKey>,
    origin_server_ts: Option<i64>,
) -> Result<String, MatrixError> {
    let room_version = ctx.room_state.room_version.clone();
    let auth_events = select_auth_events(
        event_type,
        Some(state_key),
        &ctx.room_state,
        sender,
        content.as_object(),
    );
    let key = make_state_key(event_type, state_key);

    // Deduplicate an identical state event (strix `deduplicate_state_event`).
    if let Some(existing) = ctx.room_state.state_events.get(&key) {
        let same_content = existing
            .get("content")
            .map(canonical_json)
            .unwrap_or_else(|| "null".to_string())
            == canonical_json(&content);
        if ev_sender(existing) == sender && same_content {
            return Ok(compute_event_id(existing, Some(&room_version)));
        }
    }

    let (event, event_id) = build_event(BuildEventParams {
        room_id: ctx.room_state.room_id.as_str(),
        sender,
        event_type,
        content,
        state_key: Some(state_key),
        depth: ctx.depth,
        prev_events: ctx.prev_events.clone(),
        auth_events,
        redacts: None,
        unsigned: None,
        server_name,
        signing_key,
        room_version: Some(&room_version),
        origin_server_ts,
    });

    check_event_auth(&event, &ctx.room_state)?;

    let eid = EventId::from(event_id.as_str());
    storage
        .set_state_event(&ctx.room_state.room_id, event.clone(), &eid)
        .await;

    // Mirror into the running context so later auth checks see this state.
    ctx.room_state.state_events.insert(key, event);
    ctx.depth += 1;
    ctx.prev_events = vec![event_id.clone()];
    ctx.room_state.depth = ctx.depth;
    ctx.room_state.forward_extremities = vec![eid.clone()];
    storage
        .update_room_dag(&ctx.room_state.room_id, ctx.depth, vec![eid])
        .await;

    Ok(event_id)
}

/// Build, authorize, persist, and apply an `m.room.member` state event for a
/// local room (strix `sendMembershipEvent`, local path — federation fan-out
/// arrives with the federation phase). `extra_content` is merged first, then the
/// server-controlled `membership` (and `reason`) are forced on top. Returns the
/// new event ID.
#[allow(clippy::too_many_arguments)]
pub async fn send_membership_event(
    storage: &dyn Storage,
    server_name: &str,
    signing_key: Option<&SigningKey>,
    fed: Option<&crate::federation::FederationClient>,
    registrations: &[crate::types::appservice::AppserviceRegistration],
    room_id: &RoomId,
    sender: &str,
    target_user_id: &str,
    membership: &str,
    reason: Option<&str>,
    extra_content: Option<serde_json::Map<String, Value>>,
) -> Result<String, MatrixError> {
    let room = storage
        .get_room(room_id)
        .await
        .ok_or_else(|| room_not_found("Room not found"))?;

    let mut content = extra_content.unwrap_or_default();
    content.insert("membership".to_string(), Value::String(membership.to_string()));
    if let Some(r) = reason {
        content.insert("reason".to_string(), Value::String(r.to_string()));
    }

    // `room.depth` is already the next depth to use (send_state_event stores
    // post-increment), and forward_extremities are the prev_events.
    let mut ctx = EventContext {
        depth: room.depth,
        prev_events: room
            .forward_extremities
            .iter()
            .map(|e| e.as_str().to_string())
            .collect(),
        room_state: room,
    };
    let event_id = send_state_event(
        storage,
        server_name,
        &mut ctx,
        sender,
        "m.room.member",
        target_user_id,
        Value::Object(content),
        signing_key,
        None,
    )
    .await?;

    // Propagate the membership change to remote servers + matching appservices.
    let eid = EventId::from(event_id.as_str());
    if let Some(stored) = storage.get_event(&eid).await {
        if let Some(fed) = fed {
            crate::federation::outbound::fanout_event(storage, fed, server_name, room_id, &stored.event).await;
        }
        crate::appservice::push::push_to_appservices(&stored.event, event_id.as_str(), registrations);
    }
    Ok(event_id)
}

/// MSC3083: does `user_id` satisfy a restricted room's `allow` list, i.e. is
/// they a joined member of any room named in `m.room.join_rules.allow`? When
/// `require_server` is set, the allowed room must also have that server joined
/// (strix `userSatisfiesRestrictedAllow`).
pub async fn user_satisfies_restricted_allow(
    storage: &dyn Storage,
    room: &RoomState,
    user_id: &str,
    require_server: Option<&str>,
) -> bool {
    let Some(jr) = room.state_events.get(&make_state_key("m.room.join_rules", "")) else {
        return false;
    };
    let Some(allow) = jr.get("content").and_then(|c| c.get("allow")).and_then(Value::as_array) else {
        return false;
    };
    for entry in allow {
        if entry.get("type").and_then(Value::as_str) != Some("m.room_membership") {
            continue;
        }
        let Some(allowed_room_id) = entry.get("room_id").and_then(Value::as_str) else { continue };
        let Some(allowed_room) = storage.get_room(&RoomId::from(allowed_room_id)).await else {
            continue;
        };
        if let Some(server) = require_server {
            if !crate::events::server_has_member(&allowed_room.state_events, server, "join") {
                continue;
            }
        }
        if get_membership(&allowed_room, user_id) == Some("join") {
            return true;
        }
    }
    false
}

/// Fetch a room and require the user to be joined (strix `requireJoinedRoom`).
pub async fn require_joined_room(
    storage: &dyn Storage,
    room_id: &RoomId,
    user_id: &str,
) -> Result<RoomState, MatrixError> {
    let room = storage
        .get_room(room_id)
        .await
        .ok_or_else(|| room_not_found("Room not found"))?;
    if get_membership(&room, user_id) != Some("join") {
        return Err(not_joined("You are not joined to this room"));
    }
    Ok(room)
}

/// Room read access, resolved by [`require_can_read_room`].
pub struct RoomRead {
    pub room: RoomState,
    /// `Some(stream_pos)` when the reader has departed (left/banned): reads must
    /// be served as of that position (SPEC-216). `None` when currently joined or
    /// world-readable (full current view).
    pub leave_pos: Option<i64>,
}

/// Require the user can *read* the room: joined, previously a member
/// (leave/ban — SPEC-216 lets a departed user read up to their leave point), or
/// the room is world-readable. A room the user has *forgotten* is 403. Used by
/// the room read endpoints (`/state`, `/members`, `/messages`, `/event`);
/// `/joined_members` deliberately keeps the stricter `require_joined_room`.
pub async fn require_can_read_room(
    storage: &dyn Storage,
    room_id: &RoomId,
    user_id: &str,
) -> Result<RoomRead, MatrixError> {
    let room = storage
        .get_room(room_id)
        .await
        .ok_or_else(|| room_not_found("Room not found"))?;

    // A forgotten room is invisible to the user (403), even though they left.
    let uid = UserId::from(user_id);
    let forgotten = storage
        .get_room_account_data(&uid, room_id, "m.internal.forgotten")
        .await
        .and_then(|d| d.get("forgotten").and_then(|v| v.as_bool()))
        == Some(true);
    if forgotten {
        return Err(not_joined("You are not joined to this room"));
    }

    match get_membership(&room, user_id) {
        Some("join") => Ok(RoomRead { room, leave_pos: None }),
        Some("leave") | Some("ban") => {
            let leave_pos = departure_stream_pos(storage, room_id, user_id).await;
            Ok(RoomRead { room, leave_pos: Some(leave_pos) })
        }
        _ => {
            let world_readable = room
                .state_events
                .get("m.room.history_visibility\u{1f}")
                .and_then(|e| e.get("content"))
                .and_then(|c| c.get("history_visibility"))
                .and_then(|v| v.as_str())
                == Some("world_readable");
            if world_readable {
                Ok(RoomRead { room, leave_pos: None })
            } else {
                Err(not_joined("You are not joined to this room"))
            }
        }
    }
}

/// The stream position of the user's latest `m.room.member` event — their
/// departure point (strix `resolveDepartedRead`).
async fn departure_stream_pos(storage: &dyn Storage, room_id: &RoomId, user_id: &str) -> i64 {
    let all = storage.get_events_by_room_since(room_id, 0, 1_000_000).await;
    let mut leave_pos = 0;
    for e in &all.events {
        if e.event.get("type").and_then(|v| v.as_str()) == Some("m.room.member")
            && e.event.get("state_key").and_then(|v| v.as_str()) == Some(user_id)
        {
            leave_pos = e.stream_pos;
        }
    }
    leave_pos
}

/// Room state as of a stream position: replay events up to `up_to` (inclusive)
/// keeping the latest state event per `(type, state_key)`. Used for departed
/// (SPEC-216) reads of `/state` and `/members`.
pub async fn state_as_of(
    storage: &dyn Storage,
    room_id: &RoomId,
    up_to: i64,
) -> std::collections::BTreeMap<String, (Value, EventId)> {
    use crate::events::{ev_state_key, ev_type, make_state_key};
    let all = storage.get_events_by_room_since(room_id, 0, 1_000_000).await;
    let mut state = std::collections::BTreeMap::new();
    for e in all.events {
        if e.stream_pos > up_to {
            break;
        }
        let Some(sk) = ev_state_key(&e.event) else {
            continue;
        };
        let key = make_state_key(ev_type(&e.event), sk);
        state.insert(key, (e.event, e.event_id));
    }
    state
}

/// Timeline events up to (and including) a stream position — for departed
/// `/messages` reads clamped to the leave point.
pub async fn events_up_to(
    storage: &dyn Storage,
    room_id: &RoomId,
    up_to: i64,
) -> Vec<crate::storage::StreamEventRecord> {
    storage
        .get_events_by_room_since(room_id, 0, 1_000_000)
        .await
        .events
        .into_iter()
        .filter(|e| e.stream_pos <= up_to)
        .collect()
}
