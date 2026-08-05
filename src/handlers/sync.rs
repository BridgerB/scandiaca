//! `/sync` — port of strix `handlers/sync.ts`.
//!
//! Initial and incremental sync with long-poll. Fills join rooms (timeline,
//! state, per-room account data, ephemeral typing/receipts, unread counts),
//! invite rooms (stripped `invite_state`), knock rooms (`knock_state`), leave
//! rooms (archived history reconstructed as of the leave point), presence, and
//! top-level account data. Sync filters (timeline/state type filters, timeline
//! limit, `include_leave`) are applied. Sliding sync and gappy state deltas
//! remain simplified.

use std::collections::{HashMap, HashSet};

use axum::extract::{Query, State};
use axum::response::Json;
use serde_json::{json, Map, Value};

use super::client_event_no_room;
use crate::errors::MatrixResult;
use crate::event_filter::matches_room_event_filter;
use crate::events::event_to_stripped_state;
use crate::ignored::{get_ignored_invite_senders, get_ignored_users};
use crate::push_rules::{evaluate_push_rules, get_or_init_rules, EvaluationContext};
use crate::server::{AppState, AuthCtx};
use crate::storage::Direction;
use crate::types::ephemeral::PresenceState;
use crate::types::filters::RoomEventFilter;
use crate::types::identifiers::RoomId;

const INITIAL_TIMELINE_LIMIT: usize = 20;
const INCREMENTAL_TIMELINE_LIMIT: usize = 50;

/// The resolved subset of a sync filter this handler applies.
struct ResolvedFilter {
    timeline_limit: usize,
    timeline_filter: Option<RoomEventFilter>,
    state_filter: Option<RoomEventFilter>,
    include_leave: bool,
}

/// Resolve the `?filter=` parameter (inline JSON or a stored filter id) into the
/// pieces sync applies. Falls back to defaults when absent/unparseable.
async fn resolve_filter(
    st: &AppState,
    auth: &AuthCtx,
    params: &HashMap<String, String>,
    is_initial: bool,
) -> ResolvedFilter {
    let default_limit = if is_initial {
        INITIAL_TIMELINE_LIMIT
    } else {
        INCREMENTAL_TIMELINE_LIMIT
    };
    let mut resolved = ResolvedFilter {
        timeline_limit: default_limit,
        timeline_filter: None,
        state_filter: None,
        include_leave: false,
    };

    let Some(raw) = params.get("filter") else {
        return resolved;
    };
    // Inline JSON filter, or a filter id previously created via /user/{id}/filter.
    let filter: Option<Value> = if raw.trim_start().starts_with('{') {
        serde_json::from_str(raw).ok()
    } else {
        st.storage
            .get_filter(&auth.user_id, raw)
            .await
            .map(Value::Object)
    };
    let Some(room) = filter.as_ref().and_then(|f| f.get("room")) else {
        return resolved;
    };

    if let Some(tl) = room.get("timeline") {
        if let Some(limit) = tl.get("limit").and_then(Value::as_u64) {
            resolved.timeline_limit = limit as usize;
        }
        resolved.timeline_filter = serde_json::from_value(tl.clone()).ok();
    }
    if let Some(state) = room.get("state") {
        resolved.state_filter = serde_json::from_value(state.clone()).ok();
    }
    resolved.include_leave = room
        .get("include_leave")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    resolved
}

/// `GET /_matrix/client/v3/sync`.
pub async fn sync(
    State(st): State<AppState>,
    auth: AuthCtx,
    Query(params): Query<HashMap<String, String>>,
) -> MatrixResult<Json<Value>> {
    let since: Option<i64> = params.get("since").and_then(|s| s.parse().ok());
    let timeout: u64 = params.get("timeout").and_then(|s| s.parse().ok()).unwrap_or(0);
    let is_initial = since.is_none();
    let since_pos = since.unwrap_or(0);

    // `?set_presence=` sets the caller's presence (default online). Only write
    // when it actually changes, to avoid waking every long-poll each sync
    // (TestPresence "presence can be set from sync").
    let desired = match params.get("set_presence").map(String::as_str) {
        Some("offline") => PresenceState::Offline,
        Some("unavailable") => PresenceState::Unavailable,
        _ => PresenceState::Online,
    };
    if st.storage.get_presence(&auth.user_id).await.map(|p| p.presence) != Some(desired) {
        st.storage.set_presence(&auth.user_id, desired, None).await;
    }

    if !is_initial && timeout > 0 && st.storage.get_stream_position().await <= since_pos {
        st.storage.wait_for_events(since_pos, timeout).await;
    }

    let filter = resolve_filter(&st, &auth, &params, is_initial).await;
    let next_batch = st.storage.get_stream_position().await;
    let memberships = st.storage.get_rooms_for_user_with_membership(&auth.user_id).await;

    let rules = get_or_init_rules(&*st.storage, &auth.user_id).await;
    let display_name = st.storage.get_profile(&auth.user_id).await.and_then(|p| p.displayname);
    let ignored_users = get_ignored_users(&*st.storage, &auth.user_id).await;
    let ignored_invite_senders = get_ignored_invite_senders(&*st.storage, &auth.user_id).await;

    let mut join = Map::new();
    let mut invite = Map::new();
    let mut knock = Map::new();
    let mut leave = Map::new();

    // Users this syncer newly shares a room with in this window (for presence +
    // device_lists.changed). Every user in a currently-joined room (for presence
    // on initial sync, and to gate incremental presence/device-list changes).
    let mut newly_shared: HashSet<String> = HashSet::new();
    let mut seen_users: HashSet<String> = HashSet::new();
    // Users whose final membership transition this window (in a room we share, or
    // a room we ourselves left) is leave/ban — candidates for device_lists.left.
    let mut newly_left: HashSet<String> = HashSet::new();

    for m in &memberships {
        let room_id = &m.room_id;

        match m.membership.as_str() {
            "join" => {
                let (room_json, has_content) =
                    build_join_room(&st, &auth, room_id, is_initial, since_pos, next_batch, &filter, &rules, display_name.as_deref()).await;
                // On incremental sync omit rooms with no changes this window
                // (TestSync: an unchanged room must not appear).
                if is_initial || has_content {
                    join.insert(room_id.to_string(), room_json);
                }
                // Collect joined members (seen). Track each user's FINAL membership
                // transition in this window: join/invite/knock → device_lists.changed
                // candidate; leave/ban → device_lists.left candidate.
                let members = st.storage.get_member_events(room_id).await;
                for me in &members {
                    if me.event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("join") {
                        if let Some(sk) = me.event.get("state_key").and_then(Value::as_str) {
                            seen_users.insert(sk.to_string());
                        }
                    }
                }
                if !is_initial {
                    let window = st.storage.get_events_by_room_since(room_id, since_pos, 100000).await;
                    let mut final_membership: HashMap<String, String> = HashMap::new();
                    for e in &window.events {
                        if e.event.get("type").and_then(Value::as_str) != Some("m.room.member") {
                            continue;
                        }
                        let Some(sk) = e.event.get("state_key").and_then(Value::as_str) else { continue };
                        let Some(m) = e.event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) else { continue };
                        final_membership.insert(sk.to_string(), m.to_string());
                    }
                    let self_newly_joined =
                        final_membership.get(auth.user_id.as_str()).map(String::as_str) == Some("join");
                    for (u, m) in &final_membership {
                        match m.as_str() {
                            "join" | "invite" | "knock" => {
                                newly_shared.insert(u.clone());
                            }
                            "leave" | "ban" if u != auth.user_id.as_str() => {
                                newly_left.insert(u.clone());
                            }
                            _ => {}
                        }
                    }
                    // When the syncer itself newly joined this room, every current
                    // member is a user they NEWLY share a room with — surface all of
                    // them in device_lists.changed (TestDeviceListUpdates join case).
                    if self_newly_joined {
                        for me in &members {
                            if me.event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("join") {
                                if let Some(sk) = me.event.get("state_key").and_then(Value::as_str) {
                                    if sk != auth.user_id.as_str() {
                                        newly_shared.insert(sk.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            "invite" => {
                // On incremental sync only surface an invite whose membership
                // changed in this window; on initial sync always surface it.
                let membership_changed = if is_initial {
                    true
                } else {
                    st.storage
                        .get_events_by_room_since(room_id, since_pos, filter.timeline_limit)
                        .await
                        .events
                        .iter()
                        .any(|e| {
                            e.event.get("type").and_then(Value::as_str) == Some("m.room.member")
                                && e.event.get("state_key").and_then(Value::as_str) == Some(auth.user_id.as_str())
                        })
                };
                if !membership_changed {
                    continue;
                }
                let stripped = st.storage.get_stripped_state(room_id).await;
                // Drop invites from ignored / ignored-invite-sender users.
                let inviter = stripped.iter().find(|e| {
                    e.get("type").and_then(Value::as_str) == Some("m.room.member")
                        && e.get("state_key").and_then(Value::as_str) == Some(auth.user_id.as_str())
                        && e.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("invite")
                }).and_then(|e| e.get("sender").and_then(Value::as_str));
                if let Some(inviter) = inviter {
                    if ignored_users.contains(inviter) || ignored_invite_senders.contains(inviter) {
                        continue;
                    }
                }
                invite.insert(room_id.to_string(), json!({ "invite_state": { "events": stripped } }));
            }
            "knock" => {
                let membership_changed = if is_initial {
                    true
                } else {
                    st.storage
                        .get_events_by_room_since(room_id, since_pos, filter.timeline_limit)
                        .await
                        .events
                        .iter()
                        .any(|e| {
                            e.event.get("type").and_then(Value::as_str) == Some("m.room.member")
                                && e.event.get("state_key").and_then(Value::as_str) == Some(auth.user_id.as_str())
                        })
                };
                if membership_changed {
                    knock.insert(room_id.to_string(), build_knock_room(&st, room_id, auth.user_id.as_str()).await);
                }
            }
            "leave" | "ban" => {
                // Initial sync: only when the filter opts into archived rooms AND the
                // room isn't forgotten. Incremental sync: whenever the leave/ban
                // happened in this window — forgetting does NOT hide an in-window
                // leave (TestRoomForget: leave shows in the sync spanning it).
                let want = if is_initial {
                    let forgotten = st
                        .storage
                        .get_room_account_data(&auth.user_id, room_id, "m.internal.forgotten")
                        .await
                        .and_then(|d| d.get("forgotten").and_then(Value::as_bool))
                        == Some(true);
                    filter.include_leave && !forgotten
                } else {
                    true
                };
                if want {
                    if let Some(lr) = build_leave_room(&st, room_id, auth.user_id.as_str(), is_initial, since_pos, &filter).await {
                        leave.insert(room_id.to_string(), lr);
                        // We left this room this window: every other member becomes a
                        // device_lists.left candidate (we can no longer observe them
                        // through this room). Survivors sharing another joined room
                        // are filtered out after the loop.
                        if !is_initial {
                            for me in st.storage.get_member_events(room_id).await {
                                if let Some(sk) = me.event.get("state_key").and_then(Value::as_str) {
                                    if sk != auth.user_id.as_str() {
                                        newly_left.insert(sk.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Top-level (global) account data: full set on initial, delta on incremental.
    let global_ad: Vec<Value> = if is_initial {
        st.storage
            .get_all_global_account_data(&auth.user_id)
            .await
            .into_iter()
            .map(|e| json!({ "type": e.data_type, "content": Value::Object(e.content) }))
            .collect()
    } else {
        st.storage
            .get_global_account_data_since(&auth.user_id, since_pos)
            .await
            .into_iter()
            .map(|e| json!({ "type": e.data_type, "content": Value::Object(e.content) }))
            .collect()
    };

    // To-device messages for this device (drained after reading).
    let to_device: Vec<Value> = st
        .storage
        .get_to_device_messages(&auth.user_id, &auth.device_id)
        .await
        .into_iter()
        .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
        .collect();
    if !to_device.is_empty() {
        st.storage
            .clear_to_device_messages(&auth.user_id, &auth.device_id)
            .await;
    }

    let otk_counts = st
        .storage
        .get_one_time_key_counts(&auth.user_id, &auth.device_id)
        .await;

    // Presence: initial = every user sharing a joined room; incremental = users
    // newly shared this window + already-shared users whose presence changed.
    // Self is excluded.
    let presence_users: HashSet<String> = if is_initial {
        seen_users.iter().filter(|u| *u != auth.user_id.as_str()).cloned().collect()
    } else {
        let mut set: HashSet<String> = newly_shared.iter().filter(|u| *u != auth.user_id.as_str()).cloned().collect();
        for u in &seen_users {
            if u == auth.user_id.as_str() || set.contains(u) {
                continue;
            }
            if st.storage.get_presence_changed_at(&u.as_str().into()).await > since_pos {
                set.insert(u.clone());
            }
        }
        set
    };
    let presence_events = build_presence_events(&st, &presence_users).await;

    // device_lists.changed: users whose device keys changed in (since, next_batch]
    // and who share a joined room, plus users newly joined/invited this window.
    let device_changed: Vec<String> = if is_initial {
        Vec::new()
    } else {
        let changed: HashSet<String> = st
            .storage
            .get_changed_device_users(since_pos, next_batch)
            .await
            .into_iter()
            .map(|u| u.as_str().to_string())
            .collect();
        let mut out: HashSet<String> = changed.intersection(&seen_users).cloned().collect();
        for u in &newly_shared {
            out.insert(u.clone());
        }
        out.retain(|u| u != auth.user_id.as_str());
        out.into_iter().collect()
    };

    // device_lists.left: candidates who left a shared room (or a room we left)
    // this window and no longer share ANY currently-joined room with us.
    let device_left: Vec<String> = newly_left
        .into_iter()
        .filter(|u| u != auth.user_id.as_str() && !seen_users.contains(u))
        .collect();

    Ok(Json(json!({
        "next_batch": next_batch.to_string(),
        "rooms": {
            "join": Value::Object(join),
            "invite": Value::Object(invite),
            "leave": Value::Object(leave),
            "knock": Value::Object(knock),
        },
        "account_data": { "events": global_ad },
        "presence": { "events": presence_events },
        "device_lists": { "changed": device_changed, "left": device_left },
        "device_one_time_keys_count": otk_counts,
        "to_device": { "events": to_device },
    })))
}

/// `m.presence` events for a set of users (default `online` when unset).
async fn build_presence_events(st: &AppState, users: &HashSet<String>) -> Vec<Value> {
    let mut events = Vec::new();
    for uid in users {
        let p = st.storage.get_presence(&uid.as_str().into()).await;
        let mut content = Map::new();
        let presence_str = p
            .as_ref()
            .and_then(|p| serde_json::to_value(p.presence).ok())
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "online".to_string());
        content.insert("presence".to_string(), json!(presence_str));
        if let Some(msg) = p.as_ref().and_then(|p| p.status_msg.clone()) {
            content.insert("status_msg".to_string(), json!(msg));
        }
        events.push(json!({ "type": "m.presence", "sender": uid, "content": Value::Object(content) }));
    }
    events
}

/// Build a room the user has knocked on (`knock_state`).
async fn build_knock_room(st: &AppState, room_id: &RoomId, user_id: &str) -> Value {
    let member = st.storage.get_state_event(room_id, "m.room.member", user_id).await;
    // Federated knocks stash the stripped state on unsigned.knock_room_state.
    let mut events: Vec<Value> = member
        .as_ref()
        .and_then(|rec| rec.event.get("unsigned"))
        .and_then(|u| u.get("knock_room_state"))
        .and_then(|v| v.as_array().cloned())
        .filter(|a| !a.is_empty())
        .unwrap_or(st.storage.get_stripped_state(room_id).await);
    if let Some(rec) = &member {
        let present = events.iter().any(|e| {
            e.get("type").and_then(Value::as_str) == Some("m.room.member")
                && e.get("state_key").and_then(Value::as_str) == Some(user_id)
        });
        if !present {
            events.push(event_to_stripped_state(&rec.event));
        }
    }
    json!({ "knock_state": { "events": events } })
}

/// Build the `rooms.leave` entry for a room the user left/was banned from.
/// Archived rooms contain only history from before the user left, so state is
/// reconstructed as of the leave point. On incremental sync returns `None`
/// unless the leave/ban event falls within `(since, now]`.
async fn build_leave_room(
    st: &AppState,
    room_id: &RoomId,
    user_id: &str,
    is_initial: bool,
    since_pos: i64,
    filter: &ResolvedFilter,
) -> Option<Value> {
    let all = st.storage.get_events_by_room(room_id, 100000, Some(0), Direction::Forward).await;
    let ordered = all.events;

    // The user's most recent leave/ban member event.
    let mut leave_idx: Option<usize> = None;
    for (i, er) in ordered.iter().enumerate() {
        if er.event.get("type").and_then(Value::as_str) == Some("m.room.member")
            && er.event.get("state_key").and_then(Value::as_str) == Some(user_id)
        {
            let mem = er.event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str);
            if mem == Some("leave") || mem == Some("ban") {
                leave_idx = Some(i);
            }
        }
    }
    let leave_idx = leave_idx?;
    let leave_event_id = ordered[leave_idx].event_id.as_str().to_string();

    // Incremental: only report a leave that happened in this window.
    let since_ids: Option<HashSet<String>> = if is_initial {
        None
    } else {
        let s = st.storage.get_events_by_room_since(room_id, since_pos, 100000).await;
        let set: HashSet<String> = s.events.iter().map(|e| e.event_id.as_str().to_string()).collect();
        if !set.contains(&leave_event_id) {
            return None;
        }
        Some(set)
    };

    let up_to_leave = &ordered[..=leave_idx];

    // State as of the leave point (fold all state events up to it).
    let mut state_at_leave: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for (i, er) in up_to_leave.iter().enumerate() {
        if let Some(sk) = er.event.get("state_key").and_then(Value::as_str) {
            let t = er.event.get("type").and_then(Value::as_str).unwrap_or("");
            state_at_leave.insert(format!("{t}\u{1f}{sk}"), i);
        }
    }

    // Timeline candidates (window-filtered for incremental), tail-limited, then
    // type-filtered.
    let candidates: Vec<&crate::storage::interface::EventRecord> = match &since_ids {
        None => up_to_leave.iter().collect(),
        Some(set) => up_to_leave.iter().filter(|e| set.contains(e.event_id.as_str())).collect(),
    };
    let tail_start = candidates.len().saturating_sub(filter.timeline_limit);
    let limited = candidates.len() > filter.timeline_limit;
    let tail = &candidates[tail_start..];
    let mut timeline_ids: HashSet<String> = HashSet::new();
    let mut timeline_events = Vec::new();
    for e in tail {
        let ce = client_event_no_room(&e.event, e.event_id.as_str());
        if matches_room_event_filter(&ce, filter.timeline_filter.as_ref()) {
            timeline_ids.insert(e.event_id.as_str().to_string());
            timeline_events.push(ce);
        }
    }

    // State section: state-at-leave (window-filtered for incremental), excluding
    // anything already in the timeline, then type-filtered.
    let mut state_events = Vec::new();
    for idx in state_at_leave.values() {
        let er = &up_to_leave[*idx];
        let eid = er.event_id.as_str();
        if let Some(set) = &since_ids {
            if !set.contains(eid) {
                continue;
            }
        }
        if timeline_ids.contains(eid) {
            continue;
        }
        let ce = client_event_no_room(&er.event, eid);
        if matches_room_event_filter(&ce, filter.state_filter.as_ref()) {
            state_events.push(ce);
        }
    }

    let prev_batch = st.storage.get_stream_position().await.to_string();
    let mut room = Map::new();
    if !state_events.is_empty() {
        room.insert("state".to_string(), json!({ "events": state_events }));
    }
    room.insert(
        "timeline".to_string(),
        json!({ "events": timeline_events, "limited": limited, "prev_batch": prev_batch }),
    );
    room.insert("account_data".to_string(), json!({ "events": [] }));
    Some(Value::Object(room))
}

/// Build a single joined room's sync payload.
#[allow(clippy::too_many_arguments)]
async fn build_join_room(
    st: &AppState,
    auth: &AuthCtx,
    room_id: &RoomId,
    is_initial: bool,
    since_pos: i64,
    next_batch: i64,
    filter: &ResolvedFilter,
    rules: &Value,
    display_name: Option<&str>,
) -> (Value, bool) {
    // Back-pagination boundary for a limited initial window (prev_batch).
    let mut init_boundary: Option<i64> = None;
    let (mut timeline_events, limited): (Vec<Value>, bool) = if is_initial {
        // The NEWEST `timeline_limit` events (walk back from the head), returned
        // in chronological order. Returning the oldest N instead hides recent
        // history in rooms with more than the limit (broke SyncTimelineHas).
        let page = st
            .storage
            .get_events_by_room(room_id, filter.timeline_limit, None, Direction::Backward)
            .await;
        let limited = page.events.len() >= filter.timeline_limit;
        if limited {
            init_boundary = page.end.map(|e| e - 1);
        }
        (
            page.events
                .iter()
                .rev()
                .map(|er| client_event_no_room(&er.event, er.event_id.as_str()))
                .filter(|ce| matches_room_event_filter(ce, filter.timeline_filter.as_ref()))
                .collect(),
            limited,
        )
    } else {
        let s = st
            .storage
            .get_events_by_room_since(room_id, since_pos, filter.timeline_limit)
            .await;
        (
            s.events
                .iter()
                .map(|er| client_event_no_room(&er.event, er.event_id.as_str()))
                .filter(|ce| matches_room_event_filter(ce, filter.timeline_filter.as_ref()))
                .collect(),
            s.limited,
        )
    };

    // MSC4115: stamp each timeline event's unsigned.membership with the syncing
    // user's membership at that event (TestMembershipOnEvents).
    stamp_membership(st, room_id, auth.user_id.as_str(), &mut timeline_events).await;

    // Full current state on initial sync; deltas are deferred.
    let state_events: Vec<Value> = if is_initial {
        st.storage
            .get_all_state(room_id)
            .await
            .iter()
            .map(|er| client_event_no_room(&er.event, er.event_id.as_str()))
            .filter(|ce| matches_room_event_filter(ce, filter.state_filter.as_ref()))
            .collect()
    } else {
        Vec::new()
    };

    // Per-room account data: full set on initial, delta on incremental.
    let room_ad: Vec<Value> = if is_initial {
        st.storage
            .get_all_room_account_data(&auth.user_id, room_id)
            .await
            .into_iter()
            .map(|e| json!({ "type": e.data_type, "content": Value::Object(e.content) }))
            .collect()
    } else {
        st.storage
            .get_room_account_data_since(&auth.user_id, since_pos)
            .await
            .into_iter()
            .filter(|e| e.room_id.as_str() == room_id.as_str())
            .map(|e| json!({ "type": e.data_type, "content": Value::Object(e.content) }))
            .collect()
    };

    let (notification_count, highlight_count) =
        unread_counts(st, auth, room_id, rules, display_name).await;

    // Emit an empty m.typing only on incremental sync when typing changed in this
    // window (a typing-stop). On initial sync a quiet room must carry zero
    // ephemeral events (TestACLsForEDUs), so never force it there.
    let typing_changed = !is_initial && st.storage.get_typing_changed_at(room_id).await > since_pos;

    // prev_batch: for an unlimited window the current stream position (also a
    // valid `at` token for GET /members?at=… — TestGetRoomMembersAtPoint); for an
    // incremental window the since token (back-pagination boundary).
    let prev_batch = if is_initial { init_boundary.unwrap_or(next_batch) } else { since_pos };

    let ephemeral = build_ephemeral(st, room_id, typing_changed).await;
    // Whether this room carries a change worth reporting on an incremental sync
    // (strix's gate): new timeline/state, changed account data, or ephemeral
    // content (a typing change, or any receipt).
    let has_ephemeral_content = ephemeral.iter().any(|e| {
        let t = e.get("type").and_then(Value::as_str);
        t == Some("m.receipt") || (t == Some("m.typing") && typing_changed)
    });
    let has_content = !timeline_events.is_empty()
        || !state_events.is_empty()
        || !room_ad.is_empty()
        || has_ephemeral_content;

    let room = json!({
        "summary": build_room_summary(st, room_id, auth.user_id.as_str()).await,
        "timeline": {
            "events": timeline_events,
            "limited": limited,
            "prev_batch": prev_batch.to_string(),
        },
        "state": { "events": state_events },
        "account_data": { "events": room_ad },
        "ephemeral": { "events": ephemeral },
        "unread_notifications": {
            "notification_count": notification_count,
            "highlight_count": highlight_count,
        },
    });
    (room, has_content)
}

/// MSC4115: stamp `unsigned.membership` on each timeline event with the syncing
/// user's membership at that event's point in the room DAG (strix
/// `computeMembershipMap` / `stampMembership`).
async fn stamp_membership(st: &AppState, room_id: &RoomId, user_id: &str, events: &mut [Value]) {
    if events.is_empty() {
        return;
    }
    let all = st.storage.get_events_by_room(room_id, 100000, Some(0), Direction::Forward).await;
    let mut map: HashMap<String, String> = HashMap::new();
    let mut current = "leave".to_string();
    for er in &all.events {
        if er.event.get("type").and_then(Value::as_str) == Some("m.room.member")
            && er.event.get("state_key").and_then(Value::as_str) == Some(user_id)
        {
            if let Some(m) = er.event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) {
                current = m.to_string();
            }
        }
        map.insert(er.event_id.as_str().to_string(), current.clone());
    }
    for ev in events.iter_mut() {
        let Some(eid) = ev.get("event_id").and_then(Value::as_str).map(String::from) else { continue };
        if let Some(m) = map.get(&eid) {
            if let Some(obj) = ev.as_object_mut() {
                let unsigned = obj.entry("unsigned").or_insert_with(|| json!({}));
                if let Some(u) = unsigned.as_object_mut() {
                    u.insert("membership".to_string(), json!(m));
                }
            }
        }
    }
}

/// Room summary block (`m.heroes`, joined/invited counts) for a joined room.
async fn build_room_summary(st: &AppState, room_id: &RoomId, user_id: &str) -> Value {
    let members = st.storage.get_member_events(room_id).await;
    let mut joined = 0i64;
    let mut invited = 0i64;
    let mut heroes: Vec<String> = Vec::new();
    for m in &members {
        let membership = m.event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str).unwrap_or("");
        let sk = m.event.get("state_key").and_then(Value::as_str).unwrap_or("");
        if membership == "join" {
            joined += 1;
            if sk != user_id && heroes.len() < 5 {
                heroes.push(sk.to_string());
            }
        } else if membership == "invite" {
            invited += 1;
            if sk != user_id && heroes.len() < 5 {
                heroes.push(sk.to_string());
            }
        }
    }
    let mut s = Map::new();
    if !heroes.is_empty() {
        s.insert("m.heroes".to_string(), json!(heroes));
    }
    s.insert("m.joined_member_count".to_string(), json!(joined));
    s.insert("m.invited_member_count".to_string(), json!(invited));
    Value::Object(s)
}

/// Count notifying/highlighting events after the user's read receipt in a room.
async fn unread_counts(
    st: &AppState,
    auth: &AuthCtx,
    room_id: &RoomId,
    rules: &Value,
    display_name: Option<&str>,
) -> (i64, i64) {
    let read_event: Option<String> = st
        .storage
        .get_receipts(room_id)
        .await
        .into_iter()
        .find(|r| {
            r.user_id.as_str() == auth.user_id.as_str()
                && (r.receipt_type == "m.read" || r.receipt_type == "m.read.private")
        })
        .map(|r| r.event_id.as_str().to_string());

    let member_count = st
        .storage
        .get_member_events(room_id)
        .await
        .iter()
        .filter(|m| m.event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("join"))
        .count() as i64;
    let pl_content = st
        .storage
        .get_state_event(room_id, "m.room.power_levels", "")
        .await
        .and_then(|e| e.event.get("content").cloned());

    let page = st.storage.get_events_by_room(room_id, 1000, Some(0), Direction::Forward).await;
    let mut seen_read = read_event.is_none();
    let mut notifications = 0i64;
    let mut highlights = 0i64;
    for er in page.events {
        if !seen_read {
            if er.event_id.as_str() == read_event.as_deref().unwrap_or("") {
                seen_read = true;
            }
            continue;
        }
        let sender = er.event.get("sender").and_then(Value::as_str).unwrap_or("");
        if sender == auth.user_id.as_str() {
            continue;
        }
        let sender_pl = pl_content
            .as_ref()
            .and_then(|pl| pl.get("users").and_then(|u| u.get(sender)).and_then(Value::as_i64))
            .or_else(|| pl_content.as_ref().and_then(|pl| pl.get("users_default").and_then(Value::as_i64)))
            .unwrap_or(0);
        let result = evaluate_push_rules(
            rules,
            &EvaluationContext {
                event: &er.event,
                user_id: auth.user_id.as_str(),
                display_name,
                member_count,
                power_levels: pl_content.as_ref(),
                sender_power_level: sender_pl,
            },
        );
        if result.notify {
            notifications += 1;
        }
        if result.highlight {
            highlights += 1;
        }
    }
    (notifications, highlights)
}

/// Build the ephemeral EDU list (typing + receipts) for a room. `typing_changed`
/// forces an empty `m.typing` (a typing-stop) to be emitted.
async fn build_ephemeral(st: &AppState, room_id: &RoomId, typing_changed: bool) -> Vec<Value> {
    let mut events = Vec::new();

    let typing: Vec<String> = st
        .storage
        .get_typing_users(room_id)
        .await
        .iter()
        .map(|u| u.as_str().to_string())
        .collect();
    if !typing.is_empty() || typing_changed {
        events.push(json!({ "type": "m.typing", "content": { "user_ids": typing } }));
    }

    // m.receipt: { <event_id>: { <receipt_type>: { <user_id>: { ts, thread_id? } } } }
    let receipts = st.storage.get_receipts(room_id).await;
    if !receipts.is_empty() {
        let mut by_event: Map<String, Value> = Map::new();
        for r in receipts {
            let mut data = Map::new();
            data.insert("ts".to_string(), json!(r.ts));
            if let Some(tid) = &r.thread_id {
                data.insert("thread_id".to_string(), json!(tid));
            }
            let by_type = by_event
                .entry(r.event_id.as_str().to_string())
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .unwrap();
            let by_user = by_type
                .entry(r.receipt_type.clone())
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .unwrap();
            by_user.insert(r.user_id.as_str().to_string(), Value::Object(data));
        }
        events.push(json!({ "type": "m.receipt", "content": Value::Object(by_event) }));
    }

    events
}
