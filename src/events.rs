//! Event engine — Phase-1 subset of strix `src/events.ts`.
//!
//! This module currently implements the federation-critical, byte-exact pieces:
//! room-version redaction flags, [`redact_event`], [`compute_content_hash`],
//! [`compute_event_id`], and [`compute_room_id_v12`]. Event construction, auth
//! rules, and power-level logic arrive in Phase 2.
//!
//! Like strix, these operations work over a plain JSON object
//! ([`serde_json::Value`]) rather than a typed struct, because redaction and
//! hashing must treat the event as an untyped bag of fields to remain
//! byte-identical to what other homeservers compute.

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::canonical_json::canonical_json;
use crate::errors::{bad_json, forbidden, MatrixError};
use crate::ids::domain_of;
use crate::signing::SigningKey;
use crate::types::events::{ClientEvent, StrippedStateEvent};
use crate::types::internal::{RoomState, StateEvents};

// ---------------------------------------------------------------------------
// Room-version parsing & redaction feature flags
// (mirrors strix `parseRoomVersionNumber` / `redactionFlagsFor`)
// ---------------------------------------------------------------------------

/// Extract the numeric base version from a room-version string.
///
/// Handles plain numeric versions (`"1"`..`"12"`), numeric-prefixed (`"10-dev"`),
/// and MSC-style unstable versions of the form `org.matrix.mscXXXX.N` (the
/// trailing numeric component after the final `.`). Returns `None` when no
/// numeric version can be derived (callers then default to newest behaviour).
pub fn parse_room_version_number(room_version: Option<&str>) -> Option<i64> {
    let rv = room_version?;
    // Plain numeric ("10") or numeric-prefixed ("10-foo"): JS `parseInt` reads a
    // leading integer and ignores trailing junk.
    if let Some(n) = parse_int_prefix(rv) {
        return Some(n);
    }
    // MSC-style "org.matrix.mscXXXX.N": take the trailing numeric component.
    if let Some(dot) = rv.rfind('.') {
        let tail = &rv[dot + 1..];
        if let Ok(n) = tail.parse::<i64>() {
            return Some(n);
        }
    }
    None
}

/// Emulate JS `parseInt(s, 10)`: parse an optional sign followed by leading
/// ASCII digits, ignoring any trailing characters. Returns `None` if there is no
/// leading digit (JS would yield `NaN`).
fn parse_int_prefix(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut neg = false;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
        neg = bytes[i] == b'-';
        i += 1;
    }
    let start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == start {
        return None;
    }
    let digits = &s[start..i];
    digits.parse::<i64>().ok().map(|n| if neg { -n } else { n })
}

/// Whether a room version is v12 or later.
pub fn is_room_version_12_plus(room_version: Option<&str>) -> bool {
    matches!(parse_room_version_number(room_version), Some(n) if n >= 12)
}

/// Redaction-relevant room-version feature flags, derived from the version
/// string. Mirrors the booleans Synapse hangs off its `RoomVersion`. An
/// unknown/undefined version defaults to the newest behaviour (v11+).
#[derive(Clone, Copy, Debug)]
pub struct RedactionFlags {
    /// v11+: MSC2174/MSC2176/MSC3989 updated redaction rules.
    pub updated_redaction_rules: bool,
    /// v8+: restricted join rules keep `allow` in `m.room.join_rules`.
    pub restricted_join_rule: bool,
    /// v9+: keep `join_authorised_via_users_server` in `m.room.member`.
    pub restricted_join_rule_fix: bool,
    /// v12+: MSC4291 — create event has no `room_id` (derived from its hash).
    pub msc4291: bool,
    /// v11+: room creator implied by `m.room.create.sender` (no `creator`).
    pub implicit_room_creator: bool,
}

pub fn redaction_flags_for(room_version: Option<&str>) -> RedactionFlags {
    // Unknown version → newest (v11+) behaviour.
    let v = parse_room_version_number(room_version).unwrap_or(11);
    RedactionFlags {
        updated_redaction_rules: v >= 11,
        restricted_join_rule: v >= 8,
        restricted_join_rule_fix: v >= 9,
        msc4291: v >= 12,
        implicit_room_creator: v >= 11,
    }
}

// ---------------------------------------------------------------------------
// Redaction (mirrors strix `redactEvent`, which follows Synapse `prune_event_dict`)
// ---------------------------------------------------------------------------

const ALLOWED_TOP_LEVEL_BASE: &[&str] = &[
    "event_id",
    "sender",
    "room_id",
    "hashes",
    "signatures",
    "content",
    "type",
    "state_key",
    "depth",
    "prev_events",
    "auth_events",
    "origin_server_ts",
];

const ALLOWED_TOP_LEVEL_LEGACY: &[&str] = &["prev_state", "membership", "origin"];

/// MSC4291: a v12+ `m.room.create` event carries no `room_id` of its own — the
/// room ID *is* its reference hash. Detected from the event's own content
/// (`room_version` 12+) so hashing is self-contained.
pub fn is_v12_create_event(event: &Value) -> bool {
    if event.get("type").and_then(Value::as_str) != Some("m.room.create") {
        return false;
    }
    let rv = event
        .get("content")
        .and_then(|c| c.get("room_version"))
        .and_then(Value::as_str);
    is_room_version_12_plus(rv)
}

fn copy_fields(content: &Map<String, Value>, out: &mut Map<String, Value>, fields: &[&str]) {
    for f in fields {
        if let Some(v) = content.get(*f) {
            out.insert((*f).to_string(), v.clone());
        }
    }
}

/// Redact an event down to its federation-safe form, applying the redaction
/// rules for the given `room_version`. When `room_version` is `None` the newest
/// (v11+) rules apply. For v1–v10 rooms the caller MUST pass the version, since
/// those rooms keep extra top-level keys (`prev_state`/`membership`/`origin`)
/// and use different content rules.
pub fn redact_event(event: &Value, room_version: Option<&str>) -> Value {
    let flags = redaction_flags_for(room_version);

    let etype = event.get("type").and_then(Value::as_str).unwrap_or("");

    // MSC4291: only the v12 CREATE event has its room_id stripped.
    let strip_room_id = (flags.msc4291 && etype == "m.room.create") || is_v12_create_event(event);

    let empty = Map::new();
    let content = event
        .get("content")
        .and_then(Value::as_object)
        .unwrap_or(&empty);

    let mut new_content = Map::new();
    match etype {
        "m.room.member" => {
            copy_fields(content, &mut new_content, &["membership"]);
            if flags.restricted_join_rule_fix {
                copy_fields(
                    content,
                    &mut new_content,
                    &["join_authorised_via_users_server"],
                );
            }
            if flags.updated_redaction_rules {
                // Preserve only the `signed` subkey under third_party_invite.
                if let Some(Value::Object(tpi)) = content.get("third_party_invite") {
                    let inner = match tpi.get("signed") {
                        Some(signed) => {
                            let mut m = Map::new();
                            m.insert("signed".to_string(), signed.clone());
                            Value::Object(m)
                        }
                        None => Value::Object(Map::new()),
                    };
                    new_content.insert("third_party_invite".to_string(), inner);
                }
            }
        }
        "m.room.create" => {
            if flags.updated_redaction_rules {
                // MSC2176: create events keep their full content.
                for (k, v) in content {
                    new_content.insert(k.clone(), v.clone());
                }
            }
            if !flags.implicit_room_creator {
                copy_fields(content, &mut new_content, &["creator"]);
            }
        }
        "m.room.join_rules" => {
            copy_fields(content, &mut new_content, &["join_rule"]);
            if flags.restricted_join_rule {
                copy_fields(content, &mut new_content, &["allow"]);
            }
        }
        "m.room.power_levels" => {
            copy_fields(
                content,
                &mut new_content,
                &[
                    "users",
                    "users_default",
                    "events",
                    "events_default",
                    "state_default",
                    "ban",
                    "kick",
                    "redact",
                ],
            );
            if flags.updated_redaction_rules {
                copy_fields(content, &mut new_content, &["invite"]);
            }
        }
        "m.room.history_visibility" => {
            copy_fields(content, &mut new_content, &["history_visibility"]);
        }
        "m.room.redaction" if flags.updated_redaction_rules => {
            copy_fields(content, &mut new_content, &["redacts"]);
        }
        _ => {}
    }

    let legacy: &[&str] = if flags.updated_redaction_rules {
        &[]
    } else {
        ALLOWED_TOP_LEVEL_LEGACY
    };
    let mut redacted = Map::new();
    for key in ALLOWED_TOP_LEVEL_BASE.iter().chain(legacy.iter()) {
        if *key == "content" {
            continue; // replaced by new_content below
        }
        if *key == "room_id" && strip_room_id {
            continue;
        }
        if let Some(v) = event.get(*key) {
            redacted.insert((*key).to_string(), v.clone());
        }
    }
    redacted.insert("content".to_string(), Value::Object(new_content));

    Value::Object(redacted)
}

// ---------------------------------------------------------------------------
// Hashing & event IDs (mirrors strix `computeContentHash` / `computeEventId`)
// ---------------------------------------------------------------------------

/// Content hash (`hashes.sha256`): unpadded **standard** base64 (`+/`) of the
/// SHA-256 of the canonical JSON of the event minus `unsigned`/`signatures`/
/// `hashes`/`event_id` (and `room_id` for v12 create events).
pub fn compute_content_hash(event: &Value) -> String {
    let mut copy = event.clone();
    if let Value::Object(m) = &mut copy {
        m.remove("unsigned");
        m.remove("signatures");
        m.remove("hashes");
        m.remove("event_id");
        if is_v12_create_event(event) {
            m.remove("room_id");
        }
    }
    let digest = Sha256::digest(canonical_json(&copy).as_bytes());
    STANDARD_NO_PAD.encode(digest)
}

/// Event ID: `$` + unpadded **base64url** of the SHA-256 of the *redacted* event
/// (with its computed content hash), using the room version's redaction rules.
pub fn compute_event_id(event: &Value, room_version: Option<&str>) -> String {
    let content_hash = compute_content_hash(event);
    let mut with_hash = event.clone();
    if let Value::Object(m) = &mut with_hash {
        let mut h = Map::new();
        h.insert("sha256".to_string(), Value::String(content_hash));
        m.insert("hashes".to_string(), Value::Object(h));
    }

    let redacted = redact_event(&with_hash, room_version);
    let mut for_ref = redacted;
    if let Value::Object(m) = &mut for_ref {
        m.remove("unsigned");
        m.remove("signatures");
    }

    let digest = Sha256::digest(canonical_json(&for_ref).as_bytes());
    format!("${}", URL_SAFE_NO_PAD.encode(digest))
}

/// Compute a room ID for room version 12+ from the create event: the create
/// event's event ID with the `!` sigil instead of `$`.
pub fn compute_room_id_v12(create_event: &Value) -> String {
    let event_id = compute_event_id(create_event, Some("12"));
    format!("!{}", &event_id[1..])
}

// ===========================================================================
// Constants, state-key packing, and event accessors
// ===========================================================================

/// MSC4289: power level assigned to room creators. Matches Synapse's
/// `CREATOR_POWER_LEVEL = 2**53`, strictly greater than the largest value
/// representable in canonical JSON, so creators outrank every settable level.
pub const CREATOR_POWER_LEVEL: f64 = 9_007_199_254_740_992.0; // 2^53

/// Largest/smallest integers representable in canonical JSON (`±(2^53 - 1)`).
pub const CANONICALJSON_MAX_INT: i64 = 9_007_199_254_740_991;
pub const CANONICALJSON_MIN_INT: i64 = -9_007_199_254_740_991;

/// Separator packing identifiers into one composite string key (ASCII Unit
/// Separator, U+001F). Keep pack/unpack symmetric.
pub const KEY_SEP: char = '\u{1f}';

const MEMBER_KEY_PREFIX: &str = "m.room.member\u{1f}";

/// Build a state-map key: `` `${type}\x1f${state_key}` ``.
pub fn make_state_key(event_type: &str, state_key: &str) -> String {
    format!("{event_type}{KEY_SEP}{state_key}")
}

fn room_rv(room: &RoomState) -> Option<&str> {
    Some(room.room_version.as_str())
}

// --- Event field accessors (events are raw JSON, like strix) ---------------

/// `event.type`, defaulting to `""`.
pub fn ev_type(e: &Value) -> &str {
    e.get("type").and_then(Value::as_str).unwrap_or("")
}

/// `event.sender`, defaulting to `""`.
pub fn ev_sender(e: &Value) -> &str {
    e.get("sender").and_then(Value::as_str).unwrap_or("")
}

/// `event.state_key` (`None` when the event is not a state event).
pub fn ev_state_key(e: &Value) -> Option<&str> {
    e.get("state_key").and_then(Value::as_str)
}

/// Whether the event has a `state_key` at all (strix `state_key !== undefined`).
pub fn ev_is_state(e: &Value) -> bool {
    e.get("state_key").is_some()
}

/// `event.content` as an object (`None` if absent or not an object).
pub fn ev_content(e: &Value) -> Option<&Map<String, Value>> {
    e.get("content").and_then(Value::as_object)
}

/// `event.content[field]`.
pub fn content_get<'a>(e: &'a Value, field: &str) -> Option<&'a Value> {
    ev_content(e).and_then(|c| c.get(field))
}

/// `event.auth_events` as a list of ID strings.
pub fn ev_auth_events(e: &Value) -> Vec<&str> {
    e.get("auth_events")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// `event.origin_server_ts`, defaulting to 0.
pub fn ev_origin_server_ts(e: &Value) -> i64 {
    e.get("origin_server_ts")
        .and_then(Value::as_i64)
        .unwrap_or(0)
}

/// The `membership` field of an `m.room.member` event's content.
pub fn membership_of(e: &Value) -> Option<&str> {
    content_get(e, "membership").and_then(Value::as_str)
}

/// `getMembership`: the membership of `user_id` in the room, or `None`.
pub fn get_membership<'a>(room: &'a RoomState, user_id: &str) -> Option<&'a str> {
    room.state_events
        .get(&make_state_key("m.room.member", user_id))
        .and_then(membership_of)
}

// ===========================================================================
// Power levels & creators
// ===========================================================================

/// The `m.room.power_levels` content map, if a PL event exists.
fn pl_content(room: &RoomState) -> Option<&Map<String, Value>> {
    room.state_events
        .get(&make_state_key("m.room.power_levels", ""))
        .and_then(ev_content)
}

/// Read an integer-ish power-level field with a default (numbers are read as
/// f64 to match JS number semantics).
fn pl_num(pl: Option<&Map<String, Value>>, key: &str, default: f64) -> f64 {
    pl.and_then(|m| m.get(key))
        .and_then(Value::as_f64)
        .unwrap_or(default)
}

/// Whether `user_id` is a room creator (sender of the create event or listed in
/// `additional_creators`).
pub fn is_room_creator(user_id: &str, room: &RoomState) -> bool {
    let Some(create) = room.state_events.get(&make_state_key("m.room.create", "")) else {
        return false;
    };
    if ev_sender(create) == user_id {
        return true;
    }
    content_get(create, "additional_creators")
        .and_then(Value::as_array)
        .map(|a| a.iter().any(|v| v.as_str() == Some(user_id)))
        .unwrap_or(false)
}

/// The effective power level of `user_id`.
pub fn get_user_power_level(user_id: &str, room: &RoomState) -> f64 {
    // v12+: room creators hold an implicit infinite power level (MSC4289).
    if is_room_version_12_plus(room_rv(room)) && is_room_creator(user_id, room) {
        return CREATOR_POWER_LEVEL;
    }

    match room
        .state_events
        .get(&make_state_key("m.room.power_levels", ""))
    {
        None => {
            // Before power_levels is set, the room creator has implicit PL 100.
            if let Some(create) = room.state_events.get(&make_state_key("m.room.create", "")) {
                if ev_sender(create) == user_id {
                    return 100.0;
                }
            }
            0.0
        }
        Some(pl_event) => {
            let content = ev_content(pl_event);
            if let Some(level) = content
                .and_then(|c| c.get("users"))
                .and_then(Value::as_object)
                .and_then(|users| users.get(user_id))
                .and_then(Value::as_f64)
            {
                return level;
            }
            content
                .and_then(|c| c.get("users_default"))
                .and_then(Value::as_f64)
                .unwrap_or(0.0)
        }
    }
}

/// The power level required to send an event of `event_type`.
fn get_event_power_level(event_type: &str, is_state: bool, room: &RoomState) -> f64 {
    let pl = pl_content(room);
    if let Some(level) = pl
        .and_then(|c| c.get("events"))
        .and_then(Value::as_object)
        .and_then(|events| events.get(event_type))
        .and_then(Value::as_f64)
    {
        return level;
    }
    // v12+: m.room.tombstone defaults to 150.
    if event_type == "m.room.tombstone" && is_room_version_12_plus(room_rv(room)) {
        return 150.0;
    }
    if is_state {
        pl_num(pl, "state_default", 50.0)
    } else {
        pl_num(pl, "events_default", 0.0)
    }
}

/// A room's join rule, defaulting to `"invite"`.
pub fn get_join_rule(room: &RoomState) -> &str {
    room.state_events
        .get(&make_state_key("m.room.join_rules", ""))
        .and_then(|e| content_get(e, "join_rule"))
        .and_then(Value::as_str)
        .unwrap_or("invite")
}

/// Find the local user best able to authorise a restricted-room join (MSC3083):
/// the joined local user with the highest power level meeting the invite
/// threshold, ties broken by smallest user ID.
pub fn find_authorising_local_user(room: &RoomState, local_server_name: &str) -> Option<String> {
    let invite_pl = pl_num(pl_content(room), "invite", 0.0);

    let mut best: Option<String> = None;
    let mut best_pl = f64::NEG_INFINITY;

    for (member_id, membership, _) in iter_members(&room.state_events) {
        if membership != Some("join") {
            continue;
        }
        if domain_of(member_id) != local_server_name {
            continue;
        }
        let member_pl = get_user_power_level(member_id, room);
        if member_pl < invite_pl {
            continue;
        }
        let better = member_pl > best_pl
            || (member_pl == best_pl && best.as_deref().map(|b| member_id < b).unwrap_or(true));
        if better {
            best = Some(member_id.to_string());
            best_pl = member_pl;
        }
    }
    best
}

// ===========================================================================
// Membership & power-level validation auth
// ===========================================================================

fn check_membership_auth(event: &Value, room: &RoomState) -> Result<(), MatrixError> {
    let target_user_id = ev_state_key(event).unwrap_or("");
    let membership = membership_of(event).unwrap_or("");
    let sender = ev_sender(event);
    let sender_membership = get_membership(room, sender);
    let target_membership = get_membership(room, target_user_id);
    let pl = pl_content(room);
    let sender_pl = get_user_power_level(sender, room);

    match membership {
        "join" => {
            if sender != target_user_id {
                return Err(forbidden("Cannot force another user to join"));
            }
            if sender_membership == Some("ban") {
                return Err(forbidden("User is banned from the room"));
            }
            if sender_membership == Some("join") || sender_membership == Some("invite") {
                return Ok(());
            }
            if let Some(create) = room.state_events.get(&make_state_key("m.room.create", "")) {
                if ev_sender(create) == sender && sender_membership.is_none() {
                    return Ok(());
                }
            }
            let join_rule = get_join_rule(room);
            if join_rule == "public" {
                return Ok(());
            }
            if join_rule == "restricted" || join_rule == "knock_restricted" {
                if let Some(join_auth) =
                    content_get(event, "join_authorised_via_users_server").and_then(Value::as_str)
                {
                    if get_membership(room, join_auth) != Some("join") {
                        return Err(forbidden("Authorizing user is not a member of the room"));
                    }
                    return Ok(());
                }
                if sender_membership == Some("knock") {
                    return Ok(());
                }
            }
            Err(forbidden("Room is invite-only"))
        }

        "invite" => {
            if sender_membership != Some("join") {
                return Err(forbidden("Sender is not in the room"));
            }
            if target_membership == Some("join") {
                return Err(forbidden("Cannot invite user who is already in the room"));
            }
            if target_membership == Some("ban") {
                return Err(forbidden("Cannot invite banned user"));
            }
            if sender == target_user_id {
                return Err(forbidden("Cannot invite yourself"));
            }
            let invite_pl = pl_num(pl, "invite", 0.0);
            if sender_pl < invite_pl {
                return Err(forbidden(format!(
                    "Insufficient power level to invite: need {invite_pl}, have {sender_pl}"
                )));
            }
            Ok(())
        }

        "leave" => {
            if sender == target_user_id {
                if matches!(
                    sender_membership,
                    Some("join") | Some("invite") | Some("knock")
                ) {
                    return Ok(());
                }
                return Err(forbidden("Cannot leave a room you are not in"));
            }
            if sender_membership != Some("join") {
                return Err(forbidden("Sender is not in the room"));
            }
            let target_pl = get_user_power_level(target_user_id, room);
            if target_membership == Some("ban") {
                let ban_pl = pl_num(pl, "ban", 50.0);
                if sender_pl < ban_pl {
                    return Err(forbidden(format!(
                        "You cannot unban user {target_user_id}."
                    )));
                }
                return Ok(());
            }
            let kick_pl = pl_num(pl, "kick", 50.0);
            if sender_pl < kick_pl || sender_pl <= target_pl {
                return Err(forbidden(format!("You cannot kick user {target_user_id}.")));
            }
            Ok(())
        }

        "ban" => {
            if sender_membership != Some("join") {
                return Err(forbidden("Sender is not in the room"));
            }
            let ban_pl = pl_num(pl, "ban", 50.0);
            if sender_pl < ban_pl {
                return Err(forbidden(format!(
                    "Insufficient power level to ban: need {ban_pl}, have {sender_pl}"
                )));
            }
            if target_user_id != sender {
                let target_pl = get_user_power_level(target_user_id, room);
                if sender_pl <= target_pl {
                    return Err(forbidden(
                        "Cannot ban user with equal or higher power level",
                    ));
                }
            }
            Ok(())
        }

        "knock" => {
            if sender != target_user_id {
                return Err(forbidden("Cannot knock on behalf of another user"));
            }
            if sender_membership == Some("ban") {
                return Err(forbidden("User is banned from the room"));
            }
            if sender_membership == Some("join") {
                return Err(forbidden("User is already in the room"));
            }
            if sender_membership == Some("invite") {
                return Err(forbidden("User is already invited"));
            }
            let join_rule = get_join_rule(room);
            if join_rule != "knock" && join_rule != "knock_restricted" {
                return Err(forbidden("Room join rules do not allow knocking"));
            }
            Ok(())
        }

        other => Err(forbidden(format!("Unknown membership: {other}"))),
    }
}

/// Validate a single power-level value: in room version 10+ it must be an
/// integer within the canonical-JSON range. Non-numbers are ignored.
fn validate_power_level_value(label: &str, val: &Value) -> Result<(), MatrixError> {
    if !val.is_number() {
        return Ok(());
    }
    let n = val.as_f64().unwrap_or(f64::NAN);
    if !n.is_finite() || n.fract() != 0.0 {
        return Err(bad_json(format!(
            "Power level value for {label} must be an integer in room version 10+"
        )));
    }
    if n > CANONICALJSON_MAX_INT as f64 || n < CANONICALJSON_MIN_INT as f64 {
        return Err(bad_json(format!(
            "Power level value for {label} is out of range for canonical JSON"
        )));
    }
    Ok(())
}

fn validate_integer_power_levels(event: &Value) -> Result<(), MatrixError> {
    let Some(content) = ev_content(event) else {
        return Ok(());
    };
    for field in [
        "ban",
        "events_default",
        "invite",
        "kick",
        "redact",
        "state_default",
        "users_default",
    ] {
        if let Some(v) = content.get(field) {
            validate_power_level_value(&format!("'{field}'"), v)?;
        }
    }
    for map_field in ["events", "users", "notifications"] {
        if let Some(map) = content.get(map_field).and_then(Value::as_object) {
            for (key, val) in map {
                validate_power_level_value(&format!("{map_field} entry '{key}'"), val)?;
            }
        }
    }
    Ok(())
}

// ===========================================================================
// Event authorization
// ===========================================================================

/// Authorize an event against the room's current state. Returns `Err` (the
/// strix "throw") when the event is not allowed.
pub fn check_event_auth(event: &Value, room: &RoomState) -> Result<(), MatrixError> {
    let is_v12_plus = is_room_version_12_plus(room_rv(room));
    let etype = ev_type(event);

    if etype == "m.room.create" {
        if !room.state_events.is_empty() {
            return Err(bad_json(
                "m.room.create can only be the first event in a room",
            ));
        }
        if is_v12_plus && !ev_auth_events(event).is_empty() {
            return Err(forbidden(
                "m.room.create must not have auth_events in room version 12+",
            ));
        }
        if is_v12_plus {
            if let Some(additional_creators) = content_get(event, "additional_creators") {
                validate_additional_creators(additional_creators)?;
            }
        }
        return Ok(());
    }

    // v12+: m.room.create must NOT be referenced in auth_events.
    if is_v12_plus {
        if let Some(create) = room.state_events.get(&make_state_key("m.room.create", "")) {
            let create_event_id = compute_event_id(create, room_rv(room));
            if ev_auth_events(event)
                .iter()
                .any(|id| *id == create_event_id)
            {
                return Err(forbidden(
                    "m.room.create must not be referenced in auth_events in room version 12+",
                ));
            }
        }
    }

    if etype == "m.room.member" {
        return check_membership_auth(event, room);
    }

    let sender = ev_sender(event);
    if get_membership(room, sender) != Some("join") {
        return Err(forbidden("Sender is not in the room"));
    }

    if etype == "m.room.power_levels" {
        let version_num = parse_room_version_number(room_rv(room));
        if matches!(version_num, Some(n) if n >= 10) {
            validate_integer_power_levels(event)?;
        }
        // MSC4289: creators must not be listed in content.users in v12+.
        if is_v12_plus {
            if let Some(users) = content_get(event, "users").and_then(Value::as_object) {
                if let Some(create) = room.state_events.get(&make_state_key("m.room.create", "")) {
                    let creator = ev_sender(create);
                    if users.contains_key(creator) {
                        return Err(bad_json(format!(
                            "Creator user {creator} must not appear in content.users"
                        )));
                    }
                    if let Some(additional) =
                        content_get(create, "additional_creators").and_then(Value::as_array)
                    {
                        for uid in additional.iter().filter_map(Value::as_str) {
                            if users.contains_key(uid) {
                                return Err(bad_json(
                                    "Additional creators users must not appear in content.users",
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    let is_state = ev_is_state(event);
    let required_pl = get_event_power_level(etype, is_state, room);
    let sender_pl = get_user_power_level(sender, room);
    if sender_pl < required_pl {
        return Err(forbidden(format!(
            "Insufficient power level: need {required_pl}, have {sender_pl}"
        )));
    }

    // MSC3757 owned state events.
    if let Some(state_key) = ev_state_key(event) {
        if state_key.starts_with('@') && state_key != sender {
            if is_msc3757_enabled(room_rv(room)) {
                let colon_idx = state_key[1..].find(':').map(|i| i + 1);
                let Some(colon_idx) = colon_idx else {
                    return Err(bad_json(
                        "State key neither equals a valid user ID, nor starts with one plus an underscore",
                    ));
                };
                let suffix_idx = state_key[colon_idx + 1..]
                    .find('_')
                    .map(|i| colon_idx + 1 + i);
                let state_key_user_id = match suffix_idx {
                    Some(i) => &state_key[..i],
                    None => state_key,
                };
                if !is_valid_user_id(state_key_user_id) {
                    return Err(bad_json(
                        "State key neither equals a valid user ID, nor starts with one plus an underscore",
                    ));
                }
                if state_key_user_id == sender
                    || sender_pl > get_user_power_level(state_key_user_id, room)
                {
                    return Ok(());
                }
            }
            return Err(forbidden("You are not allowed to set others' state"));
        }
    }

    Ok(())
}

// ===========================================================================
// MSC3757 / MSC4289 validators
// ===========================================================================

fn is_msc3757_enabled(room_version: Option<&str>) -> bool {
    room_version
        .map(|v| v.starts_with("org.matrix.msc3757."))
        .unwrap_or(false)
}

/// Validate a syntactically-correct host: `^[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*$`.
fn valid_host(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Validate that `s` is a syntactically valid user ID (`@localpart:server`),
/// matching the subset of Synapse's `UserID.is_valid` used by MSC3757.
fn is_valid_user_id(s: &str) -> bool {
    if !s.starts_with('@') {
        return false;
    }
    let Some(colon) = s.find(':') else {
        return false;
    };
    let domain = &s[colon + 1..];
    let host = match domain.rfind(':') {
        Some(i) => &domain[..i],
        None => domain,
    };
    if host.ends_with(']') {
        return true; // IPv6 literal
    }
    valid_host(host)
}

/// MSC4289 `check_valid_additional_creators`: an array of valid user-ID strings,
/// each at most 255 bytes. Mismatches raise `M_BAD_JSON`.
pub fn validate_additional_creators(value: &Value) -> Result<(), MatrixError> {
    let Some(arr) = value.as_array() else {
        return Err(bad_json("additional_creators must be an array"));
    };
    for entry in arr {
        let Some(s) = entry.as_str() else {
            return Err(bad_json("entry in additional_creators is not a string"));
        };
        if !is_valid_user_id(s) {
            return Err(bad_json(
                "entry in additional_creators is not a valid user ID",
            ));
        }
        // JS `.length` counts UTF-16 units; `Buffer.byteLength` counts UTF-8.
        if s.encode_utf16().count() > 255 || s.len() > 255 {
            return Err(bad_json("entry in additional_creators too long"));
        }
    }
    Ok(())
}

// ===========================================================================
// Event construction
// ===========================================================================

/// Current Unix time in milliseconds (strix `Date.now()`).
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Parameters for [`build_event`].
pub struct BuildEventParams<'a> {
    pub room_id: &'a str,
    pub sender: &'a str,
    pub event_type: &'a str,
    /// The event content (a JSON object).
    pub content: Value,
    pub state_key: Option<&'a str>,
    pub depth: i64,
    pub prev_events: Vec<String>,
    pub auth_events: Vec<String>,
    pub redacts: Option<&'a str>,
    pub unsigned: Option<Value>,
    pub server_name: &'a str,
    pub signing_key: Option<&'a SigningKey>,
    pub room_version: Option<&'a str>,
    /// Explicit `origin_server_ts`; defaults to now. Pass this for v12 create
    /// events so the stored create event's ID matches the derived room ID.
    pub origin_server_ts: Option<i64>,
}

/// Primary event factory: assembles the PDU, computes its content hash and event
/// ID, and signs it when a key is supplied. Returns `(event, event_id)`.
pub fn build_event(params: BuildEventParams<'_>) -> (Value, String) {
    let mut event = Map::new();
    event.insert(
        "auth_events".to_string(),
        Value::Array(params.auth_events.into_iter().map(Value::String).collect()),
    );
    event.insert("content".to_string(), params.content);
    event.insert("depth".to_string(), Value::from(params.depth));
    event.insert("hashes".to_string(), json!({ "sha256": "" }));
    event.insert(
        "origin_server_ts".to_string(),
        Value::from(params.origin_server_ts.unwrap_or_else(now_ms)),
    );
    event.insert(
        "prev_events".to_string(),
        Value::Array(params.prev_events.into_iter().map(Value::String).collect()),
    );
    event.insert(
        "room_id".to_string(),
        Value::String(params.room_id.to_string()),
    );
    event.insert(
        "sender".to_string(),
        Value::String(params.sender.to_string()),
    );
    let mut sig_map = Map::new();
    sig_map.insert(params.server_name.to_string(), json!({}));
    event.insert("signatures".to_string(), Value::Object(sig_map));
    event.insert(
        "type".to_string(),
        Value::String(params.event_type.to_string()),
    );
    if let Some(sk) = params.state_key {
        event.insert("state_key".to_string(), Value::String(sk.to_string()));
    }
    if let Some(r) = params.redacts {
        event.insert("redacts".to_string(), Value::String(r.to_string()));
    }
    if let Some(u) = params.unsigned {
        event.insert("unsigned".to_string(), u);
    }

    let mut value = Value::Object(event);
    // Content hash first, then derive the event ID and signature from a single
    // shared redacted-canonical form (see `finalize_event_id_and_sign`). This
    // replaces the old `compute_content_hash` + `compute_event_id` + `sign_event`
    // sequence, which recomputed the content hash 3× and canonicalized 5×.
    let content_hash = compute_content_hash(&value);
    value
        .as_object_mut()
        .unwrap()
        .insert("hashes".to_string(), json!({ "sha256": content_hash }));

    let event_id = crate::signing::finalize_event_id_and_sign(
        &mut value,
        params.server_name,
        params.signing_key,
        params.room_version,
    );

    (value, event_id)
}

/// The event ID of the room's state event for `(type, state_key)`, if present.
/// Uses the memoized `state_event_ids` cache (populated at write time) and only
/// recomputes on a cache miss — computing an event ID is expensive and
/// `select_auth_events` needs several per send.
fn get_state_event_id(room: &RoomState, event_type: &str, state_key: &str) -> Option<String> {
    let key = make_state_key(event_type, state_key);
    if let Some(id) = room.state_event_ids.get(&key) {
        return Some(id.clone());
    }
    room.state_events
        .get(&key)
        .map(|e| compute_event_id(e, room_rv(room)))
}

/// Select the auth events for a new event per the spec (always create +
/// power_levels + sender member; membership adds join_rules, target member, and
/// the restricted-join authoriser).
pub fn select_auth_events(
    event_type: &str,
    state_key: Option<&str>,
    room: &RoomState,
    sender: &str,
    content: Option<&Map<String, Value>>,
) -> Vec<String> {
    let mut auth_events: Vec<String> = Vec::new();

    // In v12+, m.room.create is NOT included in auth_events.
    if !is_room_version_12_plus(room_rv(room)) {
        if let Some(id) = get_state_event_id(room, "m.room.create", "") {
            auth_events.push(id);
        }
    }
    if let Some(id) = get_state_event_id(room, "m.room.power_levels", "") {
        auth_events.push(id);
    }
    if let Some(id) = get_state_event_id(room, "m.room.member", sender) {
        auth_events.push(id);
    }

    if event_type == "m.room.member" {
        if let Some(state_key) = state_key.filter(|s| !s.is_empty()) {
            if let Some(id) = get_state_event_id(room, "m.room.join_rules", "") {
                auth_events.push(id);
            }
            if state_key != sender {
                if let Some(id) = get_state_event_id(room, "m.room.member", state_key) {
                    auth_events.push(id);
                }
            }
            // MSC3083 restricted-room joins.
            if content
                .and_then(|c| c.get("membership"))
                .and_then(Value::as_str)
                == Some("join")
            {
                if let Some(authorising_user) = content
                    .and_then(|c| c.get("join_authorised_via_users_server"))
                    .and_then(Value::as_str)
                {
                    if authorising_user != state_key {
                        if let Some(id) =
                            get_state_event_id(room, "m.room.member", authorising_user)
                        {
                            auth_events.push(id);
                        }
                    }
                }
            }
        }
    }

    auth_events
}

// ===========================================================================
// State / membership projections
// ===========================================================================

/// Iterate the `m.room.member` entries of a room's state, yielding
/// `(user_id, membership, event)`.
pub fn iter_members(state: &StateEvents) -> impl Iterator<Item = (&str, Option<&str>, &Value)> {
    state.iter().filter_map(|(k, v)| {
        k.strip_prefix(MEMBER_KEY_PREFIX)
            .map(|user_id| (user_id, membership_of(v), v))
    })
}

/// Whether `server` has at least one member of the given membership in `state`.
pub fn server_has_member(state: &StateEvents, server: &str, membership: &str) -> bool {
    iter_members(state).any(|(user_id, m, _)| m == Some(membership) && domain_of(user_id) == server)
}

/// Number of joined members in a state map.
pub fn count_joined_members(state: &StateEvents) -> usize {
    iter_members(state)
        .filter(|(_, m, _)| *m == Some("join"))
        .count()
}

/// Whether the room is world-readable.
pub fn is_world_readable(room: &RoomState) -> bool {
    room.state_events
        .get(&make_state_key("m.room.history_visibility", ""))
        .and_then(|e| content_get(e, "history_visibility"))
        .and_then(Value::as_str)
        == Some("world_readable")
}

/// Read one field from an event's content, tolerating a missing event.
pub fn content_field<'a>(event: Option<&'a Value>, field: &str) -> Option<&'a Value> {
    event.and_then(|e| content_get(e, field))
}

/// Project an event down to the stripped-state shape used in invites/summaries.
pub fn to_stripped(event: &Value, fallback_state_key: &str) -> StrippedStateEvent {
    StrippedStateEvent {
        content: ev_content(event).cloned().unwrap_or_default(),
        sender: ev_sender(event).into(),
        state_key: ev_state_key(event)
            .unwrap_or(fallback_state_key)
            .to_string(),
        event_type: ev_type(event).to_string(),
    }
}

/// State event types included in invite/knock stripped state (strix
/// `INVITE_STATE_TYPES`).
pub const INVITE_STATE_TYPES: &[&str] = &[
    "m.room.create",
    "m.room.join_rules",
    "m.room.canonical_alias",
    "m.room.avatar",
    "m.room.name",
    "m.room.encryption",
    "m.room.member",
];

/// Project an event to stripped state for invites (strix `eventToStrippedState`).
///
/// MSC4311: the `m.room.create` event is special-cased into stripped state in
/// FULL (not reduced to the minimal 4 fields), so invitees can read the room
/// version / creators (incl. `origin_server_ts`). Returns raw [`Value`] so those
/// extra fields survive — a typed 4-field struct would drop them.
pub fn event_to_stripped_state(event: &Value) -> Value {
    let etype = ev_type(event);
    let state_key = ev_state_key(event).unwrap_or("");
    if etype == "m.room.create" && state_key.is_empty() {
        let mut obj = event.as_object().cloned().unwrap_or_default();
        obj.insert(
            "state_key".to_string(),
            Value::String(state_key.to_string()),
        );
        return Value::Object(obj);
    }
    let mut obj = Map::new();
    obj.insert(
        "content".to_string(),
        event
            .get("content")
            .cloned()
            .unwrap_or(Value::Object(Map::new())),
    );
    obj.insert(
        "sender".to_string(),
        Value::String(ev_sender(event).to_string()),
    );
    obj.insert(
        "state_key".to_string(),
        Value::String(state_key.to_string()),
    );
    obj.insert("type".to_string(), Value::String(etype.to_string()));
    Value::Object(obj)
}

/// Convert a stored PDU to the client-facing event shape.
pub fn pdu_to_client_event(pdu: &Value, event_id: &str) -> ClientEvent {
    ClientEvent {
        content: ev_content(pdu).cloned().unwrap_or_default(),
        event_id: event_id.into(),
        origin_server_ts: ev_origin_server_ts(pdu),
        room_id: pdu.get("room_id").and_then(Value::as_str).map(Into::into),
        sender: ev_sender(pdu).into(),
        state_key: ev_state_key(pdu).map(str::to_string),
        event_type: ev_type(pdu).to_string(),
        unsigned: pdu.get("unsigned").cloned(),
        redacts: pdu.get("redacts").and_then(Value::as_str).map(Into::into),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_version_parsing() {
        assert_eq!(parse_room_version_number(Some("10")), Some(10));
        assert_eq!(parse_room_version_number(Some("10-dev")), Some(10));
        assert_eq!(
            parse_room_version_number(Some("org.matrix.msc3757.10")),
            Some(10)
        );
        assert_eq!(parse_room_version_number(Some("v")), None);
        assert_eq!(parse_room_version_number(None), None);
        assert!(is_room_version_12_plus(Some("12")));
        assert!(!is_room_version_12_plus(Some("11")));
        assert!(is_room_version_12_plus(Some("org.matrix.msc4291.12")));
    }
}
