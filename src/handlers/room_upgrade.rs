//! Room upgrade — port of strix `handlers/room-upgrade.ts` (core: create the
//! replacement room with copied state + tombstone the old room). MSC4289
//! additional_creators, push-rule migration, and federation fan-out are deferred.

use std::collections::BTreeMap;

use axum::extract::{Path, State};
use axum::response::Json;
use serde_json::{json, Map, Value};

use crate::crypto::generate_room_id;
use crate::errors::{bad_json, forbidden, MatrixResult};
use crate::events::{
    build_event, check_event_auth, compute_event_id, compute_room_id_v12, get_user_power_level,
    is_room_version_12_plus, select_auth_events, BuildEventParams,
};
use crate::extract::OptionalJson;
use crate::room_ops::{require_joined_room, send_state_event, EventContext};
use crate::server::{now_ms, AppState, AuthCtx};
use crate::storage::Storage;
use crate::types::identifiers::{EventId, RoomId, UserId};
use crate::types::internal::RoomState;

/// Copy a user's room-scoped push rule from `old_room_id` to `new_room_id` in
/// their `m.push_rules` global account data (strix `copyRoomPushRule`). Idempotent.
async fn copy_room_push_rule(storage: &dyn Storage, user_id: &str, old_room_id: &str, new_room_id: &str) {
    let Some(raw) = storage.get_global_account_data(&UserId::from(user_id), "m.push_rules").await else {
        return;
    };
    let mut pr = Value::Object(raw);
    let Some(room_rules) = pr.get("global").and_then(|g| g.get("room")).and_then(Value::as_array) else {
        return;
    };
    let Some(existing) = room_rules.iter().find(|r| r.get("rule_id").and_then(Value::as_str) == Some(old_room_id)).cloned() else {
        return;
    };
    if room_rules.iter().any(|r| r.get("rule_id").and_then(Value::as_str) == Some(new_room_id)) {
        return;
    }
    let mut copied = existing;
    copied["rule_id"] = json!(new_room_id);
    if let Some(arr) = pr.get_mut("global").and_then(|g| g.get_mut("room")).and_then(Value::as_array_mut) {
        arr.push(copied);
    }
    if let Some(obj) = pr.as_object() {
        storage.set_global_account_data(&UserId::from(user_id), "m.push_rules", obj.clone()).await;
    }
}

/// Migrate room-scoped push rules from `old_room` to `new_room_id` for every
/// LOCAL joined member (strix `migrateRoomPushRules`). Shared by POST /upgrade and
/// the manual-upgrade tombstone path. TestPushRuleRoomUpgrade.
pub async fn migrate_room_push_rules(
    storage: &dyn Storage,
    server_name: &str,
    old_room: &RoomState,
    old_room_id: &str,
    new_room_id: &str,
) {
    let suffix = format!(":{server_name}");
    let members: Vec<String> = old_room
        .state_events
        .iter()
        .filter_map(|(k, ev)| {
            let uid = k.strip_prefix("m.room.member\u{1f}")?;
            let m = ev.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str)?;
            (m == "join" && uid.ends_with(&suffix)).then(|| uid.to_string())
        })
        .collect();
    for uid in members {
        copy_room_push_rule(storage, &uid, old_room_id, new_room_id).await;
    }
}

/// When a local user joins a room that replaces an earlier one (its create event
/// names a `predecessor`), copy their room-scoped push rule from the predecessor
/// (strix `copyPredecessorPushRulesOnJoin`). TestPushRuleRoomUpgrade remote-join.
pub async fn copy_predecessor_push_rules_on_join(storage: &dyn Storage, user_id: &str, new_room_id: &str) {
    let create = storage.get_state_event(&RoomId::from(new_room_id), "m.room.create", "").await;
    let old_room_id = create.and_then(|e| {
        e.event
            .get("content")
            .and_then(|c| c.get("predecessor"))
            .and_then(|p| p.get("room_id"))
            .and_then(Value::as_str)
            .map(String::from)
    });
    if let Some(old) = old_room_id {
        if old != new_room_id {
            copy_room_push_rule(storage, user_id, &old, new_room_id).await;
        }
    }
}

/// State event types copied from the old room to the replacement.
const COPIED_STATE: &[&str] = &[
    "m.room.power_levels",
    "m.room.name",
    "m.room.topic",
    "m.room.avatar",
    "m.room.join_rules",
    "m.room.history_visibility",
    "m.room.guest_access",
    "m.room.canonical_alias",
    "m.room.server_acl",
    "m.room.encryption",
];

/// `POST /_matrix/client/v3/rooms/{roomId}/upgrade`.
pub async fn upgrade(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(old_room_id): Path<String>,
    OptionalJson(body): OptionalJson,
) -> MatrixResult<Json<Value>> {
    let Some(new_version) = body.get("new_version").and_then(Value::as_str) else {
        return Err(bad_json("Missing new_version"));
    };
    let old_rid = RoomId::from(old_room_id.as_str());
    let old_room = require_joined_room(&*st.storage, &old_rid, auth.user_id.as_str()).await?;

    // Require tombstone power level.
    let tombstone_pl = old_room
        .state_events
        .get("m.room.power_levels\u{1f}")
        .and_then(|e| e.get("content"))
        .and_then(|c| c.get("events"))
        .and_then(|ev| ev.get("m.room.tombstone"))
        .and_then(Value::as_f64)
        .unwrap_or(100.0);
    if get_user_power_level(auth.user_id.as_str(), &old_room) < tombstone_pl {
        return Err(forbidden("Insufficient power level to upgrade room"));
    }

    let sn: &str = &st.server_name;
    let key = Some(st.signing_key.as_ref());
    let v12_plus = is_room_version_12_plus(Some(new_version));

    // Create content with predecessor reference.
    let mut predecessor = Map::new();
    predecessor.insert("room_id".to_string(), json!(old_room_id));
    if !v12_plus {
        let ev_id = old_room
            .state_events
            .get("m.room.create\u{1f}")
            .map(|e| compute_event_id(e, Some(&old_room.room_version)))
            .unwrap_or_default();
        predecessor.insert("event_id".to_string(), json!(ev_id));
    }
    let mut create_content = Map::new();
    create_content.insert("room_version".to_string(), json!(new_version));
    create_content.insert("predecessor".to_string(), Value::Object(predecessor));
    // MSC4289: carry the old room's additional_creators into the replacement so
    // privileged creators survive the upgrade.
    let old_create = old_room.state_events.get("m.room.create\u{1f}");
    if v12_plus {
        if let Some(ac) = old_create.and_then(|c| c.get("content")).and_then(|c| c.get("additional_creators")) {
            create_content.insert("additional_creators".to_string(), ac.clone());
        }
    }
    // The set of creators of the NEW room that must NOT appear in a v12
    // power_levels `users` map: the upgrader (the new create event's sender) plus
    // any carried-over additional_creators.
    let mut creators: std::collections::HashSet<String> = std::collections::HashSet::new();
    if v12_plus {
        creators.insert(auth.user_id.as_str().to_string());
        if let Some(arr) = create_content.get("additional_creators").and_then(Value::as_array) {
            for u in arr {
                if let Some(u) = u.as_str() {
                    creators.insert(u.to_string());
                }
            }
        }
    }

    // Replacement room id (v12 derives from the create event).
    let create_ts = now_ms();
    let new_room_id: RoomId = if v12_plus {
        let (temp, _) = build_event(BuildEventParams {
            room_id: "!placeholder:temp",
            sender: auth.user_id.as_str(),
            event_type: "m.room.create",
            content: Value::Object(create_content.clone()),
            state_key: Some(""),
            depth: 0,
            prev_events: vec![],
            auth_events: vec![],
            redacts: None,
            unsigned: None,
            server_name: sn,
            signing_key: None,
            room_version: Some(new_version),
            origin_server_ts: Some(create_ts),
        });
        let mut for_hash = temp;
        if let Some(o) = for_hash.as_object_mut() {
            o.remove("room_id");
        }
        compute_room_id_v12(&for_hash).into()
    } else {
        generate_room_id(sn).into()
    };

    st.storage
        .create_room(RoomState {
            room_id: new_room_id.clone(),
            room_version: new_version.to_string(),
            state_events: BTreeMap::new(),
            depth: 0,
            forward_extremities: vec![],
            state_event_ids: BTreeMap::new(),
        })
        .await;
    let mut ctx = EventContext::new(RoomState {
        room_id: new_room_id.clone(),
        room_version: new_version.to_string(),
        state_events: BTreeMap::new(),
        depth: 0,
        forward_extremities: vec![],
        state_event_ids: BTreeMap::new(),
    });
    let storage = &*st.storage;

    send_state_event(storage, sn, &mut ctx, auth.user_id.as_str(), "m.room.create", "", Value::Object(create_content), key, Some(create_ts)).await?;
    send_state_event(storage, sn, &mut ctx, auth.user_id.as_str(), "m.room.member", auth.user_id.as_str(), json!({ "membership": "join" }), key, None).await?;

    // Copy selected state from the old room.
    for stype in COPIED_STATE {
        let sk = format!("{stype}\u{1f}");
        if let Some(old_event) = old_room.state_events.get(&sk) {
            let mut content = old_event.get("content").cloned().unwrap_or_else(|| json!({}));
            // v12: creators hold implicit infinite power and must not be listed in
            // power_levels.users, so strip them from the copied PL event.
            if *stype == "m.room.power_levels" && !creators.is_empty() {
                if let Some(users) = content.get_mut("users").and_then(Value::as_object_mut) {
                    users.retain(|k, _| !creators.contains(k.as_str()));
                }
            }
            send_state_event(storage, sn, &mut ctx, auth.user_id.as_str(), stype, "", content, key, None).await?;
        }
    }

    // Tombstone the old room.
    let auth_events = select_auth_events("m.room.tombstone", Some(""), &old_room, auth.user_id.as_str(), None);
    let (tombstone, tombstone_id) = build_event(BuildEventParams {
        room_id: old_room_id.as_str(),
        sender: auth.user_id.as_str(),
        event_type: "m.room.tombstone",
        content: json!({ "body": "This room has been replaced", "replacement_room": new_room_id.as_str() }),
        state_key: Some(""),
        depth: old_room.depth,
        prev_events: old_room.forward_extremities.iter().map(|e| e.as_str().to_string()).collect(),
        auth_events,
        redacts: None,
        unsigned: None,
        server_name: sn,
        signing_key: key,
        room_version: Some(&old_room.room_version),
        origin_server_ts: None,
    });
    check_event_auth(&tombstone, &old_room)?;
    let tid = EventId::from(tombstone_id.as_str());
    storage.set_state_event(&old_rid, tombstone, &tid).await;
    storage.update_room_dag(&old_rid, old_room.depth + 1, vec![tid]).await;

    migrate_room_push_rules(&*st.storage, sn, &old_room, old_room_id.as_str(), new_room_id.as_str()).await;
    Ok(Json(json!({ "replacement_room": new_room_id.as_str() })))
}
