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
use crate::types::identifiers::{EventId, RoomId};
use crate::types::internal::RoomState;

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
            let content = old_event.get("content").cloned().unwrap_or_else(|| json!({}));
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

    Ok(Json(json!({ "replacement_room": new_room_id.as_str() })))
}
