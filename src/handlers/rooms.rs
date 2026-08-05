//! Room lifecycle handlers — port of strix `handlers/rooms.ts` (the local,
//! non-federated path). `createRoom` and `joined_rooms` for now; join/leave/
//! invite/kick/ban and the federated paths follow.

use std::collections::BTreeMap;

use axum::extract::State;
use axum::response::Json;
use serde_json::{json, Map, Value};

use crate::crypto::generate_room_id;
use crate::errors::{bad_json, MatrixError, MatrixResult};
use crate::events::{
    build_event, compute_room_id_v12, is_room_version_12_plus, parse_room_version_number,
    validate_additional_creators, BuildEventParams,
};
use crate::room_ops::{send_state_event, EventContext};
use crate::server::{now_ms, AppState, AuthCtx};
use crate::types::identifiers::{RoomAlias, RoomId, ServerName};
use crate::types::internal::RoomState;

const KNOWN_ROOM_VERSIONS: &[&str] = &[
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "10",
    "11",
    "12",
    "org.matrix.msc3757.10",
];

/// `POST /_matrix/client/v3/createRoom`.
pub async fn create_room(
    State(st): State<AppState>,
    auth: AuthCtx,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let user_id = auth.user_id.as_str();
    let sn: &str = &st.server_name;
    let key = Some(st.signing_key.as_ref());

    if body.get("room_version").is_some_and(|v| !v.is_string()) {
        return Err(bad_json("room_version must be a string"));
    }
    let room_version = body
        .get("room_version")
        .and_then(Value::as_str)
        .unwrap_or("10")
        .to_string();
    if body.get("room_version").is_some() && !KNOWN_ROOM_VERSIONS.contains(&room_version.as_str()) {
        return Err(MatrixError::new(
            "M_UNSUPPORTED_ROOM_VERSION",
            format!("Unsupported room version: {room_version}"),
            400,
        ));
    }
    let v12_plus = is_room_version_12_plus(Some(&room_version));

    let visibility = body.get("visibility").and_then(Value::as_str);
    if let Some(v) = visibility {
        if v != "public" && v != "private" {
            return Err(bad_json("visibility must be 'public' or 'private'"));
        }
    }
    if let Some(alias_name) = body.get("room_alias_name").and_then(Value::as_str) {
        if alias_name.is_empty() || !alias_name.chars().all(is_alias_char) {
            return Err(bad_json("room_alias_name contains invalid characters"));
        }
    }

    let create_ts = now_ms();
    let preset = body
        .get("preset")
        .and_then(Value::as_str)
        .map(String::from)
        .unwrap_or_else(|| {
            if visibility == Some("public") {
                "public_chat".to_string()
            } else {
                "private_chat".to_string()
            }
        });

    // create event content
    let mut create_content = Map::new();
    if let Some(cc) = body.get("creation_content").and_then(Value::as_object) {
        for (k, v) in cc {
            if k != "room_version" && k != "creator" {
                create_content.insert(k.clone(), v.clone());
            }
        }
    }
    create_content.insert("room_version".to_string(), json!(room_version));
    if matches!(parse_room_version_number(Some(&room_version)), Some(n) if n < 11) {
        create_content.insert("creator".to_string(), json!(user_id));
    }
    if v12_plus {
        if let Some(ac) = create_content.get("additional_creators") {
            validate_additional_creators(ac)?;
        }
        // MSC4289: in v12+ the `trusted_private_chat` preset makes invited users
        // room creators (merged into create.content.additional_creators) rather
        // than PL100 admins.
        if preset == "trusted_private_chat" {
            if let Some(invites) = body.get("invite").and_then(Value::as_array) {
                let mut merged: Vec<Value> = create_content
                    .get("additional_creators")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for inv in invites {
                    let Some(invitee) = inv.as_str() else { continue };
                    let dup = invitee == user_id
                        || merged.iter().any(|m| m.as_str() == Some(invitee));
                    if !dup {
                        merged.push(json!(invitee));
                    }
                }
                if !merged.is_empty() {
                    create_content.insert("additional_creators".to_string(), json!(merged));
                }
            }
        }
    }

    // room id
    let room_id: RoomId = if v12_plus {
        let (temp, _) = build_event(BuildEventParams {
            room_id: "!placeholder:temp",
            sender: user_id,
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
            room_version: Some(&room_version),
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
            room_id: room_id.clone(),
            room_version: room_version.clone(),
            state_events: BTreeMap::new(),
            depth: 0,
            forward_extremities: vec![],
            state_event_ids: BTreeMap::new(),
        })
        .await;

    let mut ctx = EventContext::new(RoomState {
        room_id: room_id.clone(),
        room_version: room_version.clone(),
        state_events: BTreeMap::new(),
        depth: 0,
        forward_extremities: vec![],
        state_event_ids: BTreeMap::new(),
    });
    let storage = &*st.storage;

    send_state_event(
        storage,
        sn,
        &mut ctx,
        user_id,
        "m.room.create",
        "",
        Value::Object(create_content),
        key,
        Some(create_ts),
    )
    .await?;
    send_state_event(
        storage,
        sn,
        &mut ctx,
        user_id,
        "m.room.member",
        user_id,
        json!({ "membership": "join" }),
        key,
        None,
    )
    .await?;

    let pl = power_levels_content(v12_plus, user_id, &preset, &body);
    send_state_event(
        storage,
        sn,
        &mut ctx,
        user_id,
        "m.room.power_levels",
        "",
        pl,
        key,
        None,
    )
    .await?;

    let join_rule = if preset == "public_chat" {
        "public"
    } else {
        "invite"
    };
    send_state_event(
        storage,
        sn,
        &mut ctx,
        user_id,
        "m.room.join_rules",
        "",
        json!({ "join_rule": join_rule }),
        key,
        None,
    )
    .await?;
    send_state_event(
        storage,
        sn,
        &mut ctx,
        user_id,
        "m.room.history_visibility",
        "",
        json!({ "history_visibility": "shared" }),
        key,
        None,
    )
    .await?;

    if preset != "public_chat" {
        send_state_event(
            storage,
            sn,
            &mut ctx,
            user_id,
            "m.room.guest_access",
            "",
            json!({ "guest_access": "can_join" }),
            key,
            None,
        )
        .await?;
    }

    if let Some(initial) = body.get("initial_state").and_then(Value::as_array) {
        for si in initial {
            let t = si.get("type").and_then(Value::as_str).unwrap_or("");
            let sk = si.get("state_key").and_then(Value::as_str).unwrap_or("");
            let c = si.get("content").cloned().unwrap_or_else(|| json!({}));
            send_state_event(storage, sn, &mut ctx, user_id, t, sk, c, key, None).await?;
        }
    }
    if let Some(name) = body.get("name").and_then(Value::as_str) {
        send_state_event(
            storage,
            sn,
            &mut ctx,
            user_id,
            "m.room.name",
            "",
            json!({ "name": name }),
            key,
            None,
        )
        .await?;
    }
    if let Some(topic) = body.get("topic").and_then(Value::as_str) {
        send_state_event(
            storage,
            sn,
            &mut ctx,
            user_id,
            "m.room.topic",
            "",
            // MSC3765: alongside the plain `topic`, write the rich-topic
            // representation so clients that read it get `m.topic.m.text`.
            json!({ "topic": topic, "m.topic": { "m.text": [{ "body": topic }] } }),
            key,
            None,
        )
        .await?;
    }

    // Local invites only (federated invite arrives with the federation phase).
    if let Some(invites) = body.get("invite").and_then(Value::as_array) {
        let is_direct = body
            .get("is_direct")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        for inv in invites {
            if let Some(invitee) = inv.as_str() {
                let mut content = json!({ "membership": "invite" });
                if is_direct {
                    content["is_direct"] = json!(true);
                }
                send_state_event(
                    storage,
                    sn,
                    &mut ctx,
                    user_id,
                    "m.room.member",
                    invitee,
                    content,
                    key,
                    None,
                )
                .await?;
            }
        }
    }

    if let Some(alias_name) = body.get("room_alias_name").and_then(Value::as_str) {
        let alias: RoomAlias = format!("#{alias_name}:{sn}").into();
        if st.storage.get_room_by_alias(&alias).await.is_some() {
            return Err(bad_json(format!("Room alias {alias} already exists")));
        }
        st.storage
            .create_room_alias(&alias, &room_id, vec![ServerName::from(sn)], &auth.user_id)
            .await;
        send_state_event(
            storage,
            sn,
            &mut ctx,
            user_id,
            "m.room.canonical_alias",
            "",
            json!({ "alias": alias.as_str() }),
            key,
            None,
        )
        .await?;
    }

    if visibility == Some("public") {
        st.storage
            .set_room_visibility(&room_id, crate::storage::Visibility::Public)
            .await;
    }

    Ok(Json(json!({ "room_id": room_id.as_str() })))
}

/// `GET /_matrix/client/v3/joined_rooms`.
pub async fn joined_rooms(State(st): State<AppState>, auth: AuthCtx) -> Json<Value> {
    let rooms = st.storage.get_rooms_for_user(&auth.user_id).await;
    Json(json!({ "joined_rooms": rooms.iter().map(|r| r.as_str()).collect::<Vec<_>>() }))
}

// --- helpers ---------------------------------------------------------------

fn is_alias_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '=' | '-' | '/')
}

fn power_levels_content(v12_plus: bool, user_id: &str, preset: &str, body: &Value) -> Value {
    let events = json!({
        "m.room.name": 50,
        "m.room.power_levels": 100,
        "m.room.history_visibility": 100,
        "m.room.canonical_alias": 50,
        "m.room.avatar": 50,
        "m.room.tombstone": if v12_plus { 150 } else { 100 },
        "m.room.server_acl": 100,
        "m.room.encryption": 100,
    });
    let users = if v12_plus {
        Value::Object(Map::new())
    } else {
        let mut m = Map::new();
        m.insert(user_id.to_string(), json!(100));
        Value::Object(m)
    };
    let mut pl = json!({
        "users": users,
        "users_default": 0,
        "events_default": 0,
        "state_default": 50,
        "ban": 50,
        "kick": 50,
        "redact": 50,
        "invite": 0,
        "events": events,
    });

    if preset == "trusted_private_chat" && !v12_plus {
        if let Some(invites) = body.get("invite").and_then(Value::as_array) {
            for inv in invites {
                if let Some(u) = inv.as_str() {
                    pl["users"][u] = json!(100);
                }
            }
        }
    }
    if let Some(ov) = body
        .get("power_level_content_override")
        .and_then(Value::as_object)
    {
        if let Some(plo) = pl.as_object_mut() {
            for (k, v) in ov {
                plo.insert(k.clone(), v.clone());
            }
        }
    }
    pl
}
