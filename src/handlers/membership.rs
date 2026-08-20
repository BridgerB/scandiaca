//! Room membership — port of strix `handlers/rooms.ts` membership handlers
//! (join/leave/invite/kick/ban/unban/knock/forget), local paths only. The
//! federation join/leave/invite round-trips arrive with the federation phase.

use axum::extract::{Path, State};
use axum::response::Json;
use crate::extract::OptionalJson;
use serde_json::{json, Map, Value};

use crate::errors::{forbidden, missing_param, not_found, room_not_found, MatrixError, MatrixResult};
use crate::events::{get_membership, get_user_power_level};
use crate::invite_filter::{get_invite_rule_for_target, InviteRule};
use crate::room_ops::send_membership_event;
use crate::server::{AppState, AuthCtx};
use crate::types::identifiers::{RoomId, UserId};

/// Internal room account-data marker for a forgotten room (strix
/// `FORGOTTEN_ROOM_MARKER`).
pub const FORGOTTEN_ROOM_MARKER: &str = "m.internal.forgotten";

fn key(st: &AppState) -> Option<&crate::signing::SigningKey> {
    Some(st.signing_key.as_ref())
}

/// `POST /_matrix/client/v3/join/{roomIdOrAlias}` and
/// `POST /_matrix/client/v3/rooms/{roomId}/join`.
pub async fn join(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id_or_alias): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    OptionalJson(body): OptionalJson,
) -> MatrixResult<Json<Value>> {
    let user_id = auth.user_id.as_str();

    // Resolve alias → room_id, collecting candidate servers. Local aliases use the
    // directory; a remote alias is resolved over federation (query/directory).
    let mut alias_servers: Vec<String> = Vec::new();
    let room_id = if let Some(_alias) = room_id_or_alias.strip_prefix('#') {
        if let Some(resolved) = st.storage.get_room_by_alias(&room_id_or_alias.as_str().into()).await {
            alias_servers.extend(resolved.servers.iter().map(|s| s.as_str().to_string()));
            resolved.room_id.as_str().to_string()
        } else {
            // Remote alias: ask the alias's home server.
            let domain = crate::ids::domain_of(&room_id_or_alias);
            let client = st.federation_client.as_ref();
            let resolved = match client {
                Some(c) if domain != st.server_name.as_ref() && !domain.is_empty() => c
                    .request(
                        domain,
                        "GET",
                        &format!(
                            "/_matrix/federation/v1/query/directory?room_alias={}",
                            crate::handlers::federation::membership::urlencode_public(&room_id_or_alias)
                        ),
                        None,
                    )
                    .await
                    .ok()
                    .filter(|r| r.status == 200),
                _ => None,
            };
            let Some(resolved) = resolved else {
                return Err(not_found(format!("Room alias {room_id_or_alias} not found")));
            };
            if let Some(servers) = resolved.body.get("servers").and_then(Value::as_array) {
                alias_servers.extend(servers.iter().filter_map(|v| v.as_str().map(String::from)));
            } else {
                alias_servers.push(domain.to_string());
            }
            match resolved.body.get("room_id").and_then(Value::as_str) {
                Some(r) => r.to_string(),
                None => return Err(not_found(format!("Room alias {room_id_or_alias} not found"))),
            }
        }
    } else {
        room_id_or_alias.clone()
    };
    let rid = RoomId::from(room_id.as_str());

    let Some(room) = st.storage.get_room(&rid).await else {
        // Room unknown locally → join over federation via a resident server.
        let mut candidates: Vec<String> = alias_servers.clone();
        if let Some(sn) = params.get("server_name") {
            candidates.push(sn.clone());
        }
        if room_id.contains(':') {
            candidates.push(crate::ids::domain_of(&room_id).to_string());
        }
        candidates.retain(|s| !s.is_empty() && s != st.server_name.as_ref());
        candidates.dedup();
        crate::handlers::federation::membership::perform_federation_join(
            &st, user_id, &room_id, &candidates,
        )
        .await?;
        clear_forgotten(&st, &auth.user_id, &rid).await;
        crate::handlers::room_upgrade::copy_predecessor_push_rules_on_join(&*st.storage, user_id, &room_id).await;
        return Ok(Json(json!({ "room_id": room_id })));
    };
    if get_membership(&room, user_id) == Some("ban") {
        return Err(forbidden("You are banned from this room"));
    }

    // Merge arbitrary content, dropping any client-supplied `membership`.
    let mut extra = body.as_object().cloned().unwrap_or_default();
    extra.remove("membership");
    let reason = extra.remove("reason").and_then(|v| v.as_str().map(String::from));

    // Restricted/knock_restricted rooms (MSC3083): a join that is neither a
    // rejoin nor invite-acceptance must be authorised by a local user with invite
    // power, recorded in content.join_authorised_via_users_server, or the join
    // event fails auth. Enforce the allow-rules before stamping the authoriser.
    let join_rule = crate::room_ops::get_join_rule(&room);
    let current = get_membership(&room, user_id);
    if (join_rule == "restricted" || join_rule == "knock_restricted")
        && current != Some("join")
        && current != Some("invite")
    {
        if let Some(authoriser) = crate::room_ops::find_authorising_local_user(&room, &st.server_name) {
            let satisfies =
                crate::room_ops::user_satisfies_restricted_allow(&*st.storage, &room, user_id, None).await;
            if !satisfies {
                return Err(forbidden(
                    "You are not a member of any room that grants access to this room",
                ));
            }
            extra.insert("join_authorised_via_users_server".to_string(), json!(authoriser));
        }
        // No local authoriser: fall through to the normal (federation-capable)
        // path; a purely local restricted room always has a local authoriser.
    }

    send_membership_event(
        &*st.storage,
        &st.server_name,
        key(&st),
        st.federation_client.as_deref(),
        &st.registrations,
        &rid,
        user_id,
        user_id,
        "join",
        reason.as_deref(),
        Some(extra),
    )
    .await?;

    // Re-joining clears any forgotten marker.
    clear_forgotten(&st, &auth.user_id, &rid).await;
    crate::handlers::room_upgrade::copy_predecessor_push_rules_on_join(&*st.storage, user_id, &room_id).await;

    Ok(Json(json!({ "room_id": room_id })))
}

/// `POST /_matrix/client/v3/rooms/{roomId}/leave`.
pub async fn leave(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
    OptionalJson(body): OptionalJson,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    let user_id = auth.user_id.as_str();
    let reason = body.get("reason").and_then(Value::as_str);

    let room = st.storage.get_room(&rid).await;
    if let Some(room) = &room {
        let m = get_membership(room, user_id);
        if m == Some("leave") || m == Some("ban") {
            return Ok(Json(json!({})));
        }
    }

    // A room owned by another server that we don't resident-hold (e.g. rejecting
    // a remote invite, or leaving a room we joined over federation) must leave via
    // make_leave/send_leave so the owning server learns of it.
    let room_server = if room_id.contains(':') { crate::ids::domain_of(&room_id) } else { "" };
    let resident = room
        .as_ref()
        .map(|r| {
            r.state_events.keys().any(|k| {
                k.starts_with("m.room.member\u{1f}")
                    && crate::ids::domain_of(k.trim_start_matches("m.room.member\u{1f}")) == st.server_name.as_ref()
            })
        })
        .unwrap_or(false);
    if !room_server.is_empty() && room_server != st.server_name.as_ref() && !resident {
        crate::handlers::federation::membership::perform_federation_leave(&st, user_id, &room_id, reason).await?;
        return Ok(Json(json!({})));
    }

    send_membership_event(
        &*st.storage,
        &st.server_name,
        key(&st),
        st.federation_client.as_deref(),
        &st.registrations,
        &rid,
        user_id,
        user_id,
        "leave",
        reason,
        None,
    )
    .await?;
    Ok(Json(json!({})))
}

/// `POST /_matrix/client/v3/rooms/{roomId}/invite`.
pub async fn invite(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
    OptionalJson(body): OptionalJson,
) -> MatrixResult<Json<Value>> {
    let Some(target) = body.get("user_id").and_then(Value::as_str) else {
        return Err(missing_param("Missing 'user_id'"));
    };
    let rid = RoomId::from(room_id.as_str());
    let reason = body.get("reason").and_then(Value::as_str);
    let is_direct = body.get("is_direct").and_then(Value::as_bool).unwrap_or(false);

    // MSC4155 invite filtering for a local invitee.
    let invitee_server = if target.contains(':') {
        crate::ids::domain_of(target)
    } else {
        &st.server_name
    };
    if invitee_server == st.server_name.as_ref() {
        match get_invite_rule_for_target(&*st.storage, &UserId::from(target), auth.user_id.as_str()).await {
            InviteRule::Block => return Err(forbidden("You are not permitted to invite this user.")),
            InviteRule::Ignore => return Ok(Json(json!({}))),
            InviteRule::Allow => {}
        }
    } else {
        // Remote invitee: send the invite over federation (PUT /v2/invite) so the
        // invitee's server co-signs it and shows it in their /sync.
        crate::handlers::federation::membership::perform_outbound_invite(
            &st, &room_id, auth.user_id.as_str(), target, reason, is_direct,
        )
        .await?;
        return Ok(Json(json!({})));
    }

    let extra = is_direct.then(|| {
        let mut m = Map::new();
        m.insert("is_direct".to_string(), json!(true));
        m
    });
    send_membership_event(
        &*st.storage,
        &st.server_name,
        key(&st),
        st.federation_client.as_deref(),
        &st.registrations,
        &rid,
        auth.user_id.as_str(),
        target,
        "invite",
        reason,
        extra,
    )
    .await?;
    Ok(Json(json!({})))
}

/// `POST /_matrix/client/v3/rooms/{roomId}/kick`.
pub async fn kick(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
    OptionalJson(body): OptionalJson,
) -> MatrixResult<Json<Value>> {
    let Some(target) = body.get("user_id").and_then(Value::as_str) else {
        return Err(missing_param("Missing 'user_id'"));
    };
    let rid = RoomId::from(room_id.as_str());
    let reason = body.get("reason").and_then(Value::as_str);

    // The C-S kick endpoint may only kick a user currently in the room.
    let m = st.storage.get_room(&rid).await.and_then(|r| get_membership(&r, target).map(String::from));
    if !matches!(m.as_deref(), Some("join" | "invite" | "knock")) {
        return Err(forbidden("Cannot kick a user who is not in the room"));
    }
    send_membership_event(
        &*st.storage,
        &st.server_name,
        key(&st),
        st.federation_client.as_deref(),
        &st.registrations,
        &rid,
        auth.user_id.as_str(),
        target,
        "leave",
        reason,
        None,
    )
    .await?;
    Ok(Json(json!({})))
}

/// `POST /_matrix/client/v3/rooms/{roomId}/ban`.
pub async fn ban(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
    OptionalJson(body): OptionalJson,
) -> MatrixResult<Json<Value>> {
    let Some(target) = body.get("user_id").and_then(Value::as_str) else {
        return Err(missing_param("Missing 'user_id'"));
    };
    let rid = RoomId::from(room_id.as_str());
    let reason = body.get("reason").and_then(Value::as_str);
    send_membership_event(
        &*st.storage,
        &st.server_name,
        key(&st),
        st.federation_client.as_deref(),
        &st.registrations,
        &rid,
        auth.user_id.as_str(),
        target,
        "ban",
        reason,
        None,
    )
    .await?;
    Ok(Json(json!({})))
}

/// `POST /_matrix/client/v3/rooms/{roomId}/unban`.
///
/// An unban is a `leave` event against a currently-banned target. The generic
/// membership auth treats leave-against-another as a kick (requiring the target
/// to be join/invite), so we authorize the unban here and send the leave.
pub async fn unban(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
    OptionalJson(body): OptionalJson,
) -> MatrixResult<Json<Value>> {
    let Some(target) = body.get("user_id").and_then(Value::as_str) else {
        return Err(missing_param("Missing 'user_id'"));
    };
    let rid = RoomId::from(room_id.as_str());
    let reason = body.get("reason").and_then(Value::as_str);
    let sender = auth.user_id.as_str();

    let room = st.storage.get_room(&rid).await.ok_or_else(|| room_not_found("Room not found"))?;
    if get_membership(&room, target) != Some("ban") {
        return Err(forbidden("User is not banned"));
    }
    if get_membership(&room, sender) != Some("join") {
        return Err(forbidden("Sender is not in the room"));
    }
    let ban_pl = room
        .state_events
        .get("m.room.power_levels\u{1f}")
        .and_then(|e| e.get("content"))
        .and_then(|c| c.get("ban"))
        .and_then(Value::as_f64)
        .unwrap_or(50.0);
    if get_user_power_level(sender, &room) < ban_pl {
        return Err(forbidden(format!("Insufficient power level to unban: need {ban_pl}")));
    }

    send_membership_event(
        &*st.storage,
        &st.server_name,
        key(&st),
        st.federation_client.as_deref(),
        &st.registrations,
        &rid,
        sender,
        target,
        "leave",
        reason,
        None,
    )
    .await?;
    Ok(Json(json!({})))
}

/// `POST /_matrix/client/v3/knock/{roomIdOrAlias}`.
pub async fn knock(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id_or_alias): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    OptionalJson(body): OptionalJson,
) -> MatrixResult<Json<Value>> {
    let reason = body.get("reason").and_then(Value::as_str);
    // Resolve alias locally; a bare room id is used as-is.
    let room_id = if room_id_or_alias.starts_with('#') {
        match st.storage.get_room_by_alias(&room_id_or_alias.as_str().into()).await {
            Some(r) => r.room_id.as_str().to_string(),
            None => room_id_or_alias.clone(),
        }
    } else {
        room_id_or_alias.clone()
    };
    let rid = RoomId::from(room_id.as_str());

    if st.storage.get_room(&rid).await.is_none() {
        // Remote knock via candidate servers.
        let mut servers: Vec<String> = Vec::new();
        if let Some(sn) = params.get("server_name") {
            servers.push(sn.clone());
        }
        if room_id.contains(':') {
            servers.push(crate::ids::domain_of(&room_id).to_string());
        }
        crate::handlers::federation::membership::perform_federation_knock(
            &st, auth.user_id.as_str(), &room_id, &servers, reason,
        )
        .await?;
        return Ok(Json(json!({ "room_id": room_id })));
    }
    send_membership_event(
        &*st.storage,
        &st.server_name,
        key(&st),
        st.federation_client.as_deref(),
        &st.registrations,
        &rid,
        auth.user_id.as_str(),
        auth.user_id.as_str(),
        "knock",
        reason,
        None,
    )
    .await?;
    Ok(Json(json!({ "room_id": room_id })))
}

/// `POST /_matrix/client/v3/rooms/{roomId}/forget`.
pub async fn forget(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(room_id): Path<String>,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    let room = st.storage.get_room(&rid).await.ok_or_else(|| room_not_found("Room not found"))?;
    let m = get_membership(&room, auth.user_id.as_str());
    if m != Some("leave") && m != Some("ban") {
        return Err(MatrixError::new(
            "M_UNKNOWN",
            "User must have left the room before forgetting it",
            400,
        ));
    }
    let mut content = Map::new();
    content.insert("forgotten".to_string(), json!(true));
    st.storage
        .set_room_account_data(&auth.user_id, &rid, FORGOTTEN_ROOM_MARKER, content)
        .await;
    Ok(Json(json!({})))
}

/// Clear the forgotten marker when a user re-joins a previously forgotten room.
async fn clear_forgotten(st: &AppState, user_id: &UserId, room_id: &RoomId) {
    let existing = st
        .storage
        .get_room_account_data(user_id, room_id, FORGOTTEN_ROOM_MARKER)
        .await;
    if existing
        .as_ref()
        .and_then(|d| d.get("forgotten"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        let mut content = Map::new();
        content.insert("forgotten".to_string(), json!(false));
        st.storage
            .set_room_account_data(user_id, room_id, FORGOTTEN_ROOM_MARKER, content)
            .await;
    }
}
