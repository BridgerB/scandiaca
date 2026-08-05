//! Federation membership — core make_join / send_join (public + invited joins).
//!
//! Port of strix `handlers/federation/membership.ts`. Restricted-join
//! authorisation, partial-state (`omit_members`) send_join, and outbound
//! fan-out to third servers are deferred; make/send leave+knock and 3pid invite
//! exchange arrive in later passes.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Json, Response};
use serde_json::{json, Value};

use crate::errors::{
    bad_json, forbidden, not_found, unable_to_authorise_join, MatrixError, MatrixResult,
};
use crate::events::{
    check_event_auth, compute_event_id, get_join_rule, get_membership, select_auth_events,
};
use crate::federation::verify::verify_origin_signature;
use crate::middleware::federation_auth::{FedAuth, FedAuthBody};
use crate::server::{now_ms, AppState};
use crate::signing::sign_event;
use crate::types::identifiers::{EventId, RoomId, UserId};

/// Outbound federated join: for a local user joining a room we don't hold, try
/// each candidate resident server — GET make_join → fill+sign the template →
/// PUT send_join → import the returned room state. Mirrors strix's
/// `performFederationJoin`. Restricted-join failover across servers is
/// simplified to a linear try of candidates.
pub async fn perform_federation_join(
    st: &AppState,
    user_id: &str,
    room_id: &str,
    candidates: &[String],
) -> MatrixResult<()> {
    let client = st
        .federation_client
        .as_ref()
        .ok_or_else(|| not_found("Room not found"))?;

    let mut last_err = not_found("Room not found");
    for server in candidates {
        // 1. make_join template.
        let make_path = format!(
            "/_matrix/federation/v1/make_join/{}/{}?ver=9&ver=10&ver=11&ver=12",
            urlencode(room_id),
            urlencode(user_id)
        );
        let Ok(resp) = client.request(server, "GET", &make_path, None).await else {
            continue;
        };
        if resp.status != 200 {
            last_err = MatrixError::new(
                "M_UNKNOWN",
                format!("make_join to {server} failed: {}", resp.status),
                resp.status.max(400),
            );
            continue;
        }
        let room_version = resp
            .body
            .get("room_version")
            .and_then(Value::as_str)
            .unwrap_or("10")
            .to_string();
        let Some(mut event) = resp.body.get("event").cloned() else {
            continue;
        };
        // 2. Fill + sign the template.
        if event.get("room_id").is_none() {
            event["room_id"] = json!(room_id);
        }
        event["origin_server_ts"] = json!(now_ms());
        if event.get("content").is_none() {
            event["content"] = json!({ "membership": "join" });
        }
        let signed = sign_event(&event, &st.server_name, &st.signing_key, Some(&room_version));
        let event_id = compute_event_id(&signed, Some(&room_version));

        // 3. send_join (v2).
        let send_path = format!(
            "/_matrix/federation/v2/send_join/{}/{}",
            urlencode(room_id),
            urlencode(&event_id)
        );
        let Ok(sj) = client.request(server, "PUT", &send_path, Some(signed.clone())).await else {
            continue;
        };
        if sj.status != 200 {
            last_err = MatrixError::new("M_UNKNOWN", format!("send_join failed: {}", sj.status), 400);
            continue;
        }

        // 4. Import the returned room state + auth chain, then our co-signed join.
        let state: Vec<Value> = sj
            .body
            .get("state")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let auth_chain: Vec<Value> = sj
            .body
            .get("auth_chain")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let stored_event = sj.body.get("event").cloned().unwrap_or(signed);
        st.storage
            .import_room_state(
                &RoomId::from(room_id),
                room_version.clone(),
                state,
                auth_chain,
            )
            .await;
        st.storage
            .set_state_event(&RoomId::from(room_id), stored_event, &EventId::from(event_id.as_str()))
            .await;
        return Ok(());
    }
    Err(last_err)
}

/// Public wrapper for path-segment encoding, used by the client join handler.
pub fn urlencode_public(s: &str) -> String {
    urlencode(s)
}

fn urlencode(s: &str) -> String {
    // Percent-encode the path-segment-unsafe characters we actually see in ids
    // (`!`, `#`, `:`, `/`, `@`, `+`).
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'!' => out.push_str("%21"),
            b'#' => out.push_str("%23"),
            b':' => out.push_str("%3A"),
            b'/' => out.push_str("%2F"),
            b'@' => out.push_str("%40"),
            b'+' => out.push_str("%2B"),
            _ => out.push(b as char),
        }
    }
    out
}

/// `GET /_matrix/federation/v1/make_join/{roomId}/{userId}`.
pub async fn make_join(
    State(st): State<AppState>,
    _auth: FedAuth,
    Path((room_id, user_id)): Path<(String, String)>,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    let room = st.storage.get_room(&rid).await.ok_or_else(|| not_found("Room not found"))?;

    // Room must federate.
    if room
        .state_events
        .get("m.room.create\u{1f}")
        .and_then(|e| e.get("content"))
        .and_then(|c| c.get("m.federate").or_else(|| c.get("federate")))
        .and_then(Value::as_bool)
        == Some(false)
    {
        return Err(forbidden("Room does not federate"));
    }

    let join_rule = get_join_rule(&room).to_string();
    let membership = get_membership(&room, &user_id).map(String::from);
    if membership.as_deref() == Some("ban") {
        return Err(forbidden("User is banned"));
    }

    // Non-public rooms require a standing invite (or an existing join). For a
    // restricted room (MSC3083), a user in an allowed room may join if we can
    // vouch for them via a local user with invite power.
    let is_restricted = join_rule == "restricted" || join_rule == "knock_restricted";
    let mut authoriser: Option<String> = None;
    if join_rule != "public"
        && membership.as_deref() != Some("invite")
        && membership.as_deref() != Some("join")
    {
        if is_restricted {
            if !crate::room_ops::user_satisfies_restricted_allow(&*st.storage, &room, &user_id, None).await
            {
                return Err(unable_to_authorise_join(
                    "User is not a member of any room in the allow list",
                ));
            }
            // Vouch via a local user who can invite; fail over otherwise.
            match crate::events::find_authorising_local_user(&room, &st.server_name) {
                Some(a) => authoriser = Some(a),
                None => {
                    return Err(unable_to_authorise_join(
                        "No local user able to authorise this join",
                    ))
                }
            }
        } else {
            return Err(unable_to_authorise_join("Room is not public and user is not invited"));
        }
    }

    let mut content = json!({ "membership": "join" });
    let mut auth_events = select_auth_events("m.room.member", Some(&user_id), &room, &user_id, None);
    // For a restricted join, add the authoriser to content + include their
    // m.room.member in auth_events so a resident server can verify the vouch.
    if let Some(a) = &authoriser {
        content["join_authorised_via_users_server"] = json!(a);
        if let Some(auth_member) = room.state_events.get(&format!("m.room.member\u{1f}{a}")) {
            let member_id = compute_event_id(auth_member, Some(&room.room_version));
            if !auth_events.iter().any(|e| e == &member_id) {
                auth_events.push(member_id);
            }
        }
    }

    let template = json!({
        "auth_events": auth_events,
        "content": content,
        "depth": room.depth,
        "origin_server_ts": now_ms(),
        "prev_events": room.forward_extremities.iter().map(|e| e.as_str()).collect::<Vec<_>>(),
        "room_id": room_id,
        "sender": user_id,
        "state_key": user_id,
        "type": "m.room.member",
    });
    Ok(Json(json!({ "room_version": room.room_version, "event": template })))
}

/// `PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}`.
pub async fn send_join_v2(
    st: State<AppState>,
    path: Path<(String, String)>,
    auth: FedAuthBody,
) -> MatrixResult<Response> {
    send_join_impl(st, path, auth, false).await
}

/// `PUT /_matrix/federation/v1/send_join/{roomId}/{eventId}` (array envelope).
pub async fn send_join_v1(
    st: State<AppState>,
    path: Path<(String, String)>,
    auth: FedAuthBody,
) -> MatrixResult<Response> {
    send_join_impl(st, path, auth, true).await
}

async fn send_join_impl(
    State(st): State<AppState>,
    Path((room_id, _event_id)): Path<(String, String)>,
    auth: FedAuthBody,
    v1: bool,
) -> MatrixResult<Response> {
    let mut event = auth.body;
    // Structural validation: a join m.room.member state event whose room_id
    // matches the path and whose state_key matches its sender.
    let is_join = event.get("type").and_then(Value::as_str) == Some("m.room.member")
        && event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) == Some("join")
        && event.get("state_key").and_then(Value::as_str).is_some()
        && event.get("state_key") == event.get("sender");
    if !is_join {
        return Err(bad_json("Not a valid join event"));
    }

    let rid = RoomId::from(room_id.as_str());
    let room = st.storage.get_room(&rid).await.ok_or_else(|| not_found("Room not found"))?;
    if event.get("room_id").is_none() {
        event["room_id"] = json!(room_id);
    }

    let client = st
        .federation_client
        .as_ref()
        .ok_or_else(|| forbidden("Federation not enabled"))?;
    verify_origin_signature(&event, &*st.storage, client, Some(&room.room_version)).await?;

    let event_id = compute_event_id(&event, Some(&room.room_version));
    check_event_auth(&event, &room)?;

    let co_signed = sign_event(&event, &st.server_name, &st.signing_key, Some(&room.room_version));
    let eid = EventId::from(event_id.as_str());
    st.storage.set_state_event(&rid, co_signed.clone(), &eid).await;
    st.storage
        .update_room_dag(
            &rid,
            (event.get("depth").and_then(Value::as_i64).unwrap_or(0) + 1).max(room.depth),
            vec![eid.clone()],
        )
        .await;

    // A remote user (re)joining: evict any cached device keys so the next query
    // re-fetches fresh ones.
    let joiner = event.get("state_key").and_then(Value::as_str).unwrap_or("");
    if crate::ids::domain_of(joiner) != st.server_name.as_ref() {
        st.storage.delete_device_keys(&joiner.into()).await;
    }

    // Full (non-partial) response: all current state + auth chain.
    let state_events: Vec<Value> = room.state_events.values().cloned().collect();
    let mut auth_ids: Vec<EventId> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for se in &state_events {
        if let Some(arr) = se.get("auth_events").and_then(Value::as_array) {
            for a in arr {
                if let Some(s) = a.as_str() {
                    if seen.insert(s.to_string()) {
                        auth_ids.push(EventId::from(s));
                    }
                }
            }
        }
    }
    let auth_chain = st.storage.get_auth_chain(&auth_ids).await;

    let joining_server = crate::ids::domain_of(joiner).to_string();
    let servers: Vec<String> = st
        .storage
        .get_servers_in_room(&rid)
        .await
        .into_iter()
        .map(|s| s.as_str().to_string())
        .filter(|s| *s != joining_server)
        .collect();
    let _ = &auth.origin;

    let body = json!({
        "origin": st.server_name.as_ref(),
        "auth_chain": auth_chain,
        "state": state_events,
        "event": co_signed,
        "servers_in_room": servers,
        "members_omitted": false,
    });
    if v1 {
        Ok(Json(json!([200, body])).into_response())
    } else {
        Ok(Json(body).into_response())
    }
}

// --- Federation invite -----------------------------------------------------

/// `PUT /_matrix/federation/v2/invite/{roomId}/{eventId}`.
pub async fn put_invite_v2(
    st: State<AppState>,
    path: Path<(String, String)>,
    auth: FedAuthBody,
) -> MatrixResult<Response> {
    put_invite_impl(st, path, auth, false).await
}

/// `PUT /_matrix/federation/v1/invite/{roomId}/{eventId}` (array envelope).
pub async fn put_invite_v1(
    st: State<AppState>,
    path: Path<(String, String)>,
    auth: FedAuthBody,
) -> MatrixResult<Response> {
    put_invite_impl(st, path, auth, true).await
}

async fn put_invite_impl(
    State(st): State<AppState>,
    Path((_room_id, _event_id)): Path<(String, String)>,
    auth: FedAuthBody,
    v1: bool,
) -> MatrixResult<Response> {
    let body = auth.body;
    let mut event = body.get("event").cloned().ok_or_else(|| bad_json("Missing invite event"))?;
    let state_key = event.get("state_key").and_then(Value::as_str).ok_or_else(|| bad_json("The invite event did not have a state key"))?.to_string();
    if event.get("type").and_then(Value::as_str) != Some("m.room.member")
        || event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str) != Some("invite")
    {
        return Err(bad_json("The event was not an m.room.member invite event"));
    }
    let room_id = event.get("room_id").and_then(Value::as_str).ok_or_else(|| bad_json("The invite event did not have a room_id"))?.to_string();
    if crate::ids::domain_of(&state_key) != st.server_name.as_ref() {
        return Err(forbidden("Invited user is not on this server"));
    }

    // MSC4155 invite filtering for the local invitee.
    let sender = event.get("sender").and_then(Value::as_str).unwrap_or("");
    let rule = crate::invite_filter::get_invite_rule_for_target(
        &*st.storage,
        &UserId::from(state_key.as_str()),
        sender,
    )
    .await;
    if rule == crate::invite_filter::InviteRule::Block {
        return Err(forbidden("You are not permitted to invite this user."));
    }

    let existing = st.storage.get_room(&RoomId::from(room_id.as_str())).await;
    let room_version = existing
        .as_ref()
        .map(|r| r.room_version.clone())
        .or_else(|| body.get("room_version").and_then(Value::as_str).map(String::from))
        .unwrap_or_else(|| "10".to_string());

    let client = st.federation_client.as_ref().ok_or_else(|| forbidden("Federation not enabled"))?;
    verify_origin_signature(&event, &*st.storage, client, Some(&room_version)).await?;

    let mut co_signed = sign_event(&event, &st.server_name, &st.signing_key, Some(&room_version));
    let event_id = compute_event_id(&co_signed, Some(&room_version));

    let respond = |ev: Value| -> Response {
        if v1 { Json(json!([200, { "event": ev }])).into_response() } else { Json(json!({ "event": ev })).into_response() }
    };
    if rule == crate::invite_filter::InviteRule::Ignore {
        return Ok(respond(co_signed));
    }

    // Stripped invite state → stash on unsigned + seed the room.
    let stripped: Vec<Value> = body
        .get("invite_room_state")
        .or_else(|| event.get("unsigned").and_then(|u| u.get("invite_room_state")))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if let Some(obj) = co_signed.as_object_mut() {
        let unsigned = obj.entry("unsigned").or_insert_with(|| json!({}));
        if let Some(u) = unsigned.as_object_mut() {
            u.insert("invite_room_state".to_string(), json!(stripped.clone()));
        }
    }
    let _ = &mut event;

    let eid = EventId::from(event_id.as_str());
    if existing.is_some() {
        // Out-of-band membership: update state only, leave the DAG untouched.
        st.storage.set_state_event(&RoomId::from(room_id.as_str()), co_signed.clone(), &eid).await;
    } else {
        // Seed a minimal room from the stripped state + the co-signed invite.
        let ots = event.get("origin_server_ts").and_then(Value::as_i64).unwrap_or(0);
        let mut seed: Vec<Value> = Vec::new();
        for s in &stripped {
            let t = s.get("type").and_then(Value::as_str).unwrap_or("");
            let sk = s.get("state_key").and_then(Value::as_str).unwrap_or("");
            if t == "m.room.member" && sk == state_key {
                continue;
            }
            seed.push(json!({
                "auth_events": [], "content": s.get("content").cloned().unwrap_or(json!({})),
                "depth": 0, "hashes": { "sha256": "" }, "origin_server_ts": ots,
                "prev_events": [], "room_id": room_id, "sender": s.get("sender").cloned().unwrap_or(Value::Null),
                "signatures": {}, "state_key": sk, "type": t,
            }));
        }
        seed.push(co_signed.clone());
        st.storage.import_room_state(&RoomId::from(room_id.as_str()), room_version.clone(), seed, vec![]).await;
    }
    Ok(respond(co_signed))
}

/// Outbound invite of a remote user: build+sign the invite, PUT it to the
/// invitee's server, store the co-signed event returned.
pub async fn perform_outbound_invite(
    st: &AppState,
    room_id: &str,
    sender: &str,
    target: &str,
    reason: Option<&str>,
    is_direct: bool,
) -> MatrixResult<()> {
    use crate::events::{build_event, check_event_auth, select_auth_events, BuildEventParams};
    let rid = RoomId::from(room_id);
    let room = st.storage.get_room(&rid).await.ok_or_else(|| not_found("Room not found"))?;
    let invitee_server = crate::ids::domain_of(target).to_string();
    let client = st.federation_client.as_ref().ok_or_else(|| forbidden("Federation not enabled"))?;

    let mut content = serde_json::Map::new();
    content.insert("membership".to_string(), json!("invite"));
    if let Some(r) = reason { content.insert("reason".to_string(), json!(r)); }
    if is_direct { content.insert("is_direct".to_string(), json!(true)); }

    let auth_events = select_auth_events("m.room.member", Some(target), &room, sender, Some(&content));
    let (event, event_id) = build_event(BuildEventParams {
        room_id,
        sender,
        event_type: "m.room.member",
        content: Value::Object(content),
        state_key: Some(target),
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
    check_event_auth(&event, &room)?;

    let stripped = st.storage.get_stripped_state(&rid).await;
    let path = format!(
        "/_matrix/federation/v2/invite/{}/{}",
        urlencode(room_id),
        urlencode(&event_id)
    );
    let resp = client
        .request(&invitee_server, "PUT", &path, Some(json!({
            "room_version": room.room_version, "event": event, "invite_room_state": stripped,
        })))
        .await
        .map_err(|_| MatrixError::new("M_UNKNOWN", "invite request failed", 502))?;
    if resp.status != 200 {
        let code = if resp.status == 403 { 403 } else { 400 };
        return Err(MatrixError::new("M_UNKNOWN", format!("invite failed: {}", resp.status), code));
    }
    let stored = resp.body.get("event").cloned().unwrap_or(event);
    let eid = EventId::from(event_id.as_str());
    st.storage.set_state_event(&rid, stored, &eid).await;
    st.storage.update_room_dag(&rid, room.depth + 1, vec![eid]).await;
    Ok(())
}

// --- Federation leave (reject invite / leave a remote room) ----------------

/// `GET /_matrix/federation/v1/make_leave/{roomId}/{userId}`.
pub async fn make_leave(
    State(st): State<AppState>,
    _auth: FedAuth,
    Path((room_id, user_id)): Path<(String, String)>,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    let room = st.storage.get_room(&rid).await.ok_or_else(|| not_found("Room not found"))?;
    let auth_events = select_auth_events("m.room.member", Some(&user_id), &room, &user_id, None);
    let template = json!({
        "auth_events": auth_events,
        "content": { "membership": "leave" },
        "depth": room.depth,
        "origin_server_ts": now_ms(),
        "prev_events": room.forward_extremities.iter().map(|e| e.as_str()).collect::<Vec<_>>(),
        "room_id": room_id,
        "sender": user_id,
        "state_key": user_id,
        "type": "m.room.member",
    });
    Ok(Json(json!({ "room_version": room.room_version, "event": template })))
}

/// `PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}`.
pub async fn send_leave_v2(st: State<AppState>, path: Path<(String, String)>, auth: FedAuthBody) -> MatrixResult<Response> {
    send_leave_impl(st, path, auth, false).await
}
/// `PUT /_matrix/federation/v1/send_leave/{roomId}/{eventId}` (array envelope).
pub async fn send_leave_v1(st: State<AppState>, path: Path<(String, String)>, auth: FedAuthBody) -> MatrixResult<Response> {
    send_leave_impl(st, path, auth, true).await
}

async fn send_leave_impl(
    State(st): State<AppState>,
    Path((room_id, _event_id)): Path<(String, String)>,
    auth: FedAuthBody,
    v1: bool,
) -> MatrixResult<Response> {
    let mut event = auth.body;
    let membership = event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str);
    let state_key = event.get("state_key").and_then(Value::as_str);
    let sender = event.get("sender").and_then(Value::as_str);
    // Must be a state m.room.member leave/ban whose state_key is the sender
    // (TestCannotSendNonLeaveViaSendLeave: reject regular events, non-state
    // membership events, wrong membership, and mismatched state keys with 400).
    if event.get("type").and_then(Value::as_str) != Some("m.room.member")
        || (membership != Some("leave") && membership != Some("ban"))
        || state_key.is_none()
        || state_key != sender
    {
        return Err(bad_json("Not a valid leave event"));
    }
    let room = st.storage.get_room(&RoomId::from(room_id.as_str())).await.ok_or_else(|| not_found("Room not found"))?;
    if event.get("room_id").is_none() {
        event["room_id"] = json!(room_id);
    }
    let client = st.federation_client.as_ref().ok_or_else(|| forbidden("Federation not enabled"))?;
    verify_origin_signature(&event, &*st.storage, client, Some(&room.room_version)).await?;
    let event_id = compute_event_id(&event, Some(&room.room_version));
    check_event_auth(&event, &room)?;
    let co_signed = sign_event(&event, &st.server_name, &st.signing_key, Some(&room.room_version));
    let eid = EventId::from(event_id.as_str());
    st.storage.set_state_event(&RoomId::from(room_id.as_str()), co_signed, &eid).await;
    st.storage
        .update_room_dag(
            &RoomId::from(room_id.as_str()),
            (event.get("depth").and_then(Value::as_i64).unwrap_or(0) + 1).max(room.depth),
            vec![eid],
        )
        .await;
    if v1 {
        Ok(Json(json!([200, {}])).into_response())
    } else {
        Ok(Json(json!({})).into_response())
    }
}

/// Outbound federated leave (reject an invite / leave a remote room): GET
/// make_leave → sign → PUT send_leave → record the leave locally.
pub async fn perform_federation_leave(
    st: &AppState,
    user_id: &str,
    room_id: &str,
    reason: Option<&str>,
) -> MatrixResult<()> {
    let rid = RoomId::from(room_id);
    // The room's owning/resident server: prefer the room-id domain.
    let server = crate::ids::domain_of(room_id).to_string();
    if server.is_empty() || server == st.server_name.as_ref() {
        return Err(not_found("Room not found"));
    }
    let client = st.federation_client.as_ref().ok_or_else(|| forbidden("Federation not enabled"))?;

    let make_path = format!(
        "/_matrix/federation/v1/make_leave/{}/{}",
        urlencode(room_id),
        urlencode(user_id)
    );
    let resp = client.request(&server, "GET", &make_path, None).await
        .map_err(|_| MatrixError::new("M_UNKNOWN", "make_leave failed", 502))?;
    if resp.status != 200 {
        return Err(MatrixError::new("M_UNKNOWN", format!("make_leave failed: {}", resp.status), 400));
    }
    let room_version = resp.body.get("room_version").and_then(Value::as_str).unwrap_or("10").to_string();
    let mut event = resp.body.get("event").cloned().unwrap_or(json!({}));
    if event.get("room_id").is_none() {
        event["room_id"] = json!(room_id);
    }
    event["content"] = json!({ "membership": "leave" });
    if let Some(r) = reason {
        event["content"]["reason"] = json!(r);
    }
    event["origin_server_ts"] = json!(now_ms());
    let signed = sign_event(&event, &st.server_name, &st.signing_key, Some(&room_version));
    let event_id = compute_event_id(&signed, Some(&room_version));
    let send_path = format!(
        "/_matrix/federation/v2/send_leave/{}/{}",
        urlencode(room_id),
        urlencode(&event_id)
    );
    let sl = client.request(&server, "PUT", &send_path, Some(signed.clone())).await
        .map_err(|_| MatrixError::new("M_UNKNOWN", "send_leave failed", 502))?;
    if sl.status != 200 {
        return Err(MatrixError::new("M_UNKNOWN", format!("send_leave failed: {}", sl.status), 400));
    }
    // Record the leave locally so the user's own /sync reflects the departure.
    if st.storage.get_room(&rid).await.is_some() {
        st.storage.set_state_event(&rid, signed, &EventId::from(event_id.as_str())).await;
    }
    Ok(())
}

// --- Federation knock ------------------------------------------------------

/// `GET /_matrix/federation/v1/make_knock/{roomId}/{userId}`.
pub async fn make_knock(
    State(st): State<AppState>,
    _auth: FedAuth,
    Path((room_id, user_id)): Path<(String, String)>,
) -> MatrixResult<Json<Value>> {
    let rid = RoomId::from(room_id.as_str());
    let room = st.storage.get_room(&rid).await.ok_or_else(|| not_found("Room not found"))?;
    let join_rule = get_join_rule(&room);
    if join_rule != "knock" && join_rule != "knock_restricted" {
        return Err(forbidden("Room does not support knocking"));
    }
    match get_membership(&room, &user_id) {
        Some("ban") => return Err(forbidden("User is banned")),
        Some("join") => return Err(forbidden("User is already in the room")),
        Some("invite") => return Err(forbidden("User is already invited to the room")),
        _ => {}
    }
    let auth_events = select_auth_events("m.room.member", Some(&user_id), &room, &user_id, None);
    let template = json!({
        "auth_events": auth_events,
        "content": { "membership": "knock" },
        "depth": room.depth,
        "origin_server_ts": now_ms(),
        "prev_events": room.forward_extremities.iter().map(|e| e.as_str()).collect::<Vec<_>>(),
        "room_id": room_id,
        "sender": user_id,
        "state_key": user_id,
        "type": "m.room.member",
    });
    Ok(Json(json!({ "room_version": room.room_version, "event": template })))
}

/// `PUT /_matrix/federation/v1/send_knock/{roomId}/{eventId}`.
pub async fn send_knock(
    State(st): State<AppState>,
    Path((room_id, _event_id)): Path<(String, String)>,
    auth: FedAuthBody,
) -> MatrixResult<Response> {
    let event = auth.body;
    let membership = event.get("content").and_then(|c| c.get("membership")).and_then(Value::as_str);
    let state_key = event.get("state_key").and_then(Value::as_str);
    let sender = event.get("sender").and_then(Value::as_str);
    // Must be a state m.room.member knock whose state_key is the sender
    // (TestCannotSendNonKnockViaSendKnock / TestCannotSendKnockViaSendKnock).
    if event.get("type").and_then(Value::as_str) != Some("m.room.member")
        || membership != Some("knock")
        || state_key.is_none()
        || state_key != sender
    {
        return Err(bad_json("Not a valid knock event"));
    }
    let room = st.storage.get_room(&RoomId::from(room_id.as_str())).await.ok_or_else(|| not_found("Room not found"))?;
    let client = st.federation_client.as_ref().ok_or_else(|| forbidden("Federation not enabled"))?;
    verify_origin_signature(&event, &*st.storage, client, Some(&room.room_version)).await?;
    let event_id = compute_event_id(&event, Some(&room.room_version));
    check_event_auth(&event, &room)?;
    let co_signed = sign_event(&event, &st.server_name, &st.signing_key, Some(&room.room_version));
    let eid = EventId::from(event_id.as_str());
    st.storage.set_state_event(&RoomId::from(room_id.as_str()), co_signed, &eid).await;
    st.storage.update_room_dag(&RoomId::from(room_id.as_str()), room.depth + 1, vec![eid]).await;
    // Return the room's stripped knock state so the knocker's client can render it.
    let stripped = st.storage.get_stripped_state(&RoomId::from(room_id.as_str())).await;
    Ok(Json(json!({ "knock_room_state": stripped })).into_response())
}

/// Outbound knock on a remote room: GET make_knock → sign → PUT send_knock.
pub async fn perform_federation_knock(
    st: &AppState,
    user_id: &str,
    room_id: &str,
    servers: &[String],
    reason: Option<&str>,
) -> MatrixResult<()> {
    let client = st.federation_client.as_ref().ok_or_else(|| not_found("Room not found"))?;
    let mut last = not_found("Room not found");
    for server in servers.iter().filter(|s| !s.is_empty() && s.as_str() != st.server_name.as_ref()) {
        let make_path = format!("/_matrix/federation/v1/make_knock/{}/{}?ver=7&ver=8&ver=9&ver=10&ver=11&ver=12", urlencode(room_id), urlencode(user_id));
        let Ok(resp) = client.request(server, "GET", &make_path, None).await else { continue };
        if resp.status != 200 {
            last = MatrixError::new("M_UNKNOWN", format!("make_knock failed: {}", resp.status), resp.status.max(400));
            continue;
        }
        let room_version = resp.body.get("room_version").and_then(Value::as_str).unwrap_or("10").to_string();
        let mut event = resp.body.get("event").cloned().unwrap_or(json!({}));
        if event.get("room_id").is_none() { event["room_id"] = json!(room_id); }
        event["origin_server_ts"] = json!(now_ms());
        event["content"] = json!({ "membership": "knock" });
        if let Some(r) = reason { event["content"]["reason"] = json!(r); }
        let signed = sign_event(&event, &st.server_name, &st.signing_key, Some(&room_version));
        let event_id = compute_event_id(&signed, Some(&room_version));
        let send_path = format!("/_matrix/federation/v1/send_knock/{}/{}", urlencode(room_id), urlencode(&event_id));
        let Ok(sk) = client.request(server, "PUT", &send_path, Some(signed.clone())).await else { continue };
        if sk.status != 200 {
            last = MatrixError::new("M_UNKNOWN", format!("send_knock failed: {}", sk.status), 400);
            continue;
        }
        // Seed the room locally from the returned knock state + our knock event so /sync shows it.
        let knock_state: Vec<Value> = sk.body.get("knock_room_state").and_then(Value::as_array).cloned().unwrap_or_default();
        let mut seed: Vec<Value> = Vec::new();
        for s in &knock_state {
            let t = s.get("type").and_then(Value::as_str).unwrap_or("");
            let skey = s.get("state_key").and_then(Value::as_str).unwrap_or("");
            if t == "m.room.member" && skey == user_id { continue; }
            seed.push(json!({
                "auth_events": [], "content": s.get("content").cloned().unwrap_or(json!({})),
                "depth": 0, "hashes": {"sha256":""}, "origin_server_ts": now_ms(),
                "prev_events": [], "room_id": room_id, "sender": s.get("sender").cloned().unwrap_or(Value::Null),
                "signatures": {}, "state_key": skey, "type": t,
            }));
        }
        seed.push(signed);
        if st.storage.get_room(&RoomId::from(room_id)).await.is_none() {
            st.storage.import_room_state(&RoomId::from(room_id), room_version, seed, vec![]).await;
        }
        return Ok(());
    }
    Err(last)
}
