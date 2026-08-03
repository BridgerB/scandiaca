//! Storage smoke test for the in-memory backend — port of the spirit of strix's
//! `scripts/storage-smoke.ts`. Exercises the backend as `Arc<dyn Storage>`:
//! stream-counter advancement, long-poll `wait_for_events`, room/event/state
//! persistence, sync queries, and a few cross-domain paths.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use scandiaca::storage::{create_memory_storage, Direction, Storage, Visibility};
use scandiaca::types::identifiers::{AccessToken, RoomId, UserId};
use scandiaca::types::internal::{AccountType, RoomState, StoredSession, UserAccount};
use serde_json::json;

fn store() -> Arc<dyn Storage> {
    Arc::new(create_memory_storage())
}

fn user(localpart: &str) -> UserAccount {
    UserAccount {
        user_id: format!("@{localpart}:test.localhost").into(),
        localpart: localpart.to_string(),
        server_name: "test.localhost".into(),
        password_hash: "scrypt$x$y".to_string(),
        account_type: AccountType::User,
        is_deactivated: false,
        created_at: 1000,
        displayname: Some(localpart.to_string()),
        avatar_url: None,
    }
}

#[tokio::test]
async fn users_and_sessions() {
    let s = store();
    let alice = user("alice");
    let uid: UserId = alice.user_id.clone();
    s.create_user(alice).await;

    assert!(s.get_user_by_localpart("alice").await.is_some());
    assert_eq!(s.get_user_by_id(&uid).await.unwrap().localpart, "alice");

    let token: AccessToken = "tok_alice".into();
    s.create_session(StoredSession {
        device_id: "DEV1".into(),
        user_id: uid.clone(),
        access_token_hash: "h".to_string(),
        display_name: Some("phone".to_string()),
        last_seen_ip: None,
        last_seen_ts: None,
        user_agent: None,
        access_token: token.clone(),
        refresh_token: None,
        expires_at: None,
    })
    .await;

    let session = s.get_session_by_access_token(&token).await.unwrap();
    assert_eq!(session.device_id.as_str(), "DEV1");
    assert_eq!(s.get_all_devices(&uid).await.len(), 1);

    // Password update goes through users_by_id (single source of truth).
    s.update_password(&uid, "scrypt$new").await;
    assert_eq!(
        s.get_user_by_localpart("alice")
            .await
            .unwrap()
            .password_hash,
        "scrypt$new"
    );
}

#[tokio::test]
async fn rooms_events_and_stream_counter() {
    let s = store();
    let room_id: RoomId = "!room:test.localhost".into();

    let mut state_events = BTreeMap::new();
    let create = json!({
        "type": "m.room.create", "state_key": "", "sender": "@alice:test.localhost",
        "room_id": room_id.as_str(), "content": {"room_version": "11"},
        "depth": 1, "auth_events": [], "prev_events": [], "origin_server_ts": 1,
        "hashes": {"sha256": ""}, "signatures": {}
    });
    state_events.insert("m.room.create\u{1f}".to_string(), create);

    s.create_room(RoomState {
        room_id: room_id.clone(),
        room_version: "11".to_string(),
        state_events,
        depth: 1,
        forward_extremities: vec![],
        state_event_ids: BTreeMap::new(),
    })
    .await;

    let before = s.get_stream_position().await;
    // Store a couple of timeline events; the counter must advance per event.
    for i in 0..3 {
        let event = json!({
            "type": "m.room.message", "sender": "@alice:test.localhost",
            "room_id": room_id.as_str(), "content": {"body": format!("msg {i}")},
            "depth": 2 + i, "auth_events": [], "prev_events": [],
            "origin_server_ts": 100 + i, "hashes": {"sha256": ""}, "signatures": {}
        });
        s.store_event(event, &format!("$evt{i}").into()).await;
    }
    let after = s.get_stream_position().await;
    assert_eq!(after, before + 3, "stream counter advances once per event");

    // Forward pagination from 0 returns all 3.
    let page = s
        .get_events_by_room(&room_id, 10, Some(0), Direction::Forward)
        .await;
    assert_eq!(page.events.len(), 3);

    // Incremental since `before` returns the 3 new events.
    let since = s.get_events_by_room_since(&room_id, before, 10).await;
    assert_eq!(since.events.len(), 3);
    assert!(!since.limited);

    // Directory.
    s.set_room_visibility(&room_id, Visibility::Public).await;
    assert_eq!(s.get_room_visibility(&room_id).await, Visibility::Public);
    assert_eq!(s.get_public_room_ids().await, vec![room_id.clone()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_for_events_resolves_on_change() {
    let s = store();
    let since = s.get_stream_position().await;

    // A waiter past the current position should block until an event arrives.
    let waiter = {
        let s = s.clone();
        tokio::spawn(async move {
            let start = Instant::now();
            s.wait_for_events(since, 5_000).await;
            start.elapsed()
        })
    };

    // Give the waiter a moment to park, then store an event to wake it.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let event = json!({
        "type": "m.room.message", "sender": "@a:test.localhost",
        "room_id": "!r:test.localhost", "content": {}, "depth": 1,
        "auth_events": [], "prev_events": [], "origin_server_ts": 1,
        "hashes": {"sha256": ""}, "signatures": {}
    });
    // Room has a timeline so the counter advances.
    s.create_room(RoomState {
        room_id: "!r:test.localhost".into(),
        room_version: "11".to_string(),
        state_events: BTreeMap::new(),
        depth: 0,
        forward_extremities: vec![],
        state_event_ids: BTreeMap::new(),
    })
    .await;
    s.store_event(event, &"$wake".into()).await;

    let elapsed = waiter.await.unwrap();
    assert!(
        elapsed < std::time::Duration::from_secs(4),
        "waiter should wake promptly on the new event, took {elapsed:?}"
    );
}

#[tokio::test]
async fn wait_for_events_returns_immediately_when_behind() {
    let s = store();
    // since well below the counter → returns immediately even with a long timeout.
    let start = Instant::now();
    s.wait_for_events(-1, 10_000).await;
    assert!(start.elapsed() < std::time::Duration::from_secs(1));
}
