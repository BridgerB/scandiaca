//! SQLite backend: the snapshot store must persist across reopen.
//!
//! The SQLite backend reuses the in-memory backend's logic (so the behavioural
//! conformance in `storage_memory.rs` applies equally); this suite proves the
//! extra guarantee it adds — durability across a restart.

use std::sync::Arc;

use scandiaca::storage::{create_sqlite_storage, Storage};
use scandiaca::types::identifiers::UserId;
use scandiaca::types::internal::{AccountType, UserAccount};

fn temp_db() -> String {
    let mut p = std::env::temp_dir();
    let unique = format!(
        "scandiaca-sqlite-test-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    p.push(unique);
    p.to_string_lossy().into_owned()
}

fn cleanup(path: &str) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{path}-wal"));
    let _ = std::fs::remove_file(format!("{path}-shm"));
}

fn alice() -> UserAccount {
    UserAccount {
        user_id: UserId::from("@alice:localhost"),
        localpart: "alice".into(),
        server_name: "localhost".into(),
        password_hash: "scrypt$x$y".into(),
        account_type: AccountType::User,
        is_deactivated: false,
        created_at: 1,
        displayname: Some("Alice".into()),
        avatar_url: None,
    }
}

#[tokio::test]
async fn persists_across_reopen() {
    let path = temp_db();

    {
        let store: Arc<dyn Storage> = Arc::new(create_sqlite_storage(&path));
        // Persistence is write-through, so the user is on disk after this call.
        store.create_user(alice()).await;
    }

    // Reopen the same file in a fresh backend: the user must still be there.
    {
        let store: Arc<dyn Storage> = Arc::new(create_sqlite_storage(&path));
        let got = store.get_user_by_localpart("alice").await;
        assert!(got.is_some(), "user should survive reopen");
        assert_eq!(got.unwrap().displayname.as_deref(), Some("Alice"));
    }

    cleanup(&path);
}

#[tokio::test]
async fn empty_db_starts_clean() {
    let path = temp_db();
    let store: Arc<dyn Storage> = Arc::new(create_sqlite_storage(&path));
    assert!(store.get_user_by_localpart("nobody").await.is_none());
    cleanup(&path);
}
