//! Ignore lists — port of strix `src/ignored-users.ts` + `src/ignored-invites.ts`.
//!
//! Reads the user's `m.ignored_user_list` and `m.ignored_invites` global
//! account data into sets of user ids.

use std::collections::HashSet;

use crate::storage::Storage;
use crate::types::identifiers::UserId;

/// Users the given user ignores (`m.ignored_user_list.ignored_users` keys).
pub async fn get_ignored_users(storage: &dyn Storage, user_id: &UserId) -> HashSet<String> {
    let Some(content) = storage
        .get_global_account_data(user_id, "m.ignored_user_list")
        .await
    else {
        return HashSet::new();
    };
    content
        .get("ignored_users")
        .and_then(|v| v.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

/// Senders whose invites should be suppressed (`m.ignored_invites.senders`
/// keys).
pub async fn get_ignored_invite_senders(storage: &dyn Storage, user_id: &UserId) -> HashSet<String> {
    let Some(content) = storage
        .get_global_account_data(user_id, "m.ignored_invites")
        .await
    else {
        return HashSet::new();
    };
    content
        .get("senders")
        .and_then(|v| v.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}
