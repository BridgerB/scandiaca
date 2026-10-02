//! MSC4155 invite filtering — port of strix `src/invite-filter.ts`.
//!
//! A user publishes an invite-permission config in global account data under
//! `org.matrix.msc4155.invite_permission_config`. When someone tries to invite
//! that user, the server consults the target's config to decide whether the
//! inviter is allowed/ignored/blocked.

use serde_json::Value;

use crate::glob::glob_match;
use crate::ids::domain_of;
use crate::storage::Storage;
use crate::types::identifiers::UserId;

/// Unstable account-data type carrying the invite permission config (MSC4155).
pub const INVITE_FILTER_ACCOUNT_DATA_TYPE: &str = "org.matrix.msc4155.invite_permission_config";

/// The outcome of evaluating a target's invite rules against an inviter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteRule {
    Allow,
    Ignore,
    Block,
}

/// True if any string pattern in `field` (an array) glob-matches `value`.
/// Non-array fields, non-string / empty / oversized (>255) entries are ignored
/// (mirrors synapse).
fn match_any(field: Option<&Value>, value: &str) -> bool {
    let Some(arr) = field.and_then(Value::as_array) else {
        return false;
    };
    arr.iter().any(|p| {
        p.as_str()
            .is_some_and(|s| !s.is_empty() && s.len() <= 255 && glob_match(s, value, false))
    })
}

/// Evaluate MSC4155 rules for `inviter_user_id` against a config object,
/// defaulting to `Allow`. User rules precede server rules; within each group the
/// order is allow → ignore → block; first match wins (strix `getInviteRule`).
pub fn get_invite_rule(config: Option<&Value>, inviter_user_id: &str) -> InviteRule {
    let Some(config) = config else {
        return InviteRule::Allow;
    };
    let inviter_server = if inviter_user_id.contains(':') {
        domain_of(inviter_user_id)
    } else {
        ""
    };

    if match_any(config.get("allowed_users"), inviter_user_id) {
        return InviteRule::Allow;
    }
    if match_any(config.get("ignored_users"), inviter_user_id) {
        return InviteRule::Ignore;
    }
    if match_any(config.get("blocked_users"), inviter_user_id) {
        return InviteRule::Block;
    }

    if !inviter_server.is_empty() {
        if match_any(config.get("allowed_servers"), inviter_server) {
            return InviteRule::Allow;
        }
        if match_any(config.get("ignored_servers"), inviter_server) {
            return InviteRule::Ignore;
        }
        if match_any(config.get("blocked_servers"), inviter_server) {
            return InviteRule::Block;
        }
    }

    InviteRule::Allow
}

/// Load the local target user's MSC4155 config and return the rule applying to
/// `inviter_user_id` (strix `getInviteRuleForTarget`).
pub async fn get_invite_rule_for_target(
    storage: &dyn Storage,
    target_user_id: &UserId,
    inviter_user_id: &str,
) -> InviteRule {
    let config = storage
        .get_global_account_data(target_user_id, INVITE_FILTER_ACCOUNT_DATA_TYPE)
        .await
        .map(Value::Object);
    get_invite_rule(config.as_ref(), inviter_user_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn default_allow_when_no_config() {
        assert_eq!(get_invite_rule(None, "@a:x"), InviteRule::Allow);
    }

    #[test]
    fn user_rules_precede_server_rules() {
        let cfg = json!({
            "allowed_users": ["@good:evil.com"],
            "blocked_servers": ["evil.com"],
        });
        assert_eq!(get_invite_rule(Some(&cfg), "@good:evil.com"), InviteRule::Allow);
        assert_eq!(get_invite_rule(Some(&cfg), "@bad:evil.com"), InviteRule::Block);
    }

    #[test]
    fn glob_patterns() {
        let cfg = json!({ "blocked_users": ["@spam*:*"] });
        assert_eq!(get_invite_rule(Some(&cfg), "@spam123:x.com"), InviteRule::Block);
        assert_eq!(get_invite_rule(Some(&cfg), "@ham:x.com"), InviteRule::Allow);
    }
}
