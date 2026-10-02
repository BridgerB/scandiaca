//! Push-rule engine — port of strix `src/push-rules.ts`.
//!
//! Default ruleset + `evaluate_push_rules` over override → content → room →
//! sender → underride. Rules are stored as JSON (`m.push_rules` global account
//! data); this module keeps them as [`serde_json::Value`] to round-trip
//! client-supplied rules unchanged.

use serde_json::{json, Value};

use crate::glob::{glob_match, glob_match_word_boundary};
use crate::storage::Storage;
use crate::types::identifiers::UserId;

/// The outcome of evaluating push rules for an event.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PushEvalResult {
    pub notify: bool,
    pub highlight: bool,
    pub sound: Option<String>,
}

/// Context for evaluating push rules against a single event.
pub struct EvaluationContext<'a> {
    pub event: &'a Value,
    pub user_id: &'a str,
    pub display_name: Option<&'a str>,
    pub member_count: i64,
    pub power_levels: Option<&'a Value>,
    pub sender_power_level: i64,
}

/// Valid push-rule kinds.
pub const VALID_KINDS: &[&str] = &["override", "content", "room", "sender", "underride"];

pub fn is_valid_kind(kind: &str) -> bool {
    VALID_KINDS.contains(&kind)
}

/// The server default push ruleset for a user (strix `getDefaultRules`).
pub fn get_default_rules(user_id: &UserId) -> Value {
    let uid = user_id.as_str();
    // Localpart for the legacy `.m.rule.contains_user_name` mention rule.
    let localpart = uid
        .strip_prefix('@')
        .and_then(|s| s.split(':').next())
        .unwrap_or(uid);

    json!({
        "global": {
            "override": [
                { "rule_id": ".m.rule.master", "default": true, "enabled": false, "conditions": [], "actions": [] },
                {
                    "rule_id": ".m.rule.suppress_notices", "default": true, "enabled": true,
                    "conditions": [{ "kind": "event_match", "key": "content.msgtype", "pattern": "m.notice" }],
                    "actions": ["dont_notify"]
                },
                {
                    "rule_id": ".m.rule.invite_for_me", "default": true, "enabled": true,
                    "conditions": [
                        { "kind": "event_match", "key": "type", "pattern": "m.room.member" },
                        { "kind": "event_match", "key": "content.membership", "pattern": "invite" },
                        { "kind": "event_match", "key": "state_key", "pattern": uid }
                    ],
                    "actions": ["notify", { "set_tweak": "sound", "value": "default" }]
                },
                {
                    "rule_id": ".m.rule.member_event", "default": true, "enabled": true,
                    "conditions": [{ "kind": "event_match", "key": "type", "pattern": "m.room.member" }],
                    "actions": ["dont_notify"]
                },
                {
                    "rule_id": ".m.rule.is_user_mention", "default": true, "enabled": true,
                    "conditions": [{ "kind": "event_property_contains", "key": "content.m\\.mentions.user_ids", "value": uid }],
                    "actions": ["notify", { "set_tweak": "sound", "value": "default" }, { "set_tweak": "highlight" }]
                },
                {
                    "rule_id": ".m.rule.is_room_mention", "default": true, "enabled": true,
                    "conditions": [
                        { "kind": "event_property_is", "key": "content.m\\.mentions.room", "value": true },
                        { "kind": "sender_notification_permission", "key": "room" }
                    ],
                    "actions": ["notify", { "set_tweak": "highlight" }]
                },
                {
                    "rule_id": ".m.rule.tombstone", "default": true, "enabled": true,
                    "conditions": [
                        { "kind": "event_match", "key": "type", "pattern": "m.room.tombstone" },
                        { "kind": "event_match", "key": "state_key", "pattern": "" }
                    ],
                    "actions": ["notify", { "set_tweak": "highlight" }]
                },
                {
                    "rule_id": ".m.rule.roomnotif", "default": true, "enabled": true,
                    "conditions": [
                        { "kind": "event_match", "key": "content.body", "pattern": "@room" },
                        { "kind": "sender_notification_permission", "key": "room" }
                    ],
                    "actions": ["notify", { "set_tweak": "highlight" }]
                },
                {
                    "rule_id": ".org.matrix.msc3930.rule.poll_response", "default": true, "enabled": true,
                    "conditions": [{ "kind": "event_match", "key": "type", "pattern": "org.matrix.msc3381.poll.response" }],
                    "actions": []
                }
            ],
            "content": [
                {
                    "rule_id": ".m.rule.contains_display_name", "default": true, "enabled": true,
                    "conditions": [{ "kind": "contains_display_name" }],
                    "actions": ["notify", { "set_tweak": "sound", "value": "default" }, { "set_tweak": "highlight" }]
                },
                {
                    "rule_id": ".m.rule.contains_user_name", "default": true, "enabled": true,
                    "pattern": localpart,
                    "actions": ["notify", { "set_tweak": "sound", "value": "default" }, { "set_tweak": "highlight" }]
                }
            ],
            "room": [],
            "sender": [],
            "underride": [
                {
                    "rule_id": ".m.rule.call", "default": true, "enabled": true,
                    "conditions": [{ "kind": "event_match", "key": "type", "pattern": "m.call.invite" }],
                    "actions": ["notify", { "set_tweak": "sound", "value": "ring" }]
                },
                {
                    "rule_id": ".m.rule.encrypted_room_one_to_one", "default": true, "enabled": true,
                    "conditions": [
                        { "kind": "room_member_count", "is": "2" },
                        { "kind": "event_match", "key": "type", "pattern": "m.room.encrypted" }
                    ],
                    "actions": ["notify", { "set_tweak": "sound", "value": "default" }]
                },
                {
                    "rule_id": ".m.rule.room_one_to_one", "default": true, "enabled": true,
                    "conditions": [
                        { "kind": "room_member_count", "is": "2" },
                        { "kind": "event_match", "key": "type", "pattern": "m.room.message" }
                    ],
                    "actions": ["notify", { "set_tweak": "sound", "value": "default" }]
                },
                {
                    "rule_id": ".m.rule.message", "default": true, "enabled": true,
                    "conditions": [{ "kind": "event_match", "key": "type", "pattern": "m.room.message" }],
                    "actions": ["notify"]
                },
                {
                    "rule_id": ".m.rule.encrypted", "default": true, "enabled": true,
                    "conditions": [{ "kind": "event_match", "key": "type", "pattern": "m.room.encrypted" }],
                    "actions": ["notify"]
                },
                {
                    "rule_id": ".org.matrix.msc3930.rule.poll_start_one_to_one", "default": true, "enabled": true,
                    "conditions": [
                        { "kind": "room_member_count", "is": "2" },
                        { "kind": "event_match", "key": "type", "pattern": "org.matrix.msc3381.poll.start" }
                    ],
                    "actions": ["notify", { "set_tweak": "sound", "value": "default" }]
                },
                {
                    "rule_id": ".org.matrix.msc3930.rule.poll_start", "default": true, "enabled": true,
                    "conditions": [{ "kind": "event_match", "key": "type", "pattern": "org.matrix.msc3381.poll.start" }],
                    "actions": ["notify"]
                },
                {
                    "rule_id": ".org.matrix.msc3930.rule.poll_end_one_to_one", "default": true, "enabled": true,
                    "conditions": [
                        { "kind": "room_member_count", "is": "2" },
                        { "kind": "event_match", "key": "type", "pattern": "org.matrix.msc3381.poll.end" }
                    ],
                    "actions": ["notify", { "set_tweak": "sound", "value": "default" }]
                },
                {
                    "rule_id": ".org.matrix.msc3930.rule.poll_end", "default": true, "enabled": true,
                    "conditions": [{ "kind": "event_match", "key": "type", "pattern": "org.matrix.msc3381.poll.end" }],
                    "actions": ["notify"]
                }
            ]
        }
    })
}

/// Load the user's push rules, seeding defaults on first access (strix
/// `getOrInitRules`).
pub async fn get_or_init_rules(storage: &dyn Storage, user_id: &UserId) -> Value {
    if let Some(existing) = storage.get_global_account_data(user_id, "m.push_rules").await {
        return Value::Object(existing);
    }
    let defaults = get_default_rules(user_id);
    if let Some(obj) = defaults.as_object() {
        storage
            .set_global_account_data(user_id, "m.push_rules", obj.clone())
            .await;
    }
    defaults
}

/// Persist the user's push rules (strix `saveRules`).
pub async fn save_rules(storage: &dyn Storage, user_id: &UserId, rules: &Value) {
    if let Some(obj) = rules.as_object() {
        storage
            .set_global_account_data(user_id, "m.push_rules", obj.clone())
            .await;
    }
}

/// Navigate a dot-separated path with escaped dots (`\.`) into a JSON value
/// (strix `getNestedValue`).
fn get_nested_value<'a>(obj: &'a Value, key: &str) -> Option<&'a Value> {
    let mut parts: Vec<String> = Vec::new();
    let mut current = String::new();
    let bytes: Vec<char> = key.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == '\\' && i + 1 < bytes.len() && bytes[i + 1] == '.' {
            current.push('.');
            i += 2;
        } else if bytes[i] == '.' {
            parts.push(std::mem::take(&mut current));
            i += 1;
        } else {
            current.push(bytes[i]);
            i += 1;
        }
    }
    parts.push(current);

    let mut value = obj;
    for part in &parts {
        value = value.as_object()?.get(part)?;
    }
    Some(value)
}

/// `room_member_count` comparison against `is` (e.g. `"2"`, `">2"`, `"<=10"`).
fn match_member_count(actual: i64, is: &str) -> bool {
    let is = is.trim();
    let (op, num_str) = if let Some(rest) = is.strip_prefix("==") {
        ("==", rest)
    } else if let Some(rest) = is.strip_prefix("<=") {
        ("<=", rest)
    } else if let Some(rest) = is.strip_prefix(">=") {
        (">=", rest)
    } else if let Some(rest) = is.strip_prefix('<') {
        ("<", rest)
    } else if let Some(rest) = is.strip_prefix('>') {
        (">", rest)
    } else {
        ("==", is)
    };
    let Ok(target) = num_str.parse::<i64>() else {
        return false;
    };
    match op {
        "==" => actual == target,
        "<" => actual < target,
        ">" => actual > target,
        "<=" => actual <= target,
        ">=" => actual >= target,
        _ => false,
    }
}

fn check_condition(cond: &Value, ctx: &EvaluationContext) -> bool {
    let kind = cond.get("kind").and_then(Value::as_str).unwrap_or("");
    match kind {
        "event_match" => {
            let Some(key) = cond.get("key").and_then(Value::as_str) else {
                return false;
            };
            let Some(pattern) = cond.get("pattern").and_then(Value::as_str) else {
                return false;
            };
            let Some(value) = get_nested_value(ctx.event, key).and_then(Value::as_str) else {
                return false;
            };
            if key == "content.body" {
                glob_match_word_boundary(pattern, value)
            } else {
                glob_match(pattern, value, true)
            }
        }
        "contains_display_name" => {
            let Some(display_name) = ctx.display_name else {
                return false;
            };
            get_nested_value(ctx.event, "content.body")
                .and_then(Value::as_str)
                .is_some_and(|body| glob_match_word_boundary(display_name, body))
        }
        "room_member_count" => cond
            .get("is")
            .and_then(Value::as_str)
            .is_some_and(|is| match_member_count(ctx.member_count, is)),
        "sender_notification_permission" => {
            let Some(key) = cond.get("key").and_then(Value::as_str) else {
                return false;
            };
            let required = ctx
                .power_levels
                .and_then(|pl| pl.get("notifications"))
                .and_then(|n| n.get(key))
                .and_then(Value::as_i64)
                .unwrap_or(50);
            ctx.sender_power_level >= required
        }
        "event_property_is" => {
            let Some(key) = cond.get("key").and_then(Value::as_str) else {
                return false;
            };
            let expected = cond.get("value").unwrap_or(&Value::Null);
            get_nested_value(ctx.event, key).is_some_and(|v| v == expected)
        }
        "event_property_contains" => {
            let Some(key) = cond.get("key").and_then(Value::as_str) else {
                return false;
            };
            let expected = cond.get("value").unwrap_or(&Value::Null);
            get_nested_value(ctx.event, key)
                .and_then(Value::as_array)
                .is_some_and(|arr| arr.iter().any(|item| item == expected))
        }
        _ => false,
    }
}

fn check_conditions(conditions: &Value, ctx: &EvaluationContext) -> bool {
    conditions
        .as_array()
        .map(|arr| arr.iter().all(|c| check_condition(c, ctx)))
        .unwrap_or(true)
}

fn parse_actions(actions: &Value) -> PushEvalResult {
    let mut result = PushEvalResult::default();
    let Some(actions) = actions.as_array() else {
        return result;
    };
    for action in actions {
        if action.as_str() == Some("notify") {
            result.notify = true;
        } else if action.as_str() == Some("dont_notify") {
            result.notify = false;
        } else if let Some(obj) = action.as_object() {
            match obj.get("set_tweak").and_then(Value::as_str) {
                Some("highlight") => {
                    result.highlight = obj.get("value") != Some(&Value::Bool(false));
                }
                Some("sound") => {
                    result.sound = obj.get("value").and_then(Value::as_str).map(String::from);
                }
                _ => {}
            }
        }
    }
    result
}

/// Return the first enabled rule in `list` whose conditions match.
fn find_conditional<'a>(list: Option<&'a Value>, ctx: &EvaluationContext) -> Option<&'a Value> {
    list?.as_array()?.iter().find(|r| {
        r.get("enabled").and_then(Value::as_bool).unwrap_or(false)
            && check_conditions(r.get("conditions").unwrap_or(&Value::Null), ctx)
    })
}

/// Evaluate push rules for an event (strix `evaluatePushRules`).
pub fn evaluate_push_rules(rules: &Value, ctx: &EvaluationContext) -> PushEvalResult {
    let no_match = PushEvalResult::default();
    if ctx.event.get("sender").and_then(Value::as_str) == Some(ctx.user_id) {
        return no_match;
    }
    let ruleset = rules.get("global").unwrap_or(&Value::Null);

    if let Some(r) = find_conditional(ruleset.get("override"), ctx) {
        return parse_actions(r.get("actions").unwrap_or(&Value::Null));
    }

    // content rules: conditions if present, else body word-boundary match on pattern.
    let content_match = ruleset.get("content").and_then(Value::as_array).and_then(|arr| {
        arr.iter().find(|rule| {
            if !rule.get("enabled").and_then(Value::as_bool).unwrap_or(false) {
                return false;
            }
            if let Some(conds) = rule.get("conditions").and_then(Value::as_array) {
                if !conds.is_empty() {
                    return check_conditions(rule.get("conditions").unwrap(), ctx);
                }
            }
            let Some(pattern) = rule.get("pattern").and_then(Value::as_str) else {
                return false;
            };
            get_nested_value(ctx.event, "content.body")
                .and_then(Value::as_str)
                .is_some_and(|body| glob_match_word_boundary(pattern, body))
        })
    });
    if let Some(r) = content_match {
        return parse_actions(r.get("actions").unwrap_or(&Value::Null));
    }

    let room_id = ctx.event.get("room_id").and_then(Value::as_str);
    if let Some(r) = ruleset.get("room").and_then(Value::as_array).and_then(|arr| {
        arr.iter().find(|r| {
            r.get("enabled").and_then(Value::as_bool).unwrap_or(false)
                && r.get("rule_id").and_then(Value::as_str) == room_id
        })
    }) {
        return parse_actions(r.get("actions").unwrap_or(&Value::Null));
    }

    let sender = ctx.event.get("sender").and_then(Value::as_str);
    if let Some(r) = ruleset.get("sender").and_then(Value::as_array).and_then(|arr| {
        arr.iter().find(|r| {
            r.get("enabled").and_then(Value::as_bool).unwrap_or(false)
                && r.get("rule_id").and_then(Value::as_str) == sender
        })
    }) {
        return parse_actions(r.get("actions").unwrap_or(&Value::Null));
    }

    if let Some(r) = find_conditional(ruleset.get("underride"), ctx) {
        return parse_actions(r.get("actions").unwrap_or(&Value::Null));
    }

    no_match
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Value {
        get_default_rules(&UserId::from("@bob:hs1"))
    }

    fn ctx<'a>(event: &'a Value, member_count: i64) -> EvaluationContext<'a> {
        EvaluationContext {
            event,
            user_id: "@bob:hs1",
            display_name: None,
            member_count,
            power_levels: None,
            sender_power_level: 0,
        }
    }

    #[test]
    fn own_message_never_notifies() {
        let ev = json!({ "type": "m.room.message", "sender": "@bob:hs1", "content": { "msgtype": "m.text", "body": "hi" } });
        assert_eq!(evaluate_push_rules(&rules(), &ctx(&ev, 5)), PushEvalResult::default());
    }

    #[test]
    fn group_message_notifies_no_highlight() {
        let ev = json!({ "type": "m.room.message", "sender": "@alice:hs1", "content": { "msgtype": "m.text", "body": "hi" } });
        let r = evaluate_push_rules(&rules(), &ctx(&ev, 5));
        assert!(r.notify);
        assert!(!r.highlight);
    }

    #[test]
    fn one_to_one_message_has_sound() {
        let ev = json!({ "type": "m.room.message", "sender": "@alice:hs1", "content": { "msgtype": "m.text", "body": "hi" } });
        let r = evaluate_push_rules(&rules(), &ctx(&ev, 2));
        assert!(r.notify);
        assert_eq!(r.sound.as_deref(), Some("default"));
    }

    #[test]
    fn user_mention_highlights() {
        let ev = json!({ "type": "m.room.message", "sender": "@alice:hs1", "content": { "msgtype": "m.text", "body": "hey", "m.mentions": { "user_ids": ["@bob:hs1"] } } });
        let r = evaluate_push_rules(&rules(), &ctx(&ev, 5));
        assert!(r.notify);
        assert!(r.highlight);
    }

    #[test]
    fn notices_suppressed() {
        let ev = json!({ "type": "m.room.message", "sender": "@alice:hs1", "content": { "msgtype": "m.notice", "body": "beep" } });
        let r = evaluate_push_rules(&rules(), &ctx(&ev, 5));
        assert!(!r.notify);
    }

    #[test]
    fn localpart_mention_in_body_highlights() {
        let ev = json!({ "type": "m.room.message", "sender": "@alice:hs1", "content": { "msgtype": "m.text", "body": "Hello @bob:hs1!" } });
        let r = evaluate_push_rules(&rules(), &ctx(&ev, 5));
        assert!(r.highlight);
    }

    #[test]
    fn member_count_operators() {
        assert!(match_member_count(2, "2"));
        assert!(match_member_count(2, "==2"));
        assert!(match_member_count(1, "<2"));
        assert!(match_member_count(3, ">2"));
        assert!(match_member_count(2, "<=2"));
        assert!(match_member_count(2, ">=2"));
        assert!(!match_member_count(3, "<2"));
    }

    #[test]
    fn nested_value_escaped_dot() {
        let ev = json!({ "content": { "m.mentions": { "room": true } } });
        assert_eq!(
            get_nested_value(&ev, "content.m\\.mentions.room"),
            Some(&Value::Bool(true))
        );
    }
}
