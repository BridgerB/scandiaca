//! Room event filtering — port of strix `src/event-filter.ts`.
//!
//! Applies a [`RoomEventFilter`] to a single (client) event, supporting the
//! fields that affect which events are returned: types/not_types (with `*`
//! wildcards), senders/not_senders, and contains_url.

use serde_json::Value;

use crate::glob::glob_match;
use crate::types::filters::RoomEventFilter;

/// True if `value` matches any glob pattern in `patterns`.
fn matches_any(patterns: &[String], value: &str) -> bool {
    patterns.iter().any(|p| glob_match(p, value, false))
}

/// Apply a `RoomEventFilter` to a client event (a JSON object with `type`,
/// `sender`, `content`). Returns false if the event is excluded (strix
/// `matchesRoomEventFilter`).
pub fn matches_room_event_filter(event: &Value, filter: Option<&RoomEventFilter>) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    let event_type = event.get("type").and_then(Value::as_str).unwrap_or("");
    let sender = event.get("sender").and_then(Value::as_str).unwrap_or("");

    if let Some(types) = &filter.types {
        if !matches_any(types, event_type) {
            return false;
        }
    }
    if let Some(not_types) = &filter.not_types {
        if matches_any(not_types, event_type) {
            return false;
        }
    }
    if let Some(senders) = &filter.senders {
        if !senders.iter().any(|s| s == sender) {
            return false;
        }
    }
    if let Some(not_senders) = &filter.not_senders {
        if not_senders.iter().any(|s| s == sender) {
            return false;
        }
    }
    if let Some(contains_url) = filter.contains_url {
        let has_url = event
            .get("content")
            .and_then(|c| c.get("url"))
            .is_some_and(Value::is_string);
        if has_url != contains_url {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(t: &str, sender: &str) -> Value {
        json!({ "type": t, "sender": sender, "content": {} })
    }

    #[test]
    fn no_filter_passes() {
        assert!(matches_room_event_filter(&ev("m.room.message", "@a:x"), None));
    }

    #[test]
    fn types_and_not_types() {
        let f = RoomEventFilter {
            types: Some(vec!["m.room.*".into()]),
            ..Default::default()
        };
        assert!(matches_room_event_filter(&ev("m.room.message", "@a:x"), Some(&f)));
        assert!(!matches_room_event_filter(&ev("m.reaction", "@a:x"), Some(&f)));

        let f = RoomEventFilter {
            not_types: Some(vec!["m.reaction".into()]),
            ..Default::default()
        };
        assert!(!matches_room_event_filter(&ev("m.reaction", "@a:x"), Some(&f)));
    }

    #[test]
    fn senders() {
        let f = RoomEventFilter {
            senders: Some(vec!["@a:x".into()]),
            ..Default::default()
        };
        assert!(matches_room_event_filter(&ev("m.room.message", "@a:x"), Some(&f)));
        assert!(!matches_room_event_filter(&ev("m.room.message", "@b:x"), Some(&f)));
    }

    #[test]
    fn contains_url() {
        let f = RoomEventFilter {
            contains_url: Some(true),
            ..Default::default()
        };
        let with_url = json!({ "type": "m.room.message", "sender": "@a:x", "content": { "url": "mxc://x/y" } });
        assert!(matches_room_event_filter(&with_url, Some(&f)));
        assert!(!matches_room_event_filter(&ev("m.room.message", "@a:x"), Some(&f)));
    }
}
