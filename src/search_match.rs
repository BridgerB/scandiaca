//! Event search matching — port of strix `src/search-match.ts`.

use serde_json::Value;

/// The event-content field a search `key` addresses.
fn field_for_key<'a>(content: &'a Value, key: &str) -> Option<&'a Value> {
    match key {
        "content.body" => content.get("body"),
        "content.name" => content.get("name"),
        "content.topic" => content.get("topic"),
        _ => None,
    }
}

/// Whether an event matches a search term: the term is split into words and the
/// event matches if any requested key holds a string containing every word
/// (case-insensitive).
pub fn event_matches_search_term(event: &Value, keys: &[String], search_term: &str) -> bool {
    let words: Vec<String> = search_term
        .to_lowercase()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    if words.is_empty() {
        return false;
    }
    let content = event.get("content");
    keys.iter().any(|key| {
        let field = content
            .and_then(|c| field_for_key(c, key))
            .and_then(Value::as_str);
        match field {
            Some(f) => {
                let haystack = f.to_lowercase();
                words.iter().all(|w| haystack.contains(w.as_str()))
            }
            None => false,
        }
    })
}
