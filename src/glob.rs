//! Glob → regex matching — port of strix `src/glob.ts`.
//!
//! strix builds a JS `RegExp` from a glob pattern (`*` → `.*`, `?` → `.`). The
//! Rust port compiles the same escaped pattern with the `regex` crate, whose
//! syntax is compatible for these constructs. Used by push rules and server
//! ACLs.

use regex::Regex;

/// Escape a glob pattern into a regex body: regex metacharacters are escaped,
/// then `*` → `.*` and `?` → `.` (strix `escapeGlob`).
pub fn escape_glob(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len() * 2);
    for c in pattern.chars() {
        match c {
            // JS: /[.+^${}()|[\]\\]/g → "\\$&"
            '.' | '+' | '^' | '$' | '{' | '}' | '(' | ')' | '|' | '[' | ']' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            _ => out.push(c),
        }
    }
    out
}

/// True if `value` fully matches `pattern` (anchored `^…$`). Optionally case
/// insensitive (strix `globMatch`).
pub fn glob_match(pattern: &str, value: &str, case_insensitive: bool) -> bool {
    let body = escape_glob(pattern);
    let src = if case_insensitive {
        format!("(?is)^{body}$")
    } else {
        format!("(?s)^{body}$")
    };
    match Regex::new(&src) {
        Ok(re) => re.is_match(value),
        Err(_) => false,
    }
}

/// True if `pattern` appears in `body` on a word boundary, case-insensitively
/// (strix `globMatchWordBoundary` — used for `contains_display_name`).
pub fn glob_match_word_boundary(pattern: &str, body: &str) -> bool {
    let escaped = escape_glob(pattern);
    let src = format!(r"(?is)(?:^|\W)({escaped})(?:$|\W)");
    match Regex::new(&src) {
        Ok(re) => re.is_match(body),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_and_question() {
        assert!(glob_match("m.*", "m.room.message", false));
        assert!(glob_match("m.room.?", "m.room.x", false));
        assert!(!glob_match("m.room.?", "m.room.xy", false));
        assert!(!glob_match("m.*", "x.m", false));
    }

    #[test]
    fn case_insensitive() {
        assert!(glob_match("ALICE", "alice", true));
        assert!(!glob_match("ALICE", "alice", false));
    }

    #[test]
    fn word_boundary() {
        assert!(glob_match_word_boundary("alice", "hello alice!"));
        assert!(!glob_match_word_boundary("alice", "hello alicexyz"));
    }

    #[test]
    fn literal_dot_is_escaped() {
        // "a.c" must not match "axc" — the dot is a literal.
        assert!(!glob_match("a.c", "axc", false));
        assert!(glob_match("a.c", "a.c", false));
    }
}
