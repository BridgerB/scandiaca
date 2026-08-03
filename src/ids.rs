//! Identifier helpers — port of strix `src/ids.ts`.

/// The server-name (domain) part of a Matrix identifier — everything after the
/// first colon. Works for user IDs (`@alice:example.com`), room IDs, aliases,
/// etc., and keeps any port (`@alice:example.com:8448` → `example.com:8448`).
/// An identifier with no colon yields the empty string.
pub fn domain_of(id: &str) -> &str {
    match id.find(':') {
        Some(idx) => &id[idx + 1..],
        None => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_domain() {
        assert_eq!(domain_of("@alice:example.com"), "example.com");
        assert_eq!(domain_of("!abc:example.com:8448"), "example.com:8448");
        assert_eq!(domain_of("nocolon"), "");
    }
}
