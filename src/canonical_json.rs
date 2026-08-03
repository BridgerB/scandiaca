//! Canonical JSON — port of strix `canonicalJson` (in `src/events.ts`).
//!
//! Deterministic, sorted-key, whitespace-free JSON used for signing and hashing.
//! This MUST be byte-identical to strix's output or federation signatures and
//! event-ID hashes will not verify against other servers.
//!
//! strix's reference implementation:
//! ```js
//! const canonicalJson = (val) => {
//!   if (val === null || val === undefined) return "null";
//!   if (typeof val === "boolean") return val ? "true" : "false";
//!   if (typeof val === "number") return JSON.stringify(val);
//!   if (typeof val === "string") return JSON.stringify(val);
//!   if (Array.isArray(val)) return `[${val.map(canonicalJson).join(",")}]`;
//!   if (typeof val === "object") {
//!     const keys = Object.keys(val).sort();
//!     return `{${keys.map(k => `${JSON.stringify(k)}:${canonicalJson(val[k])}`).join(",")}}`;
//!   }
//!   return JSON.stringify(val);
//! };
//! ```
//!
//! Parity decisions (each validated against `tests/fixtures/phase1.json`):
//! - **Key ordering**: JS `Array.prototype.sort` (no comparator) orders strings
//!   by UTF-16 code unit. We replicate that exactly via [`utf16_cmp`] rather than
//!   relying on Rust's UTF-8 byte ordering (identical for ASCII/BMP, divergent
//!   only for supplementary-plane keys, which never appear in Matrix events).
//! - **String escaping**: mirrors `JSON.stringify` — escape `"` `\\` and the
//!   short forms `\b \t \n \f \r`; other C0 controls as lowercase `\u00xx`;
//!   `/` and non-ASCII are emitted raw.
//! - **Numbers**: integers are emitted as-is. Float values are rendered to match
//!   `JSON.stringify` (`1.0` → `"1"`, `-0.0` → `"0"`), which differs from
//!   serde_json's float formatting (`"1.0"`). Real Matrix events only carry
//!   integers on the signed/hashed path, so this is belt-and-suspenders.

use serde_json::Value;

/// Serialize a [`Value`] to canonical JSON.
pub fn canonical_json(val: &Value) -> String {
    let mut out = String::with_capacity(256);
    write_canonical(val, &mut out);
    out
}

fn write_canonical(val: &Value, out: &mut String) {
    match val {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(n, out),
        Value::String(s) => write_json_string(s, out),
        Value::Array(arr) => {
            out.push('[');
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(v, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(k, out);
                out.push(':');
                // Index is safe: `k` came from `map.keys()`.
                write_canonical(&map[k.as_str()], out);
            }
            out.push('}');
        }
    }
}

/// Compare two strings the way JavaScript's default `Array.prototype.sort` does:
/// lexicographically by UTF-16 code unit. For all-ASCII strings (the common case
/// for event/state keys) byte order equals UTF-16 order, so fast-path that to
/// avoid re-encoding to UTF-16 on every comparison during key sorting.
pub fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    if a.is_ascii() && b.is_ascii() {
        return a.as_bytes().cmp(b.as_bytes());
    }
    a.encode_utf16().cmp(b.encode_utf16())
}

fn write_number(n: &serde_json::Number, out: &mut String) {
    use std::fmt::Write as _;
    if let Some(i) = n.as_i64() {
        // `write!` formats straight into `out`, avoiding a per-number `String`
        // allocation (`i.to_string()`).
        let _ = write!(out, "{i}");
    } else if let Some(u) = n.as_u64() {
        let _ = write!(out, "{u}");
    } else if let Some(f) = n.as_f64() {
        write_js_float(f, out);
    } else {
        // Should be unreachable for finite JSON numbers.
        out.push_str(&n.to_string());
    }
}

/// Render a float the way `JSON.stringify` (ECMAScript `Number.prototype
/// .toString`) would: integral values print with no decimal point (`1.0` → `1`,
/// `-0.0` → `0`), non-integral values use the shortest round-tripping form
/// (`1.5` → `1.5`). Rust's `f64` `Display` already matches JS for the magnitudes
/// that occur in practice; we special-case integral values to be explicit and to
/// avoid serde_json's ".0" suffixing.
fn write_js_float(f: f64, out: &mut String) {
    use std::fmt::Write as _;
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 {
        // Integer-valued and within the i64-exact range: print as an integer.
        // `(-0.0_f64) as i64 == 0`, so negative zero collapses to "0" like JS.
        let _ = write!(out, "{}", f as i64);
    } else {
        // Shortest round-trip; Rust's Display does not append a trailing ".0".
        let _ = write!(out, "{f}");
    }
}

/// Escape a string exactly as `JSON.stringify` does.
fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    // Fast path: no character needs escaping — append the whole slice at once
    // (avoids the per-char loop for the overwhelmingly common clean string).
    if !s.bytes().any(|b| b < 0x20 || b == b'"' || b == b'\\') {
        out.push_str(s);
        out.push('"');
        return;
    }
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0A}' => out.push_str("\\n"),
            '\u{0C}' => out.push_str("\\f"),
            '\u{0D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                // Lowercase 4-digit hex, matching JSON.stringify.
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_and_strips_whitespace() {
        let v = json!({ "b": 1, "a": 2, "c": { "z": 1, "y": 2 } });
        assert_eq!(canonical_json(&v), r#"{"a":2,"b":1,"c":{"y":2,"z":1}}"#);
    }

    #[test]
    fn primitives() {
        assert_eq!(canonical_json(&json!(null)), "null");
        assert_eq!(canonical_json(&json!(true)), "true");
        assert_eq!(canonical_json(&json!(false)), "false");
        assert_eq!(canonical_json(&json!(0)), "0");
        assert_eq!(canonical_json(&json!(-5)), "-5");
        assert_eq!(
            canonical_json(&json!(9007199254740991i64)),
            "9007199254740991"
        );
        assert_eq!(canonical_json(&json!("")), "\"\"");
    }

    #[test]
    fn empty_containers() {
        assert_eq!(canonical_json(&json!({})), "{}");
        assert_eq!(canonical_json(&json!([])), "[]");
    }

    #[test]
    fn escaping_short_forms_and_quotes() {
        assert_eq!(canonical_json(&json!("a\"b")), "\"a\\\"b\"");
        assert_eq!(canonical_json(&json!("a\\b")), "\"a\\\\b\"");
        assert_eq!(canonical_json(&json!("a\nb")), "\"a\\nb\"");
        assert_eq!(canonical_json(&json!("a\tb")), "\"a\\tb\"");
        // Forward slash is NOT escaped.
        assert_eq!(canonical_json(&json!("a/b")), "\"a/b\"");
    }

    #[test]
    fn escaping_non_ascii_is_raw() {
        // "café" — multi-byte UTF-8 emitted verbatim, not \u-escaped.
        let cafe = String::from_utf8(vec![b'c', b'a', b'f', 0xC3, 0xA9]).unwrap();
        assert_eq!(
            canonical_json(&Value::String(cafe.clone())),
            format!("\"{cafe}\"")
        );
    }

    #[test]
    fn escaping_control_char() {
        // U+0001 becomes a lowercase backslash-u escape. The char is built
        // at runtime so no raw control byte appears in this source file.
        let ctrl = char::from_u32(1).unwrap().to_string();
        assert_eq!(canonical_json(&Value::String(ctrl)), "\"\\u0001\"");
    }

    #[test]
    fn integral_floats_drop_decimal() {
        // Parsed from JSON float literals so the Number is an f64.
        assert_eq!(canonical_json(&serde_json::from_str("1.0").unwrap()), "1");
        assert_eq!(
            canonical_json(&serde_json::from_str("100.0").unwrap()),
            "100"
        );
        assert_eq!(canonical_json(&serde_json::from_str("1.5").unwrap()), "1.5");
        assert_eq!(canonical_json(&serde_json::from_str("-0.0").unwrap()), "0");
    }

    /// Pins the current rendering of spec-ILLEGAL numbers (integers above 2^53,
    /// floats, exponential magnitudes). These inputs cannot occur in a valid
    /// Matrix event — strix and scandiaca diverge here, and the proper fix is to
    /// REJECT them at Phase-2 event validation, not to mimic JS `JSON.stringify`.
    /// See `docs/known-divergences.md`. This test exists so any change to the
    /// behavior is deliberate, not accidental.
    #[test]
    fn known_divergence_illegal_numbers_are_pinned() {
        // Integer > 2^53: scandiaca keeps it exact (i64); strix would f64-round it.
        assert_eq!(
            canonical_json(&serde_json::from_str("9007199254740993").unwrap()),
            "9007199254740993"
        );
        // Large/small magnitudes: scandiaca emits full decimal; strix emits
        // ECMAScript exponential (1e+21 / 1e-7).
        assert_eq!(
            canonical_json(&serde_json::from_str("1e21").unwrap()),
            "1000000000000000000000"
        );
        assert_eq!(
            canonical_json(&serde_json::from_str("1e-7").unwrap()),
            "0.0000001"
        );
    }
}
