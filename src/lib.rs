//! scandiaca — a Rust Matrix homeserver, ported from strix (TypeScript).
//!
//! strix is the specification/oracle: scandiaca is correct when it produces
//! byte-identical canonical JSON, content hashes, event IDs, and signatures,
//! and passes the same Complement suite. The federation-critical primitives
//! live in [`canonical_json`], [`events`], [`signing`], and [`state_resolution`]
//! and are validated against test vectors generated from strix's real functions.

pub mod appservice;
pub mod canonical_json;
pub mod crypto;
pub mod crypto_utils;
pub mod errors;
pub mod extract;
pub mod event_filter;
pub mod events;
pub mod federation;
pub mod glob;
pub mod handlers;
pub mod ids;
pub mod ignored;
pub mod invite_filter;
pub mod middleware;
pub mod push_rules;
pub mod relations;
pub mod room_ops;
pub mod search_match;
pub mod server;
pub mod signing;
pub mod state_resolution;
pub mod storage;
pub mod types;
pub mod uiaa;
