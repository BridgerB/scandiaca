//! Federation (Server-Server API) — port of strix `src/federation/`.
//!
//! Outbound: [`client`] (signed requests), [`discovery`] (destination
//! resolution), [`key_store`] (remote signing-key fetch/verify), [`verify`]
//! (inbound PDU origin-signature verification). Inbound handlers live under
//! `crate::handlers::federation`. SRV-record resolution is deferred (Complement
//! and dev use explicit host:port or `.well-known`); a `host:8448` fallback
//! covers the rest.

pub mod client;
pub mod discovery;
pub mod key_store;
pub mod outbound;
pub mod verify;

pub use client::FederationClient;
