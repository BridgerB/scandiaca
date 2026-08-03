//! Request middleware — port of strix `src/middleware/`.
//!
//! CORS lives in [`crate::server`] (applied globally). Rate limiting is here;
//! `federation-auth` and `appservice-auth` arrive with the federation and
//! appservice phases (they depend on the federation client / appservice
//! registrations not yet ported).

pub mod federation_auth;
pub mod rate_limit;
