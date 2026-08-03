//! Application Service (appservice) support — port of strix `src/appservice/`.
//!
//! [`registration`] loads registrations from `APPSERVICE_REGISTRATIONS` and
//! matches users/aliases/tokens against their namespaces; [`push`] delivers
//! matching events to each appservice's transaction endpoint.

pub mod push;
pub mod registration;
