//! Push types — port of the storage-relevant parts of strix `src/types/push.ts`.
//!
//! The push-rules evaluation types (`PushRule`, `PushCondition`, …) arrive with
//! the push-rules engine in Phase 5; storage only needs [`Pusher`].

use serde::{Deserialize, Serialize};

/// HTTP/email push registration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pusher {
    pub pushkey: String,
    /// `"http"` | `"email"` | `null` (null deletes).
    pub kind: Option<String>,
    pub app_id: String,
    pub app_display_name: String,
    pub device_display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_tag: Option<String>,
    pub lang: String,
    pub data: PusherData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub append: Option<bool>,
    /// Internal: the access token that created this pusher (stripped before it is
    /// returned to clients). Used to prune pushers of logged-out sessions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PusherData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brand: Option<String>,
}
