//! User-facing types — port of strix `src/types/user.ts`.

use serde::{Deserialize, Serialize};

use super::identifiers::{DeviceId, MxcUri, Timestamp};

/// A user's public profile.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UserProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub displayname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<MxcUri>,
}

/// A device as exposed via `/devices`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    pub device_id: DeviceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_ts: Option<Timestamp>,
}
