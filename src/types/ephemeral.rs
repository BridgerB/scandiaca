//! Ephemeral (non-persisted) types — port of strix `src/types/ephemeral.ts`.

use serde::{Deserialize, Serialize};

/// Presence state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresenceState {
    Online,
    Offline,
    Unavailable,
}
