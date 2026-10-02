//! Room-version type — port of strix `src/types/room-versions.ts`.
//!
//! strix uses a string-literal union `"1".."12"`. The Rust port keeps it as a
//! plain `String` (the engine parses the numeric base via
//! [`crate::events::parse_room_version_number`]) so unstable/MSC version strings
//! like `org.matrix.msc3757.10` are representable.

pub type RoomVersion = String;
