//! Matrix identifier types — port of strix `src/types/identifiers.ts`.
//!
//! strix uses plain (non-branded) string aliases and casts with `as`. The Rust
//! port uses thin newtypes that are `#[serde(transparent)]` (so they serialize
//! exactly like the underlying string) and `Deref<Target = str>` for ergonomic
//! read access. They carry no validation — like strix, validation happens at the
//! handlers, not the type.

macro_rules! string_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord,
            serde::Serialize, serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            #[inline]
            pub fn as_str(&self) -> &str {
                &self.0
            }
            #[inline]
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl std::ops::Deref for $name {
            type Target = str;
            #[inline]
            fn deref(&self) -> &str {
                &self.0
            }
        }

        impl From<String> for $name {
            #[inline]
            fn from(s: String) -> Self {
                $name(s)
            }
        }

        impl From<&str> for $name {
            #[inline]
            fn from(s: &str) -> Self {
                $name(s.to_string())
            }
        }

        impl AsRef<str> for $name {
            #[inline]
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

string_id! {
    /// `@alice:example.com`
    UserId
}
string_id! {
    /// `!abc123:example.com`
    RoomId
}
string_id! {
    /// `#general:example.com`
    RoomAlias
}
string_id! {
    /// `$event_id` (v4+) or `$base64:example.com` (v1–v3)
    EventId
}
string_id! {
    /// Opaque device identifier.
    DeviceId
}
string_id! {
    /// `example.com` or `example.com:8448`
    ServerName
}
string_id! {
    /// Client-provided transaction ID for idempotency.
    TransactionId
}
string_id! {
    /// `mxc://server/id`
    MxcUri
}
string_id! {
    /// Opaque access token.
    AccessToken
}
string_id! {
    /// Opaque refresh token.
    RefreshToken
}
string_id! {
    /// Key ID in `algorithm:identifier` form, e.g. `ed25519:AABBCC`.
    KeyId
}
string_id! {
    /// Sender ID — a [`UserId`] or a pseudo-ID in rooms that use them.
    SenderId
}

/// Unix timestamp in milliseconds.
pub type Timestamp = i64;

/// Integer stream position for sync tokens.
pub type StreamPosition = i64;

/// Base64-encoded bytes (opaque string).
pub type Base64 = String;
