//! JSON aliases — port of strix `src/types/json.ts`.
//!
//! `JsonValue` is `serde_json::Value`; `JsonObject` is a JSON object (map). The
//! engine treats event bodies as opaque JSON, exactly like strix.

pub type JsonValue = serde_json::Value;
pub type JsonObject = serde_json::Map<String, serde_json::Value>;
