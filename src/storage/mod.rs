//! Storage layer — the `Storage` trait and its backends.
//!
//! strix ships four backends at parity (memory/sqlite/postgres/mysql). The Rust
//! port starts with memory + sqlite; Postgres (the real scale backend) is the
//! next priority once the server runs end-to-end.

pub mod interface;
pub mod memory;
pub mod sqlite;

pub use interface::*;
pub use memory::{create_memory_storage, MemoryStorage};
pub use sqlite::create_sqlite_storage;
