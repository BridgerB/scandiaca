# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`scandiaca` is a Matrix homeserver written in Rust — a **port of `strix`** (the TypeScript homeserver at `../strix`). It is an early-phase project: the Client-Server API surface implemented so far is small (register/login/whoami, createRoom, joined_rooms, send event, get state/messages, sync) and only the in-memory storage backend exists. Federation, sqlite, and postgres are planned but not built.

## The one rule that governs everything: strix is the oracle

scandiaca is defined as *correct* when it produces **byte-identical** output to strix for every spec-valid Matrix event: same canonical JSON, content hashes, event IDs, room IDs, and signatures, and it passes the same Complement suite. When changing anything federation-critical (`canonical_json.rs`, `events.rs`, `signing.rs`, `state_resolution.rs`), the target is not "spec-compliant in the abstract" but "matches what strix computes." Cross-check against `../strix/src/` when in doubt.

The exceptions to byte-parity are catalogued in **`docs/known-divergences.md`** — read it before "fixing" any parity mismatch. Every entry there is an *intentional* divergence that only occurs on malformed/spec-illegal input (out-of-range numbers, lone surrogates, non-string `room_version`, non-object `content`, literal `__proto__` keys). Several are deferred to a future Phase-2 event-validation boundary that will *reject* such input rather than emulate strix's lenient `JSON.stringify`. Do not add code to replicate strix's non-spec JS quirks; the plan is to reject the bad input upstream instead.

## Commands

```sh
cargo build                 # build (rust-version 1.85, edition 2021)
cargo run                   # run the server (see env vars below)
cargo test                  # run all tests, including parity suites
cargo test --test phase1_parity          # one integration test file
cargo test canonical_json_parity         # one test by name
cargo clippy
cargo fmt
```

### Running the server

Config is read from the environment (see `src/main.rs`):

- `PORT` (default `8008`), `SERVER_NAME` (default `localhost`)
- `SIGNING_KEY_SEED` — base64 of a 32-byte ed25519 seed; if unset, a fresh key is generated and its seed is printed to stdout so you can persist it. `SIGNING_KEY_ID` (default `ed25519:auto`).
- `STORAGE` — only `memory` is implemented; any other value warns and falls back to memory.

## Parity test fixtures (important, and easy to get wrong)

`tests/phase1_parity.rs` and `tests/phase2_parity.rs` assert scandiaca reproduces expected values in `tests/fixtures/phase{1,2}.json`. **Those JSON fixtures are generated output from strix's real TypeScript functions**, never hand-written. Regenerate them with the `.mjs` scripts, which import strix's source via **hardcoded absolute paths** (`/Users/bridger/Developer/matrix/upstream/strix/src/...`) and must run where strix's `node_modules` resolve:

```sh
cd ../strix
node ../scandiaca/tests/fixtures/gen-phase1.mjs
node ../scandiaca/tests/fixtures/gen-phase2.mjs
```

The generator uses a deterministic test key: seed = 32 bytes of `0x01`, key id `ed25519:test`. If you move the strix checkout, update the hardcoded paths in the `.mjs` files. `phase2.json` is loaded at runtime (not `include_str!`), so `phase2_parity.rs` compiles even when the fixture is absent — the tests fail loudly with "file missing" instead.

## Architecture

Each Rust module names the strix file it ports in its top doc-comment — follow those pointers to find the reference implementation.

- **`src/lib.rs`** — crate root; the module list is the map. `src/main.rs` is the binary entrypoint (port of strix `src/index.ts`).
- **Federation-critical core** (the byte-parity surface): `canonical_json.rs`, `events.rs` (redaction flags, content hash, event id, v12 room id, event build, auth rules), `signing.rs`, `state_resolution.rs`, `crypto.rs`/`crypto_utils.rs`. These operate over untyped `serde_json::Value` on purpose — redaction/hashing must treat an event as an opaque field bag to stay byte-identical to other homeservers.
- **`src/server.rs`** — axum bootstrap. Keeps strix's hand-rolled-router semantics: a global CORS middleware applied to *every* response including errors (a real strix deployment fix), `MatrixError` → JSON, and an `M_UNRECOGNIZED` 404 fallback. `AppState { storage, server_name, signing_key }` is cloned (via `Arc`) into every handler — the equivalent of strix's handler factories. `AuthCtx` is the `requireAuth` extractor (Bearer / `?access_token=`).
- **`src/handlers/`** — Client-Server API endpoints (`auth`, `rooms`, `room_events`, `sync`), each an axum fn capturing deps through `State`.
- **`src/storage/`** — `interface.rs` defines the `Storage` trait. strix has one ~260-method `Storage` interface; the Rust port **splits it into per-domain `#[async_trait]` sub-traits** (account, room, messaging, sync, e2ee, ephemeral, federation, media…) composed into one `Storage` supertrait, used as `Arc<dyn Storage>`. `memory/` is the only backend; each sub-trait is implemented in its own file. Postgres is the planned scale backend, isolated by this split.
- **`src/types/`** — shared types mirroring strix `src/types/` (identifiers, events, e2ee, federation, room_versions, etc.). PDUs/EDUs stay as `Value` where shapes are polymorphic.
