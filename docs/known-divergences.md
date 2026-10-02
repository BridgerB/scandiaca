# Known divergences from strix

scandiaca treats strix as the byte-parity oracle: for every **spec-valid** Matrix
event, the two must produce identical canonical JSON, content hashes, event IDs,
and signatures. The `tests/phase1_parity.rs` suite proves this against 39 vectors
generated from strix's real functions.

This document records the places where scandiaca and strix **intentionally**
diverge. Every entry below was found by an adversarial audit workflow and
**empirically confirmed** by running Node (strix) against Rust (scandiaca). The
unifying fact: **all of them require malformed or spec-illegal input that cannot
occur in a valid federated event.** Where they differ, strix's lenient
`JSON.stringify` departs from the [Matrix canonical JSON spec][canon], and
scandiaca (via `serde_json` + Rust's `String`) usually lands on the *more*
spec-correct side — the same side as Synapse/Dendrite, which reject these inputs.

The audit also **refuted** the highest-risk concerns: string escaping (all C0
controls, DEL, U+2028/U+2029, `/`), UTF-16 supplementary-plane key ordering, and
duplicate-key (last-wins) handling are all confirmed byte-identical to strix
beyond what the fixtures cover.

[canon]: https://spec.matrix.org/latest/appendices/#canonical-json

## Number formatting (canonical JSON)

Matrix canonical JSON permits only integers in `[-(2^53)+1, (2^53)-1]` and
**no floating-point values at all**. strix does not enforce this — it calls
`JSON.stringify` on whatever number it has, so:

| Input | strix (JS) | scandiaca (Rust) | Spec |
|---|---|---|---|
| `9007199254740993` (> 2^53) | `9007199254740992` (f64-rounded at `JSON.parse`) | `9007199254740993` (exact i64) | illegal → reject |
| `1e21` | `1e+21` (ECMAScript exponential) | `1000000000000000000000` | illegal (float) → reject |
| `1e-7` | `1e-7` | `0.0000001` | illegal (float) → reject |
| `1.5` | `1.5` | `1.5` | illegal (float) → reject |

**Disposition:** *deferred to Phase-2 event validation.* The correct fix is not to
replicate strix's `JSON.stringify` (which is itself non-spec), but to **reject**
out-of-range integers and non-integer numbers at the event-ingress boundary, as
Synapse does. Until that lands, scandiaca's exact-integer / shortest-float
rendering is pinned by `canonical_json` tests so any change is deliberate. Valid
events (power levels capped at `2^53-1`, timestamps, depths, counts) are unaffected
and remain byte-identical.

## Lone surrogates in strings

A JSON string containing an unpaired surrogate (e.g. `"\uD800"`): strix's
`JSON.parse` accepts it and canonicalizes it; `serde_json` **rejects it at parse
time** because Rust's `String`/`serde_json::Value` are guaranteed valid UTF-8.

**Disposition:** *accept the divergence.* scandiaca is stricter and spec-aligned
(canonical JSON is defined over valid Unicode); the malformed event is rejected at
the JSON boundary rather than hashed. This matches the behavior of most
homeservers and cannot produce a valid signed event.

## `room_version` given as a non-string

If an `m.room.create` event's `content.room_version` is the JSON **number** `12`
instead of the string `"12"`, strix's `parseInt` coerces it and treats the room as
v12 (stripping `room_id` per MSC4291); scandiaca's `as_str()` returns `None`, so it
is not treated as v12 → divergent content hash / event ID / room ID.

**Disposition:** *deferred to Phase-2 validation.* `room_version` is defined as a
string; a numeric value is malformed and should be rejected before redaction.
Tracked in `is_v12_create_event`.

## `parseInt`-style room-version parsing

`parse_room_version_number` does not fully emulate JS `parseInt(s, 10)`: it does
not skip leading whitespace (`" 12"` → JS `12`, Rust `None`) and does not promote
values above `i64::MAX` to a float. Only reachable with a malformed version string.

**Disposition:** *deferred to Phase-2 validation* (reject malformed versions). The
spec-valid versions `"1".."12"` and the MSC `org.matrix.mscXXXX.N` forms all parse
identically (covered by `events::tests::room_version_parsing`).

## Literal `__proto__` key in `m.room.create` content

In v11+ create-event redaction strix copies content via `Object.assign`, which
silently drops a literal `__proto__` own-key (JS prototype footgun); scandiaca
copies it like any other key. → divergent v12 event ID / room ID for a create
event whose content contains `"__proto__"`.

**Disposition:** *accept the divergence.* scandiaca's behavior (treat `__proto__`
as ordinary data) is the correct one; strix's is a JS-specific bug. Adversarial
input only.

## Non-object `content` on a switch-handled event type

For an `m.room.member` (etc.) event whose `content` is a string/number rather than
an object, strix's redaction throws (`"membership" in "hi"` is a `TypeError`),
which causes the inbound PDU to be **rejected**; scandiaca currently coerces the
missing object to `{}` and redacts to empty content instead of rejecting.

**Disposition:** *deferred to Phase-2 event validation — the one with real
behavioral weight.* The acceptance pipeline (buildEvent / inbound federation
verify) must reject a PDU whose `content` is not a JSON object before redaction,
matching strix's effective "reject malformed" outcome. Tracked as a Phase-2
acceptance-validation requirement.
