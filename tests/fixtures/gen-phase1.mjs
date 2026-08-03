// Phase-1 byte-exact test vectors generated from the REAL strix TypeScript
// homeserver source. These pin federation-critical byte parity so the Rust
// port (scandiaca) can verify it produces identical output.
//
// Run from a cwd where strix's node_modules resolve, e.g.:
//   cd /Users/bridger/Developer/matrix/upstream/strix
//   node /Users/bridger/Developer/matrix/upstream/scandiaca/tests/fixtures/gen-phase1.mjs
//
// Everything below is produced by strix's own functions, never hand-computed.

import { writeFileSync } from "node:fs";

// Static imports must be string literals, so the strix src path is hardcoded.
const STRIX = "/Users/bridger/Developer/matrix/upstream/strix/src";

import {
	canonicalJson,
	redactEvent,
	computeContentHash,
	computeEventId,
	computeRoomIdV12,
	isV12CreateEvent,
} from "/Users/bridger/Developer/matrix/upstream/strix/src/events.ts";
import {
	importSigningKey,
	unpaddedBase64,
	unpaddedBase64Decode,
	signJson,
	signEvent,
} from "/Users/bridger/Developer/matrix/upstream/strix/src/signing.ts";

// ---------------------------------------------------------------------------
// Fixed deterministic key material.
// ---------------------------------------------------------------------------
const SERVER_NAME = "test.localhost";
const KEY_ID = "ed25519:test";
const SEED = Buffer.alloc(32, 1); // 32 bytes, each 0x01
const key = importSigningKey(KEY_ID, SEED);

// Replicate strix generateSigningKey's key-id derivation rule on the imported
// key's *raw* public key: 'ed25519:' + first 6 base64url chars of the 32-byte
// public key. We recover the raw public key by decoding the unpadded standard
// base64 strix exposes, then re-encoding base64url.
const rawPub = unpaddedBase64Decode(key.publicKeyBase64);
const pubBase64url = rawPub.toString("base64url");
const alsoDerivedKeyId = `ed25519:${pubBase64url.slice(0, 6)}`;

// ---------------------------------------------------------------------------
// a. canonicalJson cases.
// ---------------------------------------------------------------------------
// A string exercising every escape path: a quote, backslash, forward slash
// (NOT escaped by JSON.stringify), newline, tab, backspace, form-feed, carriage
// return, a raw U+0001 control char, and a non-ASCII char (é).
const escapeString =
	'a"b\\c/d\ne\tf\bg\fh\rijé';

const canonicalCases = [
	// nested objects with keys deliberately out of sorted order
	{ input: { b: 1, a: 2, c: { z: 1, y: 2, x: 3 } } },
	// key sorting with mixed-case and digits (ASCII ordinal sort)
	{
		input: { B: 1, a: 2, A: 3, "10": 4, "2": 5, Z: 6, z: 7, "1": 8 },
	},
	// unicode string values
	{ input: { name: "café", jp: "日本", emoji: "😀🎉" } },
	// strings needing escaping (all escape paths + non-ASCII + raw control char)
	{
		input: { s: escapeString },
		sourceLiteral: 'a"b\\c/d\\ne\\tf\\bg\\fh\\ri\\u0001j\\u00e9',
	},
	// integers: 0, positive, negative, max/min safe int
	{ input: 0 },
	{ input: 42 },
	{ input: -42 },
	{
		input: 9007199254740991,
		comment: "Number.MAX_SAFE_INTEGER (2**53 - 1)",
	},
	{
		input: -9007199254740991,
		comment: "-(2**53 - 1) (Number.MIN_SAFE_INTEGER)",
	},
	// NON-integer numbers — known divergence risk vs Rust serde_json. JS source
	// literals 1.0 and 100.0 are indistinguishable from 1 and 100 and JSON files
	// cannot preserve the trailing .0, so the sourceLiteral field records what was
	// actually fed to strix in the generator source.
	{ input: 1.0, sourceLiteral: "1.0", comment: "JS float literal 1.0" },
	{ input: 1.5, sourceLiteral: "1.5", comment: "JS float literal 1.5" },
	{ input: 100.0, sourceLiteral: "100.0", comment: "JS float literal 100.0" },
	{ input: -0.0, sourceLiteral: "-0.0", comment: "JS negative zero literal" },
	{ input: 3.14159, sourceLiteral: "3.14159" },
	// booleans
	{ input: true },
	{ input: false },
	// null
	{ input: null },
	// empty object / empty array
	{ input: {} },
	{ input: [] },
	// nested arrays
	{ input: [[1, 2], [3, [4, 5]], []] },
	// array of mixed types
	{ input: [1, "two", true, null, { k: "v" }, [9]] },
	// object containing every value kind, keys out of order
	{
		input: {
			zeta: null,
			alpha: [3, 2, 1],
			mid: { nested: true, n: -7 },
			beta: "x",
			"2num": 2,
		},
	},
];

const canonicalJsonOut = canonicalCases.map((c) => {
	const entry = { input: c.input, output: canonicalJson(c.input) };
	if (c.sourceLiteral !== undefined) entry.sourceLiteral = c.sourceLiteral;
	if (c.comment !== undefined) entry.comment = c.comment;
	return entry;
});

// ---------------------------------------------------------------------------
// b. signingKey block.
// ---------------------------------------------------------------------------
const signingKeyOut = {
	seedBase64: SEED.toString("base64"),
	keyId: key.keyId,
	alsoDerivedKeyId,
	publicKeyBase64: key.publicKeyBase64, // unpadded standard base64
	publicKeyBase64url: pubBase64url, // raw public key, full base64url
};

// ---------------------------------------------------------------------------
// c. signJson cases. signJson MUTATES its argument, so clone the input for the
//    record before signing.
// ---------------------------------------------------------------------------
const signJsonInputs = [
	{ label: "empty", obj: {} },
	{ label: "few-keys", obj: { one: 1, two: "2", three: true } },
	{
		label: "with-unsigned-and-signatures",
		obj: {
			a: 1,
			unsigned: { age: 1234, transaction_id: "txn-1" },
			signatures: { "other.server": { "ed25519:abc": "PRE-EXISTING-SIG" } },
		},
	},
	{
		label: "nested-unicode",
		obj: { content: { body: "héllo 日本 😀", nested: { z: 1, a: 2 } }, n: -5 },
	},
];

const signJsonOut = signJsonInputs.map(({ label, obj }) => {
	const input = structuredClone(obj);
	const signed = signJson(obj, SERVER_NAME, key); // mutates obj === signed
	const signatureBase64 = signed.signatures[SERVER_NAME][KEY_ID];
	return { label, input, serverName: SERVER_NAME, keyId: KEY_ID, signatureBase64, signedObject: signed };
});

// ---------------------------------------------------------------------------
// d. events: redaction / content hash / event id, covering version-specific
//    redaction rules.
// ---------------------------------------------------------------------------
const eventSpecs = [
	{
		label: "create_v11",
		roomVersion: "11",
		pdu: {
			auth_events: [],
			content: {
				room_version: "11",
				creator: "@alice:test.localhost",
				"m.federate": true,
				extra_field: "kept-in-v11-full-content",
			},
			depth: 1,
			hashes: { sha256: "STRIPPED" },
			origin_server_ts: 1000,
			prev_events: [],
			room_id: "!room:test.localhost",
			sender: "@alice:test.localhost",
			signatures: { "test.localhost": { "ed25519:test": "STRIPPED" } },
			state_key: "",
			type: "m.room.create",
			unsigned: { age: 5 },
		},
	},
	{
		label: "create_v1_legacy",
		roomVersion: "1",
		pdu: {
			auth_events: [],
			content: {
				creator: "@alice:test.localhost",
				room_version: "1",
				extra_field: "dropped-in-v1-redaction",
			},
			depth: 1,
			hashes: { sha256: "STRIPPED" },
			origin: "test.localhost",
			origin_server_ts: 1000,
			prev_events: [],
			room_id: "!room:test.localhost",
			sender: "@alice:test.localhost",
			signatures: { "test.localhost": { "ed25519:test": "STRIPPED" } },
			state_key: "",
			type: "m.room.create",
		},
	},
	{
		label: "create_v12_msc4291",
		roomVersion: "12",
		// v12 create carries a room_id on the stored PDU (CS-API convenience) but
		// it MUST be stripped from the hashed/redacted form (MSC4291). roomIdV12 is
		// emitted below.
		pdu: {
			auth_events: [],
			content: {
				room_version: "12",
				"m.federate": true,
			},
			depth: 1,
			hashes: { sha256: "STRIPPED" },
			origin_server_ts: 1000,
			prev_events: [],
			room_id: "!should-be-stripped:test.localhost",
			sender: "@alice:test.localhost",
			signatures: { "test.localhost": { "ed25519:test": "STRIPPED" } },
			state_key: "",
			type: "m.room.create",
		},
	},
	{
		label: "member_join_v11",
		roomVersion: "11",
		pdu: {
			auth_events: ["$create", "$pl"],
			content: {
				membership: "join",
				displayname: "Bob",
				avatar_url: "mxc://test.localhost/abc",
				join_authorised_via_users_server: "@authoriser:test.localhost",
				third_party_invite: {
					display_name: "dropped",
					signed: {
						mxid: "@bob:test.localhost",
						token: "tok",
						signatures: { "test.localhost": { "ed25519:test": "sig" } },
					},
				},
			},
			depth: 5,
			hashes: { sha256: "STRIPPED" },
			origin_server_ts: 2000,
			prev_events: ["$prev"],
			room_id: "!room:test.localhost",
			sender: "@bob:test.localhost",
			signatures: { "test.localhost": { "ed25519:test": "STRIPPED" } },
			state_key: "@bob:test.localhost",
			type: "m.room.member",
		},
	},
	{
		label: "member_join_v10_legacy",
		roomVersion: "10",
		// Exercises LEGACY top-level keys prev_state/membership/origin (kept for
		// v1-v10) and v10 content rules: third_party_invite is DROPPED (no updated
		// redaction rules), join_authorised_via_users_server is KEPT (v9+).
		pdu: {
			auth_events: ["$create", "$pl"],
			content: {
				membership: "join",
				displayname: "Bob",
				join_authorised_via_users_server: "@authoriser:test.localhost",
				third_party_invite: {
					signed: { mxid: "@bob:test.localhost", token: "tok" },
				},
			},
			depth: 5,
			hashes: { sha256: "STRIPPED" },
			membership: "join",
			origin: "test.localhost",
			origin_server_ts: 2000,
			prev_events: ["$prev"],
			prev_state: [],
			room_id: "!room:test.localhost",
			sender: "@bob:test.localhost",
			signatures: { "test.localhost": { "ed25519:test": "STRIPPED" } },
			state_key: "@bob:test.localhost",
			type: "m.room.member",
		},
	},
	{
		label: "power_levels_v11",
		roomVersion: "11",
		pdu: {
			auth_events: ["$create", "$pl"],
			content: {
				ban: 50,
				events: { "m.room.name": 100, "m.room.power_levels": 100 },
				events_default: 0,
				invite: 50,
				kick: 50,
				redact: 50,
				state_default: 50,
				users: { "@alice:test.localhost": 100, "@bob:test.localhost": 50 },
				users_default: 0,
				notifications: { room: 50 },
			},
			depth: 3,
			hashes: { sha256: "STRIPPED" },
			origin_server_ts: 1500,
			prev_events: ["$prev"],
			room_id: "!room:test.localhost",
			sender: "@alice:test.localhost",
			signatures: { "test.localhost": { "ed25519:test": "STRIPPED" } },
			state_key: "",
			type: "m.room.power_levels",
		},
	},
	{
		label: "power_levels_v6_legacy",
		roomVersion: "6",
		// v6 has no updated redaction rules → `invite` is DROPPED from the redacted
		// power_levels content (contrast with v11 which keeps it).
		pdu: {
			auth_events: ["$create", "$pl"],
			content: {
				ban: 50,
				events: { "m.room.name": 100 },
				events_default: 0,
				invite: 50,
				kick: 50,
				redact: 50,
				state_default: 50,
				users: { "@alice:test.localhost": 100 },
				users_default: 0,
			},
			depth: 3,
			hashes: { sha256: "STRIPPED" },
			origin: "test.localhost",
			origin_server_ts: 1500,
			prev_events: ["$prev"],
			prev_state: [],
			room_id: "!room:test.localhost",
			sender: "@alice:test.localhost",
			signatures: { "test.localhost": { "ed25519:test": "STRIPPED" } },
			state_key: "",
			type: "m.room.power_levels",
		},
	},
	{
		label: "join_rules_restricted_v11",
		roomVersion: "11",
		pdu: {
			auth_events: ["$create", "$pl"],
			content: {
				join_rule: "restricted",
				allow: [
					{ type: "m.room_membership", room_id: "!space:test.localhost" },
					{ type: "m.room_membership", room_id: "!other:test.localhost" },
				],
				extra: "dropped",
			},
			depth: 4,
			hashes: { sha256: "STRIPPED" },
			origin_server_ts: 1600,
			prev_events: ["$prev"],
			room_id: "!room:test.localhost",
			sender: "@alice:test.localhost",
			signatures: { "test.localhost": { "ed25519:test": "STRIPPED" } },
			state_key: "",
			type: "m.room.join_rules",
		},
	},
	{
		label: "message_v11",
		roomVersion: "11",
		// m.room.message has no redaction case → content is fully stripped to {}.
		pdu: {
			auth_events: ["$create", "$pl", "$member"],
			content: {
				msgtype: "m.text",
				body: "Hello, world! café 日本 😀",
				"m.mentions": { user_ids: ["@alice:test.localhost"] },
			},
			depth: 7,
			hashes: { sha256: "STRIPPED" },
			origin_server_ts: 3000,
			prev_events: ["$prev"],
			room_id: "!room:test.localhost",
			sender: "@bob:test.localhost",
			signatures: { "test.localhost": { "ed25519:test": "STRIPPED" } },
			type: "m.room.message",
			unsigned: { age: 12 },
		},
	},
	{
		label: "redaction_v11",
		roomVersion: "11",
		// v11: `redacts` lives in content and is KEPT; the legacy top-level
		// `redacts` is NOT an allowed top-level key, so it is dropped.
		pdu: {
			auth_events: ["$create", "$pl", "$member"],
			content: { redacts: "$target_event:test.localhost", reason: "spam" },
			depth: 8,
			hashes: { sha256: "STRIPPED" },
			origin_server_ts: 3100,
			prev_events: ["$prev"],
			redacts: "$target_event:test.localhost",
			room_id: "!room:test.localhost",
			sender: "@alice:test.localhost",
			signatures: { "test.localhost": { "ed25519:test": "STRIPPED" } },
			type: "m.room.redaction",
		},
	},
	{
		label: "redaction_v6_legacy",
		roomVersion: "6",
		// v6: no updated redaction rules → content `redacts` is dropped, and the
		// top-level `redacts` is also not an allowed key, so the redacted content
		// is empty {} (strix behavior — recorded faithfully).
		pdu: {
			auth_events: ["$create", "$pl", "$member"],
			content: { reason: "spam" },
			depth: 8,
			hashes: { sha256: "STRIPPED" },
			origin: "test.localhost",
			origin_server_ts: 3100,
			prev_events: ["$prev"],
			prev_state: [],
			redacts: "$target_event:test.localhost",
			room_id: "!room:test.localhost",
			sender: "@alice:test.localhost",
			signatures: { "test.localhost": { "ed25519:test": "STRIPPED" } },
			type: "m.room.redaction",
		},
	},
];

const eventsOut = eventSpecs.map((spec) => {
	const entry = {
		label: spec.label,
		roomVersion: spec.roomVersion,
		pdu: spec.pdu,
		redacted: redactEvent(spec.pdu, spec.roomVersion),
		contentHash: computeContentHash(spec.pdu),
		eventId: computeEventId(spec.pdu, spec.roomVersion),
	};
	if (isV12CreateEvent(spec.pdu)) {
		entry.isV12CreateEvent = true;
		entry.roomIdV12 = computeRoomIdV12(spec.pdu);
	}
	return entry;
});

// ---------------------------------------------------------------------------
// e. signEvent cases (1-2 events).
// ---------------------------------------------------------------------------
const signEventSpecs = [
	{ label: "create_v11", roomVersion: "11", pdu: eventSpecs[0].pdu },
	{ label: "message_v11", roomVersion: "11", pdu: eventSpecs[9].pdu },
];

const signEventOut = signEventSpecs.map(({ label, roomVersion, pdu }) => {
	const signedEvent = signEvent(pdu, SERVER_NAME, key, roomVersion);
	const signatureBase64 = signedEvent.signatures[SERVER_NAME][KEY_ID];
	return { label, roomVersion, pdu, signedEvent, signatureBase64 };
});

// ---------------------------------------------------------------------------
// Assemble + write.
// ---------------------------------------------------------------------------
const out = {
	_meta: {
		description:
			"Byte-exact federation test vectors generated from strix TypeScript source.",
		generator:
			"scandiaca/tests/fixtures/gen-phase1.mjs (imports strix src directly)",
		serverName: SERVER_NAME,
		keyId: KEY_ID,
		seedHex: SEED.toString("hex"),
		strixSrc: STRIX,
	},
	canonicalJson: canonicalJsonOut,
	signingKey: signingKeyOut,
	signJson: signJsonOut,
	events: eventsOut,
	signEvent: signEventOut,
};

const outPath =
	"/Users/bridger/Developer/matrix/upstream/scandiaca/tests/fixtures/phase1.json";
writeFileSync(outPath, `${JSON.stringify(out, null, 2)}\n`);

console.log("wrote", outPath);
console.log("signingKey:", JSON.stringify(signingKeyOut, null, 2));
console.log(
	"canonicalJson count:",
	canonicalJsonOut.length,
	" signJson:",
	signJsonOut.length,
	" events:",
	eventsOut.length,
	" signEvent:",
	signEventOut.length,
);
