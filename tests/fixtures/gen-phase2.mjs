// Phase-2 test vectors generated from the REAL strix TypeScript event engine
// (events.ts + state-resolution.ts). Verifies the Rust port (scandiaca)
// reproduces buildEvent / selectAuthEvents / checkEventAuth / resolveState.
//
// Run from a cwd where strix's node_modules resolve:
//   cd /Users/bridger/Developer/matrix/upstream/strix
//   node /Users/bridger/Developer/matrix/upstream/scandiaca/tests/fixtures/gen-phase2.mjs
//
// Everything below is produced by strix's own functions, never hand-computed.

import { writeFileSync } from "node:fs";

import {
	buildEvent,
	selectAuthEvents,
	checkEventAuth,
	makeStateKey,
	computeEventId,
} from "/Users/bridger/Developer/matrix/upstream/strix/src/events.ts";
import { resolveState } from "/Users/bridger/Developer/matrix/upstream/strix/src/state-resolution.ts";
import { importSigningKey } from "/Users/bridger/Developer/matrix/upstream/strix/src/signing.ts";

const SERVER = "test.localhost";
const KEY = importSigningKey("ed25519:test", Buffer.alloc(32, 1));
const alice = "@alice:test.localhost";
const bob = "@bob:test.localhost";
const carol = "@carol:test.localhost";

// --- helpers ---------------------------------------------------------------

// Build a (signed) event, returning { event, eventId }.
function build(p) {
	return buildEvent({
		roomId: p.roomId,
		sender: p.sender,
		type: p.type,
		content: p.content,
		stateKey: p.stateKey,
		depth: p.depth,
		prevEvents: p.prevEvents ?? [],
		authEvents: p.authEvents ?? [],
		redacts: p.redacts,
		unsigned: p.unsigned,
		serverName: SERVER,
		signingKey: KEY,
		roomVersion: p.roomVersion,
		originServerTs: p.originServerTs,
	});
}

function stateMapOf(events) {
	const m = new Map();
	for (const e of events) {
		m.set(makeStateKey(e.event.type, e.event.state_key ?? ""), e.event);
	}
	return m;
}

function serializeRoom(rs) {
	return {
		room_id: rs.room_id,
		room_version: rs.room_version,
		state_events: Object.fromEntries(rs.state_events),
		depth: rs.depth,
		forward_extremities: rs.forward_extremities,
	};
}

// Build a base room. Returns the built events + a live RoomState.
function baseRoom(rv, roomId, plContent, joinRule = "public") {
	let ts = 1000;
	const create = build({
		roomId,
		sender: alice,
		type: "m.room.create",
		content: rv === "12" ? { room_version: rv } : { room_version: rv },
		stateKey: "",
		depth: 1,
		roomVersion: rv,
		originServerTs: ts++,
	});
	const inV12 = rv === "12";
	const aliceJoin = build({
		roomId,
		sender: alice,
		type: "m.room.member",
		content: { membership: "join" },
		stateKey: alice,
		depth: 2,
		prevEvents: [create.eventId],
		authEvents: inV12 ? [] : [create.eventId],
		roomVersion: rv,
		originServerTs: ts++,
	});
	const pl = build({
		roomId,
		sender: alice,
		type: "m.room.power_levels",
		content: plContent,
		stateKey: "",
		depth: 3,
		prevEvents: [aliceJoin.eventId],
		authEvents: inV12
			? [aliceJoin.eventId]
			: [create.eventId, aliceJoin.eventId],
		roomVersion: rv,
		originServerTs: ts++,
	});
	const jr = build({
		roomId,
		sender: alice,
		type: "m.room.join_rules",
		content: { join_rule: joinRule },
		stateKey: "",
		depth: 4,
		prevEvents: [pl.eventId],
		authEvents: inV12
			? [aliceJoin.eventId, pl.eventId]
			: [create.eventId, aliceJoin.eventId, pl.eventId],
		roomVersion: rv,
		originServerTs: ts++,
	});
	const events = { create, aliceJoin, pl, jr };
	const roomState = {
		room_id: roomId,
		room_version: rv,
		state_events: stateMapOf([create, aliceJoin, pl, jr]),
		depth: 4,
		forward_extremities: [jr.eventId],
	};
	return { events, roomState, lastTs: ts };
}

const DEFAULT_PL = {
	users: { [alice]: 100 },
	users_default: 0,
	events_default: 0,
	state_default: 50,
	ban: 50,
	kick: 50,
	redact: 50,
	invite: 0,
};

const fixtures = {
	_meta: {
		description: "Phase-2 vectors from strix events.ts + state-resolution.ts",
		server: SERVER,
		keyId: "ed25519:test",
	},
	buildEvent: [],
	selectAuthEvents: [],
	checkEventAuth: [],
	resolveState: [],
};

// ===========================================================================
// 1. buildEvent
// ===========================================================================
function buildCase(label, params) {
	const { signingKey, ...rest } = params;
	const recorded = { ...rest };
	if (signingKey) recorded.signed = true;
	const { event, eventId } = buildEvent(params);
	return { label, params: recorded, event, eventId };
}

fixtures.buildEvent.push(
	buildCase("create_v11_signed", {
		roomId: "!r:test.localhost",
		sender: alice,
		type: "m.room.create",
		content: { room_version: "11" },
		stateKey: "",
		depth: 1,
		prevEvents: [],
		authEvents: [],
		serverName: SERVER,
		signingKey: KEY,
		roomVersion: "11",
		originServerTs: 5000,
	}),
);
fixtures.buildEvent.push(
	buildCase("create_v12_signed", {
		roomId: "!r12:test.localhost",
		sender: alice,
		type: "m.room.create",
		content: { room_version: "12" },
		stateKey: "",
		depth: 1,
		prevEvents: [],
		authEvents: [],
		serverName: SERVER,
		signingKey: KEY,
		roomVersion: "12",
		originServerTs: 5001,
	}),
);
fixtures.buildEvent.push(
	buildCase("message_v11_signed", {
		roomId: "!r:test.localhost",
		sender: alice,
		type: "m.room.message",
		content: { msgtype: "m.text", body: "hello" },
		depth: 5,
		prevEvents: ["$prev"],
		authEvents: ["$c", "$pl", "$m"],
		serverName: SERVER,
		signingKey: KEY,
		roomVersion: "11",
		originServerTs: 5002,
	}),
);
fixtures.buildEvent.push(
	buildCase("member_join_v11_signed", {
		roomId: "!r:test.localhost",
		sender: bob,
		type: "m.room.member",
		content: { membership: "join", displayname: "Bob" },
		stateKey: bob,
		depth: 6,
		prevEvents: ["$prev"],
		authEvents: ["$c", "$pl", "$jr"],
		serverName: SERVER,
		signingKey: KEY,
		roomVersion: "11",
		originServerTs: 5003,
	}),
);
fixtures.buildEvent.push(
	buildCase("message_v11_unsigned", {
		roomId: "!r:test.localhost",
		sender: alice,
		type: "m.room.message",
		content: { msgtype: "m.text", body: "unsigned" },
		depth: 7,
		prevEvents: ["$prev"],
		authEvents: ["$c", "$pl", "$m"],
		serverName: SERVER,
		roomVersion: "11",
		originServerTs: 5004,
	}),
);

// ===========================================================================
// 2. selectAuthEvents
// ===========================================================================
{
	const v11 = baseRoom("11", "!sel11:test.localhost", DEFAULT_PL);
	fixtures.selectAuthEvents.push({
		label: "message_v11",
		roomState: serializeRoom(v11.roomState),
		eventType: "m.room.message",
		sender: alice,
		content: {},
		authEvents: selectAuthEvents("m.room.message", undefined, v11.roomState, alice, {}),
	});

	const v12 = baseRoom("12", "!sel12:test.localhost", DEFAULT_PL);
	fixtures.selectAuthEvents.push({
		label: "message_v12_no_create",
		roomState: serializeRoom(v12.roomState),
		eventType: "m.room.message",
		sender: alice,
		content: {},
		authEvents: selectAuthEvents("m.room.message", undefined, v12.roomState, alice, {}),
	});

	// restricted join with authorising user (carol joined).
	const restricted = baseRoom("11", "!selr:test.localhost", DEFAULT_PL, "restricted");
	const carolJoin = build({
		roomId: "!selr:test.localhost",
		sender: carol,
		type: "m.room.member",
		content: { membership: "join" },
		stateKey: carol,
		depth: 5,
		roomVersion: "11",
		originServerTs: 1100,
	});
	restricted.roomState.state_events.set(makeStateKey("m.room.member", carol), carolJoin.event);
	const joinContent = { membership: "join", join_authorised_via_users_server: carol };
	fixtures.selectAuthEvents.push({
		label: "restricted_join_with_authoriser",
		roomState: serializeRoom(restricted.roomState),
		eventType: "m.room.member",
		stateKey: bob,
		sender: bob,
		content: joinContent,
		authEvents: selectAuthEvents("m.room.member", bob, restricted.roomState, bob, joinContent),
	});
}

// ===========================================================================
// 3. checkEventAuth
// ===========================================================================
function authCase(label, event, roomState) {
	let result;
	try {
		checkEventAuth(event, "$ignored", roomState);
		result = { ok: true };
	} catch (e) {
		result = { ok: false, errcode: e.errcode, error: e.error };
	}
	return { label, roomState: serializeRoom(roomState), event, result };
}

{
	const r = baseRoom("11", "!auth1:test.localhost", DEFAULT_PL); // public room
	// alice (joined) sends a message → ok
	const msg = build({
		roomId: r.roomState.room_id,
		sender: alice,
		type: "m.room.message",
		content: { body: "hi" },
		depth: 5,
		roomVersion: "11",
		originServerTs: 2000,
	});
	fixtures.checkEventAuth.push(authCase("message_by_joined_ok", msg.event, r.roomState));

	// bob (not a member) sends a message → forbidden
	const msgBob = build({
		roomId: r.roomState.room_id,
		sender: bob,
		type: "m.room.message",
		content: { body: "hi" },
		depth: 5,
		roomVersion: "11",
		originServerTs: 2001,
	});
	fixtures.checkEventAuth.push(authCase("message_by_nonmember_forbidden", msgBob.event, r.roomState));

	// second create into a non-empty room → bad_json
	const create2 = build({
		roomId: r.roomState.room_id,
		sender: alice,
		type: "m.room.create",
		content: { room_version: "11" },
		stateKey: "",
		depth: 5,
		roomVersion: "11",
		originServerTs: 2002,
	});
	fixtures.checkEventAuth.push(authCase("second_create_badjson", create2.event, r.roomState));

	// alice invites bob → ok
	const invite = build({
		roomId: r.roomState.room_id,
		sender: alice,
		type: "m.room.member",
		content: { membership: "invite" },
		stateKey: bob,
		depth: 5,
		roomVersion: "11",
		originServerTs: 2003,
	});
	fixtures.checkEventAuth.push(authCase("invite_by_joined_ok", invite.event, r.roomState));

	// bob (not member) invites carol → forbidden
	const inviteBob = build({
		roomId: r.roomState.room_id,
		sender: bob,
		type: "m.room.member",
		content: { membership: "invite" },
		stateKey: carol,
		depth: 5,
		roomVersion: "11",
		originServerTs: 2004,
	});
	fixtures.checkEventAuth.push(authCase("invite_by_nonmember_forbidden", inviteBob.event, r.roomState));

	// power_levels with a non-integer value (v11 ⇒ v10+) → bad_json
	const badPl = build({
		roomId: r.roomState.room_id,
		sender: alice,
		type: "m.room.power_levels",
		content: { ...DEFAULT_PL, users_default: 0.5 },
		stateKey: "",
		depth: 5,
		roomVersion: "11",
		originServerTs: 2005,
	});
	fixtures.checkEventAuth.push(authCase("noninteger_pl_badjson", badPl.event, r.roomState));

	// join to a public room → ok
	const joinPub = build({
		roomId: r.roomState.room_id,
		sender: bob,
		type: "m.room.member",
		content: { membership: "join" },
		stateKey: bob,
		depth: 5,
		roomVersion: "11",
		originServerTs: 2006,
	});
	fixtures.checkEventAuth.push(authCase("join_public_ok", joinPub.event, r.roomState));

	// set another user's state without MSC3757 → forbidden
	const otherState = build({
		roomId: r.roomState.room_id,
		sender: alice,
		type: "m.room.member",
		content: { foo: "bar" },
		stateKey: bob,
		depth: 5,
		roomVersion: "11",
		originServerTs: 2007,
	});
	// member events go through membership auth; use a non-member state type instead:
	const otherState2 = build({
		roomId: r.roomState.room_id,
		sender: alice,
		type: "com.example.state",
		content: { foo: "bar" },
		stateKey: bob,
		depth: 5,
		roomVersion: "11",
		originServerTs: 2008,
	});
	fixtures.checkEventAuth.push(authCase("set_others_state_forbidden", otherState2.event, r.roomState));
}

{
	// invite-only room: bob joins with no invite → forbidden
	const inv = baseRoom("11", "!auth2:test.localhost", DEFAULT_PL, "invite");
	const joinNoInvite = build({
		roomId: inv.roomState.room_id,
		sender: bob,
		type: "m.room.member",
		content: { membership: "join" },
		stateKey: bob,
		depth: 5,
		roomVersion: "11",
		originServerTs: 2100,
	});
	fixtures.checkEventAuth.push(authCase("join_inviteonly_forbidden", joinNoInvite.event, inv.roomState));
}

{
	// kick scenarios: alice & bob both joined.
	const r = baseRoom("11", "!auth3:test.localhost", {
		...DEFAULT_PL,
		users: { [alice]: 100, [bob]: 100 },
	});
	const bobJoin = build({
		roomId: r.roomState.room_id,
		sender: bob,
		type: "m.room.member",
		content: { membership: "join" },
		stateKey: bob,
		depth: 5,
		roomVersion: "11",
		originServerTs: 2200,
	});
	r.roomState.state_events.set(makeStateKey("m.room.member", bob), bobJoin.event);
	// alice (PL 100) kicks bob (PL 100): sender_pl <= target_pl → forbidden
	const kickEqual = build({
		roomId: r.roomState.room_id,
		sender: alice,
		type: "m.room.member",
		content: { membership: "leave" },
		stateKey: bob,
		depth: 6,
		roomVersion: "11",
		originServerTs: 2201,
	});
	fixtures.checkEventAuth.push(authCase("kick_equal_pl_forbidden", kickEqual.event, r.roomState));

	// now bob at PL 0: alice kicks bob → ok
	const r2 = baseRoom("11", "!auth4:test.localhost", {
		...DEFAULT_PL,
		users: { [alice]: 100, [bob]: 0 },
	});
	r2.roomState.state_events.set(makeStateKey("m.room.member", bob), bobJoin.event);
	const kickOk = build({
		roomId: r2.roomState.room_id,
		sender: alice,
		type: "m.room.member",
		content: { membership: "leave" },
		stateKey: bob,
		depth: 6,
		roomVersion: "11",
		originServerTs: 2202,
	});
	fixtures.checkEventAuth.push(authCase("kick_lower_pl_ok", kickOk.event, r2.roomState));
}

{
	// v12 room: power_levels listing the creator in content.users → bad_json
	const v12 = baseRoom("12", "!auth12:test.localhost", DEFAULT_PL);
	const plCreator = build({
		roomId: v12.roomState.room_id,
		sender: alice,
		type: "m.room.power_levels",
		content: { users: { [alice]: 100 }, users_default: 0 },
		stateKey: "",
		depth: 5,
		roomVersion: "12",
		originServerTs: 2300,
	});
	fixtures.checkEventAuth.push(authCase("v12_creator_in_users_badjson", plCreator.event, v12.roomState));
}

// ===========================================================================
// 4. resolveState
// ===========================================================================
function resolveCase(label, rv, forks, authEventsList, roomState) {
	const authMap = new Map();
	for (const e of authEventsList) {
		authMap.set(computeEventId(e, rv), e);
	}
	const resolved = resolveState(forks, authMap, roomState, rv);
	return {
		label,
		roomVersion: rv,
		stateAtForks: forks.map((f) => Object.fromEntries(f)),
		authEvents: Object.fromEntries(authMap),
		roomState: serializeRoom(roomState),
		resolved: Object.fromEntries(resolved),
	};
}

{
	// (a) single fork passthrough
	const r = baseRoom("11", "!res1:test.localhost", DEFAULT_PL);
	const fork = new Map(r.roomState.state_events);
	fixtures.resolveState.push(
		resolveCase(
			"single_fork_passthrough",
			"11",
			[fork],
			[r.events.create.event, r.events.aliceJoin.event, r.events.pl.event, r.events.jr.event],
			r.roomState,
		),
	);
}

{
	// (b) conflict on m.room.name (non-power → mainline)
	const roomId = "!res2:test.localhost";
	const r = baseRoom("11", roomId, DEFAULT_PL);
	const authChain = [r.events.create.eventId, r.events.aliceJoin.eventId, r.events.pl.eventId];
	const nameA = build({
		roomId,
		sender: alice,
		type: "m.room.name",
		content: { name: "Room A" },
		stateKey: "",
		depth: 5,
		authEvents: authChain,
		roomVersion: "11",
		originServerTs: 3000,
	});
	const nameB = build({
		roomId,
		sender: alice,
		type: "m.room.name",
		content: { name: "Room B" },
		stateKey: "",
		depth: 5,
		authEvents: authChain,
		roomVersion: "11",
		originServerTs: 3001,
	});
	const base = r.roomState.state_events;
	const fork1 = new Map(base);
	fork1.set(makeStateKey("m.room.name", ""), nameA.event);
	const fork2 = new Map(base);
	fork2.set(makeStateKey("m.room.name", ""), nameB.event);
	fixtures.resolveState.push(
		resolveCase(
			"conflict_name_mainline",
			"11",
			[fork1, fork2],
			[
				r.events.create.event,
				r.events.aliceJoin.event,
				r.events.pl.event,
				r.events.jr.event,
				nameA.event,
				nameB.event,
			],
			r.roomState,
		),
	);
}

{
	// (c) conflict on m.room.power_levels (power → reverse-topo sort)
	const roomId = "!res3:test.localhost";
	const r = baseRoom("11", roomId, DEFAULT_PL);
	const plAuth = [r.events.create.eventId, r.events.aliceJoin.eventId, r.events.pl.eventId];
	const plA = build({
		roomId,
		sender: alice,
		type: "m.room.power_levels",
		content: { ...DEFAULT_PL, events_default: 10 },
		stateKey: "",
		depth: 5,
		authEvents: plAuth,
		roomVersion: "11",
		originServerTs: 3100,
	});
	const plB = build({
		roomId,
		sender: alice,
		type: "m.room.power_levels",
		content: { ...DEFAULT_PL, events_default: 20 },
		stateKey: "",
		depth: 5,
		authEvents: plAuth,
		roomVersion: "11",
		originServerTs: 3101,
	});
	const base = r.roomState.state_events;
	const fork1 = new Map(base);
	fork1.set(makeStateKey("m.room.power_levels", ""), plA.event);
	const fork2 = new Map(base);
	fork2.set(makeStateKey("m.room.power_levels", ""), plB.event);
	fixtures.resolveState.push(
		resolveCase(
			"conflict_power_levels",
			"11",
			[fork1, fork2],
			[
				r.events.create.event,
				r.events.aliceJoin.event,
				r.events.pl.event,
				r.events.jr.event,
				plA.event,
				plB.event,
			],
			r.roomState,
		),
	);
}

{
	// (d) v12 conflict (v2.1: empty-set start + conflicted subgraph)
	const roomId = "!res12:test.localhost";
	const r = baseRoom("12", roomId, DEFAULT_PL);
	const nameAuth = [r.events.aliceJoin.eventId, r.events.pl.eventId];
	const nameA = build({
		roomId,
		sender: alice,
		type: "m.room.name",
		content: { name: "V12 A" },
		stateKey: "",
		depth: 5,
		authEvents: nameAuth,
		roomVersion: "12",
		originServerTs: 3200,
	});
	const nameB = build({
		roomId,
		sender: alice,
		type: "m.room.name",
		content: { name: "V12 B" },
		stateKey: "",
		depth: 5,
		authEvents: nameAuth,
		roomVersion: "12",
		originServerTs: 3201,
	});
	const base = r.roomState.state_events;
	const fork1 = new Map(base);
	fork1.set(makeStateKey("m.room.name", ""), nameA.event);
	const fork2 = new Map(base);
	fork2.set(makeStateKey("m.room.name", ""), nameB.event);
	fixtures.resolveState.push(
		resolveCase(
			"conflict_name_v12",
			"12",
			[fork1, fork2],
			[
				r.events.create.event,
				r.events.aliceJoin.event,
				r.events.pl.event,
				r.events.jr.event,
				nameA.event,
				nameB.event,
			],
			r.roomState,
		),
	);
}

const OUT = "/Users/bridger/Developer/matrix/upstream/scandiaca/tests/fixtures/phase2.json";
writeFileSync(OUT, `${JSON.stringify(fixtures, null, 2)}\n`);
console.log(`wrote ${OUT}`);
console.log(
	`buildEvent=${fixtures.buildEvent.length} selectAuthEvents=${fixtures.selectAuthEvents.length} checkEventAuth=${fixtures.checkEventAuth.length} resolveState=${fixtures.resolveState.length}`,
);
for (const c of fixtures.checkEventAuth) {
	console.log(`  auth ${c.label}: ${JSON.stringify(c.result)}`);
}
for (const c of fixtures.resolveState) {
	console.log(`  resolve ${c.label}: keys=${Object.keys(c.resolved).length}`);
}
