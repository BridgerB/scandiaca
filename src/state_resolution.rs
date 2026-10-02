//! State Resolution v2 / v2.1 — port of strix `src/state-resolution.ts`.
//!
//! [`resolve_state`] reconciles conflicting room state across forks. v2.0 (room
//! versions 2–11) starts the iterative auth-check phase from the unconflicted
//! state; v2.1 (v12+, MSC4297) expands candidates with the conflicted subgraph
//! and starts from the empty set, auth-checking each candidate against a base
//! built from its own `auth_events`. The output must match strix's so federating
//! servers agree on room state.
//!
//! Events are raw [`Value`]s, like strix's plain objects.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::Value;

use crate::events::{
    check_event_auth, compute_event_id, content_get, ev_auth_events, ev_origin_server_ts,
    ev_sender, ev_state_key, ev_type, is_room_version_12_plus, make_state_key, CREATOR_POWER_LEVEL,
};
use crate::types::internal::{RoomState, StateEvents};

/// Map of event id → event, used throughout resolution.
type EventMap = HashMap<String, Value>;

/// Whether an event is a "power event" (Synapse `_is_power_event`):
/// power_levels / join_rules / create with empty state_key, or a member event
/// that is a kick/ban of another user.
fn is_power_event(event: &Value) -> bool {
    if ev_state_key(event) == Some("") {
        let t = ev_type(event);
        if t == "m.room.power_levels" || t == "m.room.join_rules" || t == "m.room.create" {
            return true;
        }
    }
    if ev_type(event) == "m.room.member" {
        if let Some(membership) = content_get(event, "membership").and_then(Value::as_str) {
            if membership == "leave" || membership == "ban" {
                return ev_sender(event) != ev_state_key(event).unwrap_or("");
            }
        }
    }
    false
}

/// Power level of an event's sender, computed from the event's OWN `auth_events`
/// (Synapse `_get_power_level_for_sender`), not from running state.
fn get_power_level_for_sender(
    event: &Value,
    auth_event_map: &EventMap,
    room_version: Option<&str>,
    create_event: Option<&Value>,
) -> f64 {
    let mut pl_event: Option<&Value> = None;
    let mut create: Option<&Value> = create_event;
    for aid in ev_auth_events(event) {
        if let Some(aev) = auth_event_map.get(aid) {
            if ev_type(aev) == "m.room.power_levels" && ev_state_key(aev) == Some("") {
                pl_event = Some(aev);
            }
            if ev_type(aev) == "m.room.create" && ev_state_key(aev) == Some("") {
                create = Some(aev);
            }
        }
    }

    let sender = ev_sender(event);

    // v12+: room creators hold an implicit infinite power level (MSC4289).
    if is_room_version_12_plus(room_version) {
        if let Some(c) = create {
            let is_creator = ev_sender(c) == sender
                || content_get(c, "additional_creators")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().any(|v| v.as_str() == Some(sender)))
                    .unwrap_or(false);
            if is_creator {
                return CREATOR_POWER_LEVEL;
            }
        }
    }

    match pl_event {
        None => {
            if let Some(c) = create {
                if ev_sender(c) == sender {
                    return 100.0;
                }
            }
            0.0
        }
        Some(plev) => {
            if let Some(level) = content_get(plev, "users")
                .and_then(Value::as_object)
                .and_then(|users| users.get(sender))
                .and_then(Value::as_f64)
            {
                return level;
            }
            content_get(plev, "users_default")
                .and_then(Value::as_f64)
                .unwrap_or(0.0)
        }
    }
}

/// Build the auth-chain subgraph restricted to events in `full_conflicted_set`.
/// Returns `event_id -> its in-set auth_events` (out-edges for the topo sort).
fn build_power_graph(
    event_ids: &[String],
    auth_event_map: &EventMap,
    full_conflicted_set: &HashSet<String>,
) -> HashMap<String, HashSet<String>> {
    let mut graph: HashMap<String, HashSet<String>> = HashMap::new();
    for start_id in event_ids {
        let mut stack = vec![start_id.clone()];
        while let Some(eid) = stack.pop() {
            graph.entry(eid.clone()).or_default();
            let Some(event) = auth_event_map.get(&eid) else {
                continue;
            };
            let in_set: Vec<String> = ev_auth_events(event)
                .into_iter()
                .filter(|aid| full_conflicted_set.contains(*aid))
                .map(str::to_string)
                .collect();
            for aid in in_set {
                if !graph.contains_key(&aid) {
                    stack.push(aid.clone());
                }
                graph.get_mut(&eid).unwrap().insert(aid);
            }
        }
    }
    graph
}

/// Tie-break ordering for the power sort: higher PL first, then `origin_server_ts`
/// ascending, then event id ascending. Returns true if `a` sorts before `b`.
fn pq_less(
    a: &str,
    b: &str,
    power_level: &HashMap<String, f64>,
    auth_event_map: &EventMap,
) -> bool {
    let pl_a = *power_level.get(a).unwrap_or(&0.0);
    let pl_b = *power_level.get(b).unwrap_or(&0.0);
    if pl_a != pl_b {
        return pl_a > pl_b;
    }
    let ts_a = auth_event_map.get(a).map(ev_origin_server_ts).unwrap_or(0);
    let ts_b = auth_event_map.get(b).map(ev_origin_server_ts).unwrap_or(0);
    if ts_a != ts_b {
        return ts_a < ts_b;
    }
    a < b
}

/// Lexicographical reverse-topological power sort (Synapse
/// `_reverse_topological_power_sort`).
fn reverse_topological_power_sort(
    event_ids: &[String],
    auth_event_map: &EventMap,
    full_conflicted_set: &HashSet<String>,
    room_version: Option<&str>,
    create_event: Option<&Value>,
) -> Vec<String> {
    let graph = build_power_graph(event_ids, auth_event_map, full_conflicted_set);

    let mut power_level: HashMap<String, f64> = HashMap::new();
    for id in graph.keys() {
        let pl = auth_event_map
            .get(id)
            .map(|ev| get_power_level_for_sender(ev, auth_event_map, room_version, create_event))
            .unwrap_or(0.0);
        power_level.insert(id.clone(), pl);
    }

    // reverse_graph[node] = parents; outdegree[node] = its out-edges.
    let mut reverse_graph: HashMap<String, HashSet<String>> = HashMap::new();
    let mut outdegree: HashMap<String, HashSet<String>> = HashMap::new();
    for (node, edges) in &graph {
        reverse_graph.entry(node.clone()).or_default();
        outdegree.insert(node.clone(), edges.clone());
        for edge in edges {
            reverse_graph
                .entry(edge.clone())
                .or_default()
                .insert(node.clone());
        }
    }

    let enqueue = |queue: &mut Vec<String>, id: String| {
        let pos = queue.partition_point(|x| pq_less(x, &id, &power_level, auth_event_map));
        queue.insert(pos, id);
    };

    let mut queue: Vec<String> = Vec::new();
    for (node, edges) in &outdegree {
        if edges.is_empty() {
            enqueue(&mut queue, node.clone());
        }
    }

    let mut sorted: Vec<String> = Vec::new();
    while !queue.is_empty() {
        let node = queue.remove(0);
        sorted.push(node.clone());
        if let Some(parents) = reverse_graph.get(&node).cloned() {
            for parent in parents {
                if let Some(out) = outdegree.get_mut(&parent) {
                    out.remove(&node);
                    if out.is_empty() {
                        enqueue(&mut queue, parent.clone());
                    }
                }
            }
        }
    }

    sorted
}

/// Mainline ordering for the non-power "leftover" events (Synapse `_mainline_sort`).
fn mainline_sort(
    event_ids: &[String],
    resolved_power_level_id: Option<&str>,
    auth_event_map: &EventMap,
    room_version: Option<&str>,
) -> Vec<String> {
    if event_ids.is_empty() {
        return Vec::new();
    }

    // Build the mainline: resolved PL → its PL ancestor → ... → root.
    let mut mainline: Vec<String> = Vec::new();
    let mut pl_id: Option<String> = resolved_power_level_id.map(str::to_string);
    let mut guard_seen: HashSet<String> = HashSet::new();
    while let Some(pid) = pl_id.take() {
        if guard_seen.contains(&pid) {
            break;
        }
        guard_seen.insert(pid.clone());
        mainline.push(pid.clone());
        if let Some(plev) = auth_event_map.get(&pid) {
            for aid in ev_auth_events(plev) {
                if let Some(aev) = auth_event_map.get(aid) {
                    if ev_type(aev) == "m.room.power_levels" && ev_state_key(aev) == Some("") {
                        pl_id = Some(aid.to_string());
                        break;
                    }
                }
            }
        }
    }

    // mainline_map: event_id → depth (1-based from the root end).
    let mut mainline_map: HashMap<String, i64> = HashMap::new();
    for (i, id) in mainline.iter().rev().enumerate() {
        mainline_map.insert(id.clone(), (i as i64) + 1);
    }

    let mainline_depth = |event: &Value| -> i64 {
        let mut tmp: Option<&Value> = Some(event);
        let mut seen: HashSet<String> = HashSet::new();
        while let Some(ev) = tmp {
            let id = compute_event_id(ev, room_version);
            if let Some(depth) = mainline_map.get(&id) {
                return *depth;
            }
            if seen.contains(&id) {
                break;
            }
            seen.insert(id);
            let mut next: Option<&Value> = None;
            for aid in ev_auth_events(ev) {
                if let Some(aev) = auth_event_map.get(aid) {
                    if ev_type(aev) == "m.room.power_levels" && ev_state_key(aev) == Some("") {
                        next = Some(aev);
                        break;
                    }
                }
            }
            tmp = next;
        }
        0
    };

    let mut order: HashMap<String, (i64, i64)> = HashMap::new();
    for id in event_ids {
        let (depth, ts) = match auth_event_map.get(id) {
            Some(ev) => (mainline_depth(ev), ev_origin_server_ts(ev)),
            None => (0, 0),
        };
        order.insert(id.clone(), (depth, ts));
    }

    let mut result = event_ids.to_vec();
    result.sort_by(|a, b| {
        let oa = order.get(a).copied().unwrap_or((0, 0));
        let ob = order.get(b).copied().unwrap_or((0, 0));
        oa.0.cmp(&ob.0).then(oa.1.cmp(&ob.1)).then_with(|| a.cmp(b))
    });
    result
}

/// Apply sorted candidate events onto `resolved_state`, keeping each only if it
/// passes auth (Synapse `_iterative_auth_checks`).
#[allow(clippy::too_many_arguments)]
fn apply_events(
    event_ids: &[String],
    room_state: &RoomState,
    resolved_state: &mut StateEvents,
    auth_event_map: &EventMap,
    use_auth_event_base: bool,
    create_event: Option<&Value>,
    _room_version: Option<&str>,
) {
    for event_id in event_ids {
        let Some(event) = auth_event_map.get(event_id) else {
            continue;
        };
        let Some(state_key) = ev_state_key(event) else {
            continue;
        };
        let key = make_state_key(ev_type(event), state_key);

        let mut base: StateEvents = BTreeMap::new();
        if use_auth_event_base {
            // The create event is unconflicted and required for v12+ auth rules,
            // but is not in any v12+ auth_events, so seed it explicitly.
            if let Some(c) = create_event {
                base.insert(make_state_key("m.room.create", ""), c.clone());
            }
            for auth_id in ev_auth_events(event) {
                if let Some(auth_event) = auth_event_map.get(auth_id) {
                    if let Some(ask) = ev_state_key(auth_event) {
                        base.insert(make_state_key(ev_type(auth_event), ask), auth_event.clone());
                    }
                }
            }
        }
        // The running resolved state takes priority.
        for (k, v) in resolved_state.iter() {
            base.insert(k.clone(), v.clone());
        }

        let test_state = RoomState {
            room_id: room_state.room_id.clone(),
            room_version: room_state.room_version.clone(),
            state_events: base,
            depth: room_state.depth,
            forward_extremities: room_state.forward_extremities.clone(),
            state_event_ids: std::collections::BTreeMap::new(),
        };

        if check_event_auth(event, &test_state).is_ok() {
            resolved_state.insert(key, event.clone());
        }
    }
}

/// Compute the conflicted subgraph (MSC4297 / v2.1): every event on a path
/// between two conflicted events, down to a common ancestor.
fn compute_conflicted_subgraph(
    conflicted_ids: &HashSet<String>,
    auth_event_map: &EventMap,
) -> HashSet<String> {
    struct Frame {
        event_id: String,
        remaining: Vec<String>,
    }

    let mut subgraph: HashSet<String> = HashSet::new();
    let mut expanded: HashSet<String> = HashSet::new();

    for start in conflicted_ids {
        let remaining = auth_event_map
            .get(start)
            .map(|e| ev_auth_events(e).iter().map(|s| s.to_string()).collect())
            .unwrap_or_default();
        let mut stack: Vec<Frame> = vec![Frame {
            event_id: start.clone(),
            remaining,
        }];

        while !stack.is_empty() {
            let top = stack.len() - 1;
            if stack[top].remaining.is_empty() {
                stack.pop();
                continue;
            }
            let child_id = stack[top].remaining.pop().unwrap();

            if conflicted_ids.contains(&child_id) || subgraph.contains(&child_id) {
                for f in &stack {
                    subgraph.insert(f.event_id.clone());
                }
                subgraph.insert(child_id);
                continue;
            }

            if expanded.contains(&child_id) {
                continue;
            }
            expanded.insert(child_id.clone());

            let Some(child_event) = auth_event_map.get(&child_id) else {
                continue;
            };
            let remaining = ev_auth_events(child_event)
                .iter()
                .map(|s| s.to_string())
                .collect();
            stack.push(Frame {
                event_id: child_id,
                remaining,
            });
        }
    }

    subgraph
}

/// Resolve conflicting state from multiple forks (State Resolution v2 / v2.1).
pub fn resolve_state(
    state_at_forks: &[StateEvents],
    auth_events: &EventMap,
    room_state: &RoomState,
    room_version: Option<&str>,
) -> StateEvents {
    if state_at_forks.is_empty() {
        return BTreeMap::new();
    }
    if state_at_forks.len() == 1 {
        return state_at_forks[0].clone();
    }

    let use_v21 = is_room_version_12_plus(room_version);
    let id_for = |ev: &Value| compute_event_id(ev, room_version);

    // Index every fork event by id so the sorts / iterative phase can resolve
    // candidate ids back to events even if absent from `auth_events`.
    let mut event_map: EventMap = auth_events.clone();
    for fork in state_at_forks {
        for ev in fork.values() {
            let id = id_for(ev);
            event_map.entry(id).or_insert_with(|| ev.clone());
        }
    }

    let mut all_keys: HashSet<String> = HashSet::new();
    for state_map in state_at_forks {
        for key in state_map.keys() {
            all_keys.insert(key.clone());
        }
    }

    let mut unconflicted: StateEvents = BTreeMap::new();
    let mut conflicted_ids: HashSet<String> = HashSet::new();
    let mut full_conflicted_set: HashSet<String> = HashSet::new();

    for key in &all_keys {
        // A key is conflicted if any fork is missing it, or the forks disagree.
        let mut ids: HashSet<Option<String>> = HashSet::new();
        let mut by_id: HashMap<String, Value> = HashMap::new();
        for state_map in state_at_forks {
            match state_map.get(key) {
                Some(ev) => {
                    let id = id_for(ev);
                    ids.insert(Some(id.clone()));
                    by_id.insert(id, ev.clone());
                }
                None => {
                    ids.insert(None);
                }
            }
        }

        if ids.len() == 1 {
            if let Some(only) = by_id.into_values().next() {
                unconflicted.insert(key.clone(), only);
            }
        } else {
            for id in by_id.into_keys() {
                conflicted_ids.insert(id.clone());
                full_conflicted_set.insert(id);
            }
        }
    }

    // MSC4297: expand the candidate set with the conflicted subgraph.
    if use_v21 && !conflicted_ids.is_empty() {
        let subgraph = compute_conflicted_subgraph(&conflicted_ids, &event_map);
        for id in subgraph {
            full_conflicted_set.insert(id);
        }
    }

    let create_event = unconflicted
        .get(&make_state_key("m.room.create", ""))
        .cloned();

    // Partition the full conflicted set into power events and the rest.
    let mut power_event_ids: Vec<String> = Vec::new();
    let mut other_event_ids: Vec<String> = Vec::new();
    for id in &full_conflicted_set {
        let Some(ev) = event_map.get(id) else {
            continue;
        };
        if ev_state_key(ev).is_none() {
            continue;
        }
        if is_power_event(ev) {
            power_event_ids.push(id.clone());
        } else {
            other_event_ids.push(id.clone());
        }
    }

    let sorted_power = reverse_topological_power_sort(
        &power_event_ids,
        &event_map,
        &full_conflicted_set,
        room_version,
        create_event.as_ref(),
    );

    // v2.0: start from unconflicted; v2.1: start from empty.
    let mut resolved_state: StateEvents = if use_v21 {
        BTreeMap::new()
    } else {
        unconflicted.clone()
    };

    apply_events(
        &sorted_power,
        room_state,
        &mut resolved_state,
        &event_map,
        use_v21,
        create_event.as_ref(),
        room_version,
    );

    let resolved_pl_id = resolved_state
        .get(&make_state_key("m.room.power_levels", ""))
        .map(id_for);
    let sorted_other = mainline_sort(
        &other_event_ids,
        resolved_pl_id.as_deref(),
        &event_map,
        room_version,
    );

    apply_events(
        &sorted_other,
        room_state,
        &mut resolved_state,
        &event_map,
        use_v21,
        create_event.as_ref(),
        room_version,
    );

    // Unconflicted state always still applies, layered on top.
    for (key, event) in &unconflicted {
        resolved_state.insert(key.clone(), event.clone());
    }

    resolved_state
}
