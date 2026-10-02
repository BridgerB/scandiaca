//! Push-rules CRUD — port of strix `handlers/push-rules.ts`.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::response::Json;
use serde_json::{json, Value};

use crate::errors::{bad_json, forbidden, not_found, MatrixResult};
use crate::push_rules::{get_or_init_rules, is_valid_kind, save_rules};
use crate::server::{AppState, AuthCtx};

/// The `global.<kind>` rule array (cloned).
fn rules_for_kind(rules: &Value, kind: &str) -> Vec<Value> {
    rules
        .get("global")
        .and_then(|g| g.get(kind))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn find_rule<'a>(list: &'a [Value], rule_id: &str) -> Option<&'a Value> {
    list.iter().find(|r| r.get("rule_id").and_then(Value::as_str) == Some(rule_id))
}

/// `GET /_matrix/client/v3/pushrules/` (and `/pushrules`).
pub async fn get_all(State(st): State<AppState>, auth: AuthCtx) -> Json<Value> {
    let rules = get_or_init_rules(&*st.storage, &auth.user_id).await;
    Json(json!({ "global": rules.get("global").cloned().unwrap_or_else(|| json!({})) }))
}

/// `GET /_matrix/client/v3/pushrules/global/`.
pub async fn get_global(State(st): State<AppState>, auth: AuthCtx) -> Json<Value> {
    let rules = get_or_init_rules(&*st.storage, &auth.user_id).await;
    Json(rules.get("global").cloned().unwrap_or_else(|| json!({})))
}

/// `GET /_matrix/client/v3/pushrules/global/{kind}`.
pub async fn get_by_kind(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path(kind): Path<String>,
) -> MatrixResult<Json<Value>> {
    if !is_valid_kind(&kind) {
        return Err(not_found("Unknown rule kind"));
    }
    let rules = get_or_init_rules(&*st.storage, &auth.user_id).await;
    Ok(Json(json!(rules_for_kind(&rules, &kind))))
}

/// `GET /_matrix/client/v3/pushrules/global/{kind}/{ruleId}`.
pub async fn get_rule(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((kind, rule_id)): Path<(String, String)>,
) -> MatrixResult<Json<Value>> {
    if !is_valid_kind(&kind) {
        return Err(not_found("Unknown rule kind"));
    }
    let rules = get_or_init_rules(&*st.storage, &auth.user_id).await;
    let list = rules_for_kind(&rules, &kind);
    find_rule(&list, &rule_id)
        .cloned()
        .map(Json)
        .ok_or_else(|| not_found("Rule not found"))
}

/// `PUT /_matrix/client/v3/pushrules/global/{kind}/{ruleId}`.
pub async fn put_rule(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((kind, rule_id)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    if !is_valid_kind(&kind) {
        return Err(not_found("Unknown rule kind"));
    }
    if rule_id.starts_with('.') {
        return Err(bad_json("Cannot create rules with '.' prefix (reserved for defaults)"));
    }
    let Some(actions) = body.get("actions").filter(|v| v.is_array()) else {
        return Err(bad_json("Missing or invalid 'actions' field"));
    };

    let mut new_rule = json!({
        "rule_id": rule_id,
        "default": false,
        "enabled": true,
        "actions": actions.clone(),
    });
    if kind == "content" {
        let Some(pattern) = body.get("pattern").and_then(Value::as_str) else {
            return Err(bad_json("Content rules require a 'pattern' field"));
        };
        new_rule["pattern"] = json!(pattern);
    } else if kind == "override" || kind == "underride" {
        new_rule["conditions"] = body.get("conditions").cloned().unwrap_or_else(|| json!([]));
    }

    let mut rules = get_or_init_rules(&*st.storage, &auth.user_id).await;
    let mut list = rules_for_kind(&rules, &kind);
    // Remove any existing rule with this id.
    list.retain(|r| r.get("rule_id").and_then(Value::as_str) != Some(rule_id.as_str()));

    if let Some(before) = params.get("before") {
        let idx = list.iter().position(|r| r.get("rule_id").and_then(Value::as_str) == Some(before.as_str()));
        match idx {
            Some(i) => list.insert(i, new_rule),
            None => return Err(not_found("'before' rule not found")),
        }
    } else if let Some(after) = params.get("after") {
        let idx = list.iter().position(|r| r.get("rule_id").and_then(Value::as_str) == Some(after.as_str()));
        match idx {
            Some(i) => list.insert(i + 1, new_rule),
            None => return Err(not_found("'after' rule not found")),
        }
    } else {
        // Insert before the first default rule (client rules precede defaults).
        match list.iter().position(|r| r.get("default").and_then(Value::as_bool) == Some(true)) {
            Some(i) => list.insert(i, new_rule),
            None => list.push(new_rule),
        }
    }

    rules["global"][kind.as_str()] = json!(list);
    save_rules(&*st.storage, &auth.user_id, &rules).await;
    Ok(Json(json!({})))
}

/// `DELETE /_matrix/client/v3/pushrules/global/{kind}/{ruleId}`.
pub async fn delete_rule(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((kind, rule_id)): Path<(String, String)>,
) -> MatrixResult<Json<Value>> {
    if !is_valid_kind(&kind) {
        return Err(not_found("Unknown rule kind"));
    }
    let mut rules = get_or_init_rules(&*st.storage, &auth.user_id).await;
    let mut list = rules_for_kind(&rules, &kind);
    let idx = list
        .iter()
        .position(|r| r.get("rule_id").and_then(Value::as_str) == Some(rule_id.as_str()))
        .ok_or_else(|| not_found("Rule not found"))?;
    if list[idx].get("default").and_then(Value::as_bool) == Some(true) {
        return Err(forbidden("Cannot delete default rules"));
    }
    list.remove(idx);
    rules["global"][kind.as_str()] = json!(list);
    save_rules(&*st.storage, &auth.user_id, &rules).await;
    Ok(Json(json!({})))
}

/// `GET /_matrix/client/v3/pushrules/global/{kind}/{ruleId}/enabled`.
pub async fn get_enabled(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((kind, rule_id)): Path<(String, String)>,
) -> MatrixResult<Json<Value>> {
    let rule = lookup(&st, &auth, &kind, &rule_id).await?;
    Ok(Json(json!({ "enabled": rule.get("enabled").and_then(Value::as_bool).unwrap_or(true) })))
}

/// `PUT /_matrix/client/v3/pushrules/global/{kind}/{ruleId}/enabled`.
pub async fn put_enabled(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((kind, rule_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let Some(enabled) = body.get("enabled").and_then(Value::as_bool) else {
        return Err(bad_json("Missing or invalid 'enabled' field"));
    };
    mutate_rule(&st, &auth, &kind, &rule_id, |r| {
        r["enabled"] = json!(enabled);
    })
    .await
}

/// `GET /_matrix/client/v3/pushrules/global/{kind}/{ruleId}/actions`.
pub async fn get_actions(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((kind, rule_id)): Path<(String, String)>,
) -> MatrixResult<Json<Value>> {
    let rule = lookup(&st, &auth, &kind, &rule_id).await?;
    Ok(Json(json!({ "actions": rule.get("actions").cloned().unwrap_or_else(|| json!([])) })))
}

/// `PUT /_matrix/client/v3/pushrules/global/{kind}/{ruleId}/actions`.
pub async fn put_actions(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((kind, rule_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> MatrixResult<Json<Value>> {
    let Some(actions) = body.get("actions").filter(|v| v.is_array()).cloned() else {
        return Err(bad_json("Missing or invalid 'actions' field"));
    };
    mutate_rule(&st, &auth, &kind, &rule_id, |r| {
        r["actions"] = actions.clone();
    })
    .await
}

async fn lookup(st: &AppState, auth: &AuthCtx, kind: &str, rule_id: &str) -> MatrixResult<Value> {
    if !is_valid_kind(kind) {
        return Err(not_found("Unknown rule kind"));
    }
    let rules = get_or_init_rules(&*st.storage, &auth.user_id).await;
    let list = rules_for_kind(&rules, kind);
    find_rule(&list, rule_id).cloned().ok_or_else(|| not_found("Rule not found"))
}

async fn mutate_rule(
    st: &AppState,
    auth: &AuthCtx,
    kind: &str,
    rule_id: &str,
    f: impl Fn(&mut Value),
) -> MatrixResult<Json<Value>> {
    if !is_valid_kind(kind) {
        return Err(not_found("Unknown rule kind"));
    }
    let mut rules = get_or_init_rules(&*st.storage, &auth.user_id).await;
    let mut list = rules_for_kind(&rules, kind);
    let idx = list
        .iter()
        .position(|r| r.get("rule_id").and_then(Value::as_str) == Some(rule_id))
        .ok_or_else(|| not_found("Rule not found"))?;
    f(&mut list[idx]);
    rules["global"][kind] = json!(list);
    save_rules(&*st.storage, &auth.user_id, &rules).await;
    Ok(Json(json!({})))
}
