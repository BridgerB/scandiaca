//! Appservice transaction push — port of strix `appservice/push.ts`.
//!
//! Fire-and-forget delivery of a matching event to every appservice whose
//! namespaces cover the event's sender, `state_key`, or `room_id`, via
//! `PUT /_matrix/app/v1/transactions/{txnId}` with the AS `hs_token`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Value};

use crate::server::now_ms;
use crate::types::appservice::{AppserviceNamespace, AppserviceRegistration};

static TXN_COUNTER: AtomicU64 = AtomicU64::new(0);

fn http() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("build appservice http client")
    })
}

fn ns_any_match(list: &Option<Vec<AppserviceNamespace>>, value: &str) -> bool {
    let Some(list) = list else { return false };
    list.iter().any(|ns| Regex::new(&ns.regex).map(|re| re.is_match(value)).unwrap_or(false))
}

/// Push a stored event to every appservice whose namespaces match it. Spawns a
/// background task per matching AS; never blocks the caller.
pub fn push_to_appservices(event: &Value, event_id: &str, regs: &[AppserviceRegistration]) {
    if regs.is_empty() {
        return;
    }
    let client_event = crate::handlers::client_event(event, event_id);
    let sender = event.get("sender").and_then(Value::as_str).unwrap_or("");
    let state_key = event.get("state_key").and_then(Value::as_str);
    let room_id = event.get("room_id").and_then(Value::as_str).unwrap_or("");

    for reg in regs {
        if reg.url.is_empty() {
            continue;
        }
        let matches_user = reg.namespaces.users.as_ref().is_some_and(|list| {
            list.iter().any(|ns| {
                let re = Regex::new(&ns.regex).ok();
                re.as_ref().is_some_and(|re| re.is_match(sender))
                    || state_key.is_some_and(|sk| re.as_ref().is_some_and(|re| re.is_match(sk)))
            })
        });
        let matches_room = ns_any_match(&reg.namespaces.rooms, room_id);
        if !matches_user && !matches_room {
            continue;
        }

        let txn_id = format!("{}_{}", now_ms(), TXN_COUNTER.fetch_add(1, Ordering::SeqCst) + 1);
        let url = format!("{}/_matrix/app/v1/transactions/{txn_id}", reg.url.trim_end_matches('/'));
        let body = json!({ "events": [client_event.clone()] });
        let hs_token = reg.hs_token.clone();
        let id = reg.id.clone();
        tokio::spawn(async move {
            let res = http()
                .put(&url)
                .header("Authorization", format!("Bearer {hs_token}"))
                .json(&body)
                .send()
                .await;
            match res {
                Ok(r) if r.status().as_u16() >= 400 => {
                    eprintln!("Appservice {id} returned {} for txn {txn_id}", r.status());
                }
                Err(e) => eprintln!("Failed to push to appservice {id}: {e}"),
                _ => {}
            }
        });
    }
}
