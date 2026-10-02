//! Appservice registration loading + namespace matching — port of strix
//! `appservice/registration.ts`.

use regex::Regex;

use crate::types::appservice::{AppserviceNamespace, AppserviceNamespaces, AppserviceRegistration};

/// Load registrations from every `*.yaml`/`*.yml` file in `dir`, parsing
/// Complement's regular registration YAML shape (no general YAML support).
/// Mirrors strix's `complement-as-registrations.ts` but in-process, so the
/// runtime image needs no Node. Returns empty if the dir is missing/unreadable.
pub fn parse_registration_dir(dir: &str) -> Vec<AppserviceRegistration> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let is_yaml = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e == "yaml" || e == "yml")
            .unwrap_or(false);
        if !is_yaml {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Some(reg) = parse_complement_yaml(&text) {
                out.push(reg);
            }
        }
    }
    out
}

/// Parse one Complement registration YAML (the minimal regular subset: top-level
/// scalar keys + a `namespaces:` block with `users`/`aliases`/`rooms` lists of
/// `{exclusive, regex}` entries).
fn parse_complement_yaml(text: &str) -> Option<AppserviceRegistration> {
    let mut top: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut users = Vec::new();
    let mut aliases = Vec::new();
    let mut rooms = Vec::new();

    let strip = |s: &str| -> String {
        let t = s.trim();
        t.trim_matches('"').trim_matches('\'').to_string()
    };

    let mut in_namespaces = false;
    // Track the current namespace list by name rather than holding a &mut.
    let mut ns_name = String::new();

    for raw in text.lines() {
        let line = raw.trim_end();
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let content = line.trim_start();

        if indent == 0 {
            in_namespaces = content.starts_with("namespaces:");
            if !in_namespaces {
                if let Some((k, v)) = content.split_once(':') {
                    top.insert(k.trim().to_string(), strip(v));
                }
            }
            ns_name.clear();
            continue;
        }
        if !in_namespaces {
            continue;
        }
        // Inside namespaces: a "users:"/"aliases:"/"rooms:" header (indent ~2) or
        // list entries (indent ~4+, starting with "-").
        if content.ends_with(':') && !content.starts_with('-') {
            ns_name = content.trim_end_matches(':').trim().to_string();
            continue;
        }
        // A list entry line, possibly "- exclusive: false" or "regex: .*".
        let entry_line = content.trim_start_matches('-').trim();
        let target: &mut Vec<AppserviceNamespace> = match ns_name.as_str() {
            "users" => &mut users,
            "aliases" => &mut aliases,
            "rooms" => &mut rooms,
            _ => continue,
        };
        if content.starts_with('-') {
            // Start of a new entry.
            target.push(AppserviceNamespace { exclusive: false, regex: String::new() });
        }
        if let Some(entry) = target.last_mut() {
            if let Some((k, v)) = entry_line.split_once(':') {
                match k.trim() {
                    "exclusive" => entry.exclusive = strip(v) == "true",
                    "regex" => entry.regex = strip(v),
                    _ => {}
                }
            }
        }
    }

    Some(AppserviceRegistration {
        id: top.remove("id")?,
        url: top.remove("url").unwrap_or_default(),
        as_token: top.remove("as_token")?,
        hs_token: top.remove("hs_token")?,
        sender_localpart: top.remove("sender_localpart")?,
        namespaces: AppserviceNamespaces {
            users: (!users.is_empty()).then_some(users),
            aliases: (!aliases.is_empty()).then_some(aliases),
            rooms: (!rooms.is_empty()).then_some(rooms),
        },
        rate_limited: top.remove("rate_limited").map(|v| v == "true"),
        protocols: None,
    })
}

/// Parse registrations from the `APPSERVICE_REGISTRATIONS` env value (a JSON
/// array of registration objects). Returns empty on unset/empty/invalid.
pub fn parse_registrations(env_value: Option<&str>) -> Vec<AppserviceRegistration> {
    let Some(raw) = env_value.filter(|s| !s.is_empty()) else {
        return Vec::new();
    };
    match serde_json::from_str::<Vec<AppserviceRegistration>>(raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to parse APPSERVICE_REGISTRATIONS as JSON: {e}");
            Vec::new()
        }
    }
}

fn ns_matches(regexes: &Option<Vec<crate::types::appservice::AppserviceNamespace>>, value: &str, exclusive_only: bool) -> bool {
    let Some(list) = regexes else { return false };
    list.iter().any(|ns| {
        if exclusive_only && !ns.exclusive {
            return false;
        }
        Regex::new(&ns.regex).map(|re| re.is_match(value)).unwrap_or(false)
    })
}

/// The appservice whose user namespace matches `user_id`.
pub fn find_appservice_for_user<'a>(
    user_id: &str,
    regs: &'a [AppserviceRegistration],
) -> Option<&'a AppserviceRegistration> {
    regs.iter().find(|r| ns_matches(&r.namespaces.users, user_id, false))
}

/// The appservice whose alias namespace matches `alias`.
pub fn find_appservice_for_alias<'a>(
    alias: &str,
    regs: &'a [AppserviceRegistration],
) -> Option<&'a AppserviceRegistration> {
    regs.iter().find(|r| ns_matches(&r.namespaces.aliases, alias, false))
}

/// The appservice owning `as_token`.
pub fn find_appservice_by_token<'a>(
    as_token: &str,
    regs: &'a [AppserviceRegistration],
) -> Option<&'a AppserviceRegistration> {
    regs.iter().find(|r| r.as_token == as_token)
}

/// The appservice that exclusively owns `user_id` (if any).
pub fn find_exclusive_appservice_for_user<'a>(
    user_id: &str,
    regs: &'a [AppserviceRegistration],
) -> Option<&'a AppserviceRegistration> {
    regs.iter().find(|r| ns_matches(&r.namespaces.users, user_id, true))
}
