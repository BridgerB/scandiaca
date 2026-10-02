//! HTTP server — axum bootstrap, shared state, CORS, and the base endpoints.
//!
//! strix hand-rolls a router on `node:http`; the Rust port uses axum but keeps
//! the same semantics: a global CORS layer applied to EVERY response (including
//! thrown errors — strix's live-deployment fix), `MatrixError` → JSON error, and
//! a 404 `M_UNRECOGNIZED` fallback. Handlers capture their dependencies through
//! the shared [`AppState`] (axum's `State`), mirroring strix's handler factories.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Map, Value};

use crate::errors::{missing_token, unknown_token, user_deactivated, MatrixError};
use crate::handlers;
use crate::signing::{sign_json, SigningKey};
use crate::storage::Storage;
use crate::types::identifiers::{AccessToken, DeviceId, UserId};

/// Shared application state, cloned (cheaply, via `Arc`) into every handler.
#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn Storage>,
    pub server_name: Arc<str>,
    pub signing_key: Arc<SigningKey>,
    /// Outbound federation client (present once federation is enabled).
    pub federation_client: Option<Arc<crate::federation::FederationClient>>,
    /// Application-service registrations (from `APPSERVICE_REGISTRATIONS`).
    pub registrations: Arc<Vec<crate::types::appservice::AppserviceRegistration>>,
}

/// Unix time in milliseconds (strix `Date.now()`).
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Authenticated request context, extracted from the access token — the Rust
/// equivalent of strix's `requireAuth` middleware (appservice-token fallback
/// arrives with the appservice phase).
pub struct AuthCtx {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub access_token: AccessToken,
}

impl FromRequestParts<AppState> for AuthCtx {
    type Rejection = MatrixError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_access_token(parts)?;

        // Appservice token fallback: if the token is an AS `as_token`, honor an
        // optional `?user_id=` masquerade within the AS namespace, auto-creating
        // the AS user (strix `requireAuth` AS branch). Default device is
        // `_as_<sender_localpart>`.
        if let Some(reg) = crate::appservice::registration::find_appservice_by_token(&token, &state.registrations)
        {
            let query_user = parts
                .uri
                .query()
                .and_then(|q| query_param(q, "user_id"))
                .map(|u| percent_decode(&u));
            let user_id = match query_user {
                Some(u) => {
                    // The masqueraded user must be in the AS user namespace.
                    if crate::appservice::registration::find_appservice_for_user(&u, &state.registrations)
                        .map(|r| r.id != reg.id)
                        .unwrap_or(true)
                    {
                        return Err(crate::errors::forbidden(
                            "Application service cannot masquerade as this user",
                        ));
                    }
                    UserId::from(u.as_str())
                }
                None => UserId::from(format!("@{}:{}", reg.sender_localpart, state.server_name).as_str()),
            };
            // Auto-create the AS user if it does not exist.
            if state.storage.get_user_by_id(&user_id).await.is_none() {
                let localpart = user_id
                    .as_str()
                    .trim_start_matches('@')
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .to_string();
                state
                    .storage
                    .create_user(crate::types::internal::UserAccount {
                        user_id: user_id.clone(),
                        localpart,
                        server_name: state.server_name.as_ref().into(),
                        password_hash: String::new(),
                        account_type: crate::types::internal::AccountType::Appservice,
                        is_deactivated: false,
                        created_at: now_ms(),
                        displayname: None,
                        avatar_url: None,
                    })
                    .await;
            }
            return Ok(AuthCtx {
                user_id,
                device_id: DeviceId::from(format!("_as_{}", reg.sender_localpart).as_str()),
                access_token: AccessToken::from(token.as_str()),
            });
        }

        let session = state
            .storage
            .get_session_by_access_token(&AccessToken::from(token.as_str()))
            .await
            .ok_or_else(|| unknown_token("Unrecognised access token", false))?;
        if let Some(account) = state.storage.get_user_by_id(&session.user_id).await {
            if account.is_deactivated {
                return Err(user_deactivated("This account has been deactivated"));
            }
        }
        // Best-effort last-seen update (fire-and-forget would need the IP; we keep
        // it simple here and refresh on touch paths later).
        Ok(AuthCtx {
            user_id: session.user_id,
            device_id: session.device_id,
            access_token: session.access_token,
        })
    }
}

/// Extract the access token from `Authorization: Bearer` or `?access_token=`
/// (rejecting if both are present) — strix `extractAccessToken`.
pub fn extract_access_token(parts: &Parts) -> Result<String, MatrixError> {
    let auth_header = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let query_token = parts
        .uri
        .query()
        .and_then(|q| query_param(q, "access_token"))
        .unwrap_or_default();

    if !auth_header.is_empty() && !query_token.is_empty() {
        return Err(missing_token(
            "Do not supply access_token as both a query parameter and in the Authorization header",
        ));
    }
    if !query_token.is_empty() {
        return Ok(query_token);
    }
    if !auth_header.is_empty() {
        let parts: Vec<&str> = auth_header.splitn(2, ' ').collect();
        if parts.len() != 2 || parts[0] != "Bearer" || parts[1].is_empty() {
            return Err(missing_token("Invalid Authorization header"));
        }
        return Ok(parts[1].to_string());
    }
    Err(missing_token("Missing access token"))
}

/// Read one query-string parameter (access tokens are base64url, so no
/// percent-decoding is needed).
fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let mut it = pair.splitn(2, '=');
        if it.next() == Some(key) {
            Some(it.next().unwrap_or("").to_string())
        } else {
            None
        }
    })
}

/// Minimal percent-decoder for the `?user_id=` masquerade query param
/// (e.g. `@user%3Aserver` → `@user:server`).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Build the full axum router.
pub fn build_router(state: AppState) -> Router {
    let app = Router::new()
        .route("/_matrix/client/versions", get(handlers::discovery::versions))
        .route(
            "/.well-known/matrix/server",
            get(handlers::discovery::well_known_server),
        )
        .route(
            "/.well-known/matrix/client",
            get(handlers::discovery::well_known_client),
        )
        .route(
            "/.well-known/matrix/support",
            get(handlers::discovery::well_known_support),
        )
        .route(
            "/.well-known/matrix/policy",
            get(handlers::discovery::well_known_policy_server),
        )
        .route(
            "/_matrix/client/v1/auth_metadata",
            get(handlers::discovery::auth_metadata),
        )
        .route(
            "/_matrix/client/v3/capabilities",
            get(handlers::discovery::capabilities),
        )
        .route("/_matrix/key/v2/server", get(key_server))
        // Federation (Server-Server API)
        .route(
            "/_matrix/federation/v1/version",
            get(handlers::federation::version),
        )
        .route(
            "/_matrix/federation/v1/query/profile",
            get(handlers::federation::query_profile),
        )
        .route(
            "/_matrix/federation/v1/query/directory",
            get(handlers::federation::query_directory),
        )
        .route(
            "/_matrix/key/v2/query",
            post(handlers::federation::key_notary_query),
        )
        .route(
            "/_matrix/key/v2/query/{serverName}",
            get(handlers::federation::key_notary_get),
        )
        .route(
            "/_matrix/federation/v1/event/{eventId}",
            get(handlers::federation::get_event),
        )
        .route(
            "/_matrix/federation/v1/state/{roomId}",
            get(handlers::federation::get_room_state),
        )
        .route(
            "/_matrix/federation/v1/state_ids/{roomId}",
            get(handlers::federation::get_room_state_ids),
        )
        .route(
            "/_matrix/federation/v1/event_auth/{roomId}/{eventId}",
            get(handlers::federation::get_event_auth),
        )
        .route(
            "/_matrix/federation/v1/get_missing_events/{roomId}",
            post(handlers::federation::get_missing_events),
        )
        .route(
            "/_matrix/federation/v1/backfill/{roomId}",
            get(handlers::federation::get_backfill),
        )
        .route(
            "/_matrix/federation/v1/hierarchy/{roomId}",
            get(handlers::spaces::get_federation_hierarchy),
        )
        .route(
            "/_matrix/federation/v1/make_join/{roomId}/{userId}",
            get(handlers::federation::membership::make_join),
        )
        .route(
            "/_matrix/federation/v1/send_join/{roomId}/{eventId}",
            axum::routing::put(handlers::federation::membership::send_join_v1),
        )
        .route(
            "/_matrix/federation/v2/send_join/{roomId}/{eventId}",
            axum::routing::put(handlers::federation::membership::send_join_v2),
        )
        .route(
            "/_matrix/federation/v1/send/{txnId}",
            axum::routing::put(handlers::federation::transactions::put_federation_send),
        )
        .route(
            "/_matrix/federation/v1/invite/{roomId}/{eventId}",
            axum::routing::put(handlers::federation::membership::put_invite_v1),
        )
        .route(
            "/_matrix/federation/v2/invite/{roomId}/{eventId}",
            axum::routing::put(handlers::federation::membership::put_invite_v2),
        )
        .route(
            "/_matrix/federation/v1/make_leave/{roomId}/{userId}",
            get(handlers::federation::membership::make_leave),
        )
        .route(
            "/_matrix/federation/v1/send_leave/{roomId}/{eventId}",
            axum::routing::put(handlers::federation::membership::send_leave_v1),
        )
        .route(
            "/_matrix/federation/v2/send_leave/{roomId}/{eventId}",
            axum::routing::put(handlers::federation::membership::send_leave_v2),
        )
        .route(
            "/_matrix/federation/v1/make_knock/{roomId}/{userId}",
            get(handlers::federation::membership::make_knock),
        )
        .route(
            "/_matrix/federation/v1/send_knock/{roomId}/{eventId}",
            axum::routing::put(handlers::federation::membership::send_knock),
        )
        .route(
            "/_matrix/federation/v1/user/devices/{userId}",
            get(handlers::federation::keys::get_user_devices),
        )
        .route(
            "/_matrix/federation/v1/user/keys/query",
            axum::routing::post(handlers::federation::keys::post_keys_query),
        )
        .route(
            "/_matrix/federation/v1/user/keys/claim",
            axum::routing::post(handlers::federation::keys::post_keys_claim),
        )
        .route(
            "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync",
            axum::routing::post(handlers::sliding_sync::sliding_sync),
        )
        .route(
            "/_matrix/client/v4/sync",
            axum::routing::post(handlers::sliding_sync::sliding_sync),
        )
        .route(
            "/_matrix/client/v1/appservice/{appserviceId}/ping",
            axum::routing::post(handlers::appservice::ping),
        )
        .route(
            "/_matrix/federation/v1/media/download/{mediaId}",
            get(handlers::federation::media::serve_media),
        )
        .route(
            "/_matrix/federation/v1/media/thumbnail/{mediaId}",
            get(handlers::federation::media::serve_media),
        )
        .route(
            "/_matrix/client/v3/register",
            post(handlers::auth::register),
        )
        .route(
            "/_matrix/client/v3/login",
            get(handlers::auth::login_flows).post(handlers::auth::login),
        )
        .route(
            "/_matrix/client/v3/account/whoami",
            get(handlers::auth::whoami),
        )
        .route(
            "/_matrix/client/v3/register/available",
            get(handlers::account::register_available),
        )
        .route(
            "/_matrix/client/v1/register/m.login.registration_token/validity",
            get(handlers::account::registration_token_validity),
        )
        .route(
            "/_matrix/client/v3/account/password",
            post(handlers::account::change_password),
        )
        .route(
            "/_matrix/client/v3/account/deactivate",
            post(handlers::account::deactivate),
        )
        .route("/_matrix/client/v3/logout", post(handlers::logout::logout))
        .route(
            "/_matrix/client/v3/logout/all",
            post(handlers::logout::logout_all),
        )
        .route("/_matrix/client/v3/refresh", post(handlers::refresh::refresh))
        .route(
            "/_matrix/client/v3/admin/whois/{userId}",
            get(handlers::admin::whois),
        )
        .route(
            "/_matrix/client/v1/admin/lock/{userId}",
            get(handlers::admin::get_lock).put(handlers::admin::put_lock),
        )
        .route(
            "/_matrix/client/v1/admin/suspend/{userId}",
            get(handlers::admin::get_suspend).put(handlers::admin::put_suspend),
        )
        // Profile
        .route(
            "/_matrix/client/v3/profile/{userId}",
            get(handlers::profile::get_profile),
        )
        .route(
            "/_matrix/client/v3/profile/{userId}/displayname",
            get(handlers::profile::get_displayname).put(handlers::profile::put_displayname),
        )
        .route(
            "/_matrix/client/v3/profile/{userId}/avatar_url",
            get(handlers::profile::get_avatar_url).put(handlers::profile::put_avatar_url),
        )
        .route(
            "/_matrix/client/v3/profile/{userId}/{keyName}",
            get(handlers::profile::get_profile_field).put(handlers::profile::put_profile_field),
        )
        // Presence
        .route(
            "/_matrix/client/v3/presence/{userId}/status",
            get(handlers::presence::get_presence).put(handlers::presence::put_presence),
        )
        // Filters
        .route(
            "/_matrix/client/v3/user/{userId}/filter",
            post(handlers::filters::create_filter),
        )
        .route(
            "/_matrix/client/v3/user/{userId}/filter/{filterId}",
            get(handlers::filters::get_filter),
        )
        // Account data
        .route(
            "/_matrix/client/v3/user/{userId}/account_data/{type}",
            get(handlers::account_data::get_global)
                .put(handlers::account_data::put_global)
                .delete(handlers::account_data::delete_global),
        )
        .route(
            "/_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}",
            get(handlers::account_data::get_room)
                .put(handlers::account_data::put_room)
                .delete(handlers::account_data::delete_room),
        )
        // MSC3391 unstable delete-account-data endpoints (TestRemovingAccountData).
        .route(
            "/_matrix/client/unstable/org.matrix.msc3391/user/{userId}/account_data/{type}",
            axum::routing::delete(handlers::account_data::delete_global),
        )
        .route(
            "/_matrix/client/unstable/org.matrix.msc3391/user/{userId}/rooms/{roomId}/account_data/{type}",
            axum::routing::delete(handlers::account_data::delete_room),
        )
        .route(
            "/_matrix/client/v3/user/{userId}/rooms/{roomId}/tags",
            get(handlers::account_data::get_tags),
        )
        .route(
            "/_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag}",
            axum::routing::put(handlers::account_data::put_tag)
                .delete(handlers::account_data::delete_tag),
        )
        .route(
            "/_matrix/client/v3/createRoom",
            post(handlers::rooms::create_room),
        )
        .route(
            "/_matrix/client/v3/joined_rooms",
            get(handlers::rooms::joined_rooms),
        )
        // Membership
        .route(
            "/_matrix/client/v3/join/{roomIdOrAlias}",
            post(handlers::membership::join),
        )
        .route(
            "/_matrix/client/v3/knock/{roomIdOrAlias}",
            post(handlers::membership::knock),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/join",
            post(handlers::membership::join),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/leave",
            post(handlers::membership::leave),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/invite",
            post(handlers::membership::invite),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/kick",
            post(handlers::membership::kick),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/ban",
            post(handlers::membership::ban),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/unban",
            post(handlers::membership::unban),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/forget",
            post(handlers::membership::forget),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}",
            axum::routing::put(handlers::room_events::put_send_event),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/state",
            get(handlers::room_events::get_all_state),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/state/{eventType}",
            get(handlers::room_events::get_state_event)
                .put(handlers::room_events::put_state_event),
        )
        // Trailing-slash variant (empty state key): clients request
        // `.../state/{eventType}/` to mean state_key="" (Complement does this).
        .route(
            "/_matrix/client/v3/rooms/{roomId}/state/{eventType}/",
            get(handlers::room_events::get_state_event)
                .put(handlers::room_events::put_state_event),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}",
            get(handlers::room_events::get_state_event)
                .put(handlers::room_events::put_state_event),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/messages",
            get(handlers::room_events::get_messages),
        )
        .route(
            "/_matrix/client/v1/rooms/{roomId}/timestamp_to_event",
            get(handlers::room_events::get_timestamp_to_event),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/event/{eventId}",
            get(handlers::room_events::get_event),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/members",
            get(handlers::room_events::get_members),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/joined_members",
            get(handlers::room_events::get_joined_members),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}",
            axum::routing::put(handlers::room_events::redact),
        )
        // Ephemeral
        .route(
            "/_matrix/client/v3/rooms/{roomId}/typing/{userId}",
            axum::routing::put(handlers::ephemeral::put_typing),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}",
            post(handlers::ephemeral::post_receipt),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/read_markers",
            post(handlers::ephemeral::post_read_markers),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/report/{eventId}",
            post(handlers::ephemeral::report_event),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/report",
            post(handlers::ephemeral::report_room),
        )
        .route(
            "/_matrix/client/v3/users/{userId}/report",
            post(handlers::ephemeral::report_user),
        )
        // Relations + threads
        .route(
            "/_matrix/client/v1/rooms/{roomId}/relations/{eventId}",
            get(handlers::relations::get_relations),
        )
        .route(
            "/_matrix/client/v1/rooms/{roomId}/relations/{eventId}/{relType}",
            get(handlers::relations::get_relations),
        )
        .route(
            "/_matrix/client/v1/rooms/{roomId}/relations/{eventId}/{relType}/{eventType}",
            get(handlers::relations::get_relations),
        )
        .route(
            "/_matrix/client/v1/rooms/{roomId}/threads",
            get(handlers::relations::get_threads),
        )
        // Directory
        .route(
            "/_matrix/client/v3/directory/room/{roomAlias}",
            get(handlers::directory::get_alias)
                .put(handlers::directory::put_alias)
                .delete(handlers::directory::delete_alias),
        )
        .route(
            "/_matrix/client/v3/directory/list/room/{roomId}",
            get(handlers::directory::get_list_room).put(handlers::directory::put_list_room),
        )
        .route(
            "/_matrix/client/v3/publicRooms",
            get(handlers::directory::get_public_rooms).post(handlers::directory::post_public_rooms),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/aliases",
            get(handlers::directory::get_room_aliases),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/initialSync",
            get(handlers::room_events::get_room_initial_sync),
        )
        .route(
            "/_matrix/client/v1/rooms/{roomId}/hierarchy",
            get(handlers::spaces::get_hierarchy),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/hierarchy",
            get(handlers::spaces::get_hierarchy),
        )
        .route(
            "/_matrix/client/v3/rooms/{roomId}/upgrade",
            post(handlers::room_upgrade::upgrade),
        )
        .route(
            "/_matrix/client/v1/room_summary/{roomIdOrAlias}",
            get(handlers::room_summary::get_room_summary),
        )
        .route(
            "/_matrix/client/unstable/im.nheko.summary/summary/{roomIdOrAlias}",
            get(handlers::room_summary::get_room_summary),
        )
        // Devices
        .route("/_matrix/client/v3/devices", get(handlers::devices::get_devices))
        .route(
            "/_matrix/client/v3/devices/{deviceId}",
            get(handlers::devices::get_device)
                .put(handlers::devices::put_device)
                .delete(handlers::devices::delete_device),
        )
        .route(
            "/_matrix/client/v3/delete_devices",
            post(handlers::devices::delete_devices),
        )
        // E2EE keys
        .route("/_matrix/client/v3/keys/upload", post(handlers::e2ee::post_keys_upload))
        .route("/_matrix/client/v3/keys/query", post(handlers::e2ee::post_keys_query))
        .route("/_matrix/client/v3/keys/claim", post(handlers::e2ee::post_keys_claim))
        .route("/_matrix/client/v3/keys/changes", get(handlers::e2ee::get_keys_changes))
        .route(
            "/_matrix/client/v3/sendToDevice/{eventType}/{txnId}",
            axum::routing::put(handlers::e2ee::put_send_to_device),
        )
        // Cross-signing
        .route(
            "/_matrix/client/v3/keys/device_signing/upload",
            post(handlers::cross_signing::post_device_signing_upload),
        )
        .route(
            "/_matrix/client/v3/keys/signatures/upload",
            post(handlers::cross_signing::post_signatures_upload),
        )
        // Key backup — versions
        .route(
            "/_matrix/client/v3/room_keys/version",
            post(handlers::key_backup::post_version).get(handlers::key_backup::get_version),
        )
        .route(
            "/_matrix/client/v3/room_keys/version/{version}",
            get(handlers::key_backup::get_version)
                .put(handlers::key_backup::put_version)
                .delete(handlers::key_backup::delete_version),
        )
        // Key backup — keys
        .route(
            "/_matrix/client/v3/room_keys/keys",
            axum::routing::put(handlers::key_backup::put_all)
                .get(handlers::key_backup::get_all)
                .delete(handlers::key_backup::delete_all),
        )
        .route(
            "/_matrix/client/v3/room_keys/keys/{roomId}",
            axum::routing::put(handlers::key_backup::put_room)
                .get(handlers::key_backup::get_room)
                .delete(handlers::key_backup::delete_room),
        )
        .route(
            "/_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}",
            axum::routing::put(handlers::key_backup::put_session)
                .get(handlers::key_backup::get_session)
                .delete(handlers::key_backup::delete_session),
        )
        // Pushers + notifications
        .route(
            "/_matrix/client/v3/pushers",
            get(handlers::pushers::get_pushers),
        )
        .route(
            "/_matrix/client/v3/pushers/set",
            post(handlers::pushers::set_pusher),
        )
        .route(
            "/_matrix/client/v3/notifications",
            get(handlers::notifications::get_notifications),
        )
        // Push rules
        .route(
            "/_matrix/client/v3/pushrules/",
            get(handlers::push_rules::get_all),
        )
        .route(
            "/_matrix/client/v3/pushrules/global/",
            get(handlers::push_rules::get_global),
        )
        .route(
            "/_matrix/client/v3/pushrules/global/{kind}",
            get(handlers::push_rules::get_by_kind),
        )
        .route(
            "/_matrix/client/v3/pushrules/global/{kind}/{ruleId}",
            get(handlers::push_rules::get_rule)
                .put(handlers::push_rules::put_rule)
                .delete(handlers::push_rules::delete_rule),
        )
        .route(
            "/_matrix/client/v3/pushrules/global/{kind}/{ruleId}/enabled",
            get(handlers::push_rules::get_enabled).put(handlers::push_rules::put_enabled),
        )
        .route(
            "/_matrix/client/v3/pushrules/global/{kind}/{ruleId}/actions",
            get(handlers::push_rules::get_actions).put(handlers::push_rules::put_actions),
        )
        // Media repository (v3 + authenticated client/v1 aliases)
        .route("/_matrix/media/v3/upload", post(handlers::media::upload))
        .route(
            "/_matrix/media/v3/upload/{serverName}/{mediaId}",
            axum::routing::put(handlers::media::async_upload),
        )
        .route("/_matrix/media/v1/create", post(handlers::media::create_media))
        .route(
            "/_matrix/media/v3/download/{serverName}/{mediaId}",
            get(handlers::media::download),
        )
        .route(
            "/_matrix/media/v3/download/{serverName}/{mediaId}/{fileName}",
            get(handlers::media::download),
        )
        .route(
            "/_matrix/media/v3/thumbnail/{serverName}/{mediaId}",
            get(handlers::media::thumbnail),
        )
        .route("/_matrix/media/v3/config", get(handlers::media::config))
        .route(
            "/_matrix/client/v1/media/download/{serverName}/{mediaId}",
            get(handlers::media::download_authed),
        )
        .route(
            "/_matrix/client/v1/media/download/{serverName}/{mediaId}/{fileName}",
            get(handlers::media::download_authed),
        )
        .route(
            "/_matrix/client/v1/media/thumbnail/{serverName}/{mediaId}",
            get(handlers::media::thumbnail_authed),
        )
        .route("/_matrix/client/v1/media/config", get(handlers::media::config))
        .route(
            "/_matrix/client/v3/voip/turnServer",
            get(handlers::misc::turn_server),
        )
        .route(
            "/_matrix/client/v3/thirdparty/protocols",
            get(handlers::misc::thirdparty_protocols),
        )
        .route(
            "/_matrix/client/v3/thirdparty/protocol/{protocol}",
            get(handlers::misc::thirdparty_protocol),
        )
        .route(
            "/_matrix/client/v3/user/{userId}/openid/request_token",
            post(handlers::misc::openid_request_token),
        )
        .route("/_matrix/client/v3/search", post(handlers::search::search))
        .route(
            "/_matrix/client/v3/user_directory/search",
            post(handlers::user_directory::search),
        )
        .route(
            "/_matrix/client/unstable/io.element.msc4306/rooms/{roomId}/thread/{threadRootId}/subscription",
            get(handlers::thread_subscriptions::get_thread_subscription)
                .put(handlers::thread_subscriptions::put_thread_subscription)
                .delete(handlers::thread_subscriptions::delete_thread_subscription),
        )
        .route("/_matrix/client/v3/sync", get(handlers::sync::sync))
        .fallback(unrecognized)
        // A known path hit with an unsupported method must still return the JSON
        // M_UNRECOGNIZED error (not a bare 405 with an empty body) — TestUnknownEndpoints.
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn(cors))
        // Allow media uploads up to ~60 MB (default axum limit is 2 MB).
        .layer(axum::extract::DefaultBodyLimit::max(60 * 1024 * 1024))
        .with_state(state);

    // `Router::layer` runs AFTER routing, so a URI rewrite there is too late to
    // change which route matches. To rewrite legacy `client/r0` → `v3` paths
    // BEFORE routing, wrap the real router as a fallback service behind the
    // rewrite layer (the outer router has no routes, so every request falls
    // through to `app` — after the rewrite layer has run).
    Router::new()
        .fallback_service(app)
        .layer(middleware::from_fn(rewrite_legacy_paths))
}

/// TLS config for the optional federation listener.
pub struct TlsConfig {
    pub fed_port: u16,
    pub cert_path: String,
    pub key_path: String,
}

/// Bind and serve until the process is terminated. Always serves the client API
/// (plain HTTP) on `port`; when `tls` is set, also serves federation over HTTPS
/// on `tls.fed_port` sharing the same router. Uses a connect-info make service so
/// handlers can read the client IP (for rate limiting).
pub async fn run(state: AppState, port: u16, tls: Option<TlsConfig>) -> std::io::Result<()> {
    let app = build_router(state);

    if let Some(tls) = tls {
        let tls_app = app.clone();
        tokio::spawn(async move {
            match axum_server::tls_rustls::RustlsConfig::from_pem_file(&tls.cert_path, &tls.key_path)
                .await
            {
                Ok(config) => {
                    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], tls.fed_port));
                    println!("Federation TLS listening on :{}", tls.fed_port);
                    if let Err(e) = axum_server::bind_rustls(addr, config)
                        .serve(
                            tls_app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
                        )
                        .await
                    {
                        eprintln!("federation TLS server error: {e}");
                    }
                }
                Err(e) => eprintln!("failed to load TLS cert/key: {e}"),
            }
        });
    }

    // Set TCP_NODELAY on every accepted connection. Without it, Nagle's algorithm
    // interacts with delayed ACKs to add ~1–2ms of latency to each small
    // request/response on a sequential keep-alive connection — invisible under
    // concurrency but a big hit to single-request latency (Node enables nodelay
    // by default; hyper/axum does not).
    use axum::serve::ListenerExt;
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await?
        .tap_io(|stream| {
            let _ = stream.set_nodelay(true);
        });
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
}

// --- CORS -------------------------------------------------------------------

fn apply_cors(headers: &mut HeaderMap) {
    headers.insert("Access-Control-Allow-Origin", HeaderValue::from_static("*"));
    headers.insert(
        "Access-Control-Allow-Methods",
        HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"),
    );
    headers.insert(
        "Access-Control-Allow-Headers",
        HeaderValue::from_static("Origin, X-Requested-With, Content-Type, Accept, Authorization"),
    );
}

/// Rewrite legacy `/_matrix/client/r0/…` request paths to `/_matrix/client/v3/…`
/// (r0 is a spec alias of v3) so the router's v3 routes serve both without
/// duplicate registrations. Preserves the query string.
async fn rewrite_legacy_paths(mut req: Request<Body>, next: Next) -> Response {
    let path = req.uri().path();
    if let Some(rest) = path.strip_prefix("/_matrix/client/r0/") {
        let new_path = format!("/_matrix/client/v3/{rest}");
        let new_uri = match req.uri().query() {
            Some(q) => format!("{new_path}?{q}"),
            None => new_path,
        };
        if let Ok(uri) = new_uri.parse() {
            *req.uri_mut() = uri;
        }
    }
    next.run(req).await
}

/// Global CORS middleware: short-circuits OPTIONS preflight and adds the CORS
/// headers to EVERY response, including error responses (so browser clients see
/// the headers even on a 4xx/5xx — strix's live CORS fix).
async fn cors(req: Request<Body>, next: Next) -> Response {
    if req.method() == Method::OPTIONS {
        let mut res = Response::new(Body::empty());
        *res.status_mut() = StatusCode::OK;
        apply_cors(res.headers_mut());
        return res;
    }
    let mut res = next.run(req).await;
    apply_cors(res.headers_mut());
    res
}

// --- Base endpoints ---------------------------------------------------------

/// `GET /_matrix/key/v2/server` — this server's published signing keys, signed.
async fn key_server(State(st): State<AppState>) -> Json<Value> {
    let valid_until = now_ms() + 24 * 60 * 60 * 1000;

    let mut verify_keys = Map::new();
    verify_keys.insert(
        st.signing_key.key_id.clone(),
        json!({ "key": st.signing_key.public_key_base64.clone() }),
    );

    let mut body = Map::new();
    body.insert(
        "server_name".to_string(),
        Value::String(st.server_name.to_string()),
    );
    body.insert("valid_until_ts".to_string(), Value::from(valid_until));
    body.insert("verify_keys".to_string(), Value::Object(verify_keys));
    body.insert("old_verify_keys".to_string(), Value::Object(Map::new()));

    let signed = sign_json(&Value::Object(body), &st.server_name, &st.signing_key);
    Json(signed)
}

/// 404 fallback for unmatched routes.
async fn unrecognized() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "errcode": "M_UNRECOGNIZED", "error": "Unrecognized request" })),
    )
        .into_response()
}

/// 405 fallback for a known path hit with an unsupported method — still the JSON
/// M_UNRECOGNIZED error (TestUnknownEndpoints expects 405 with a JSON body).
async fn method_not_allowed() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(json!({ "errcode": "M_UNRECOGNIZED", "error": "Unrecognized request" })),
    )
        .into_response()
}
