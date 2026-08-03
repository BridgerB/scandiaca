//! `AccountStore` for the in-memory backend.

use async_trait::async_trait;

use super::{now_ms, record_device_key_change, MemoryStorage};
use crate::storage::interface::{AccountStore, ThreePidRecord, UiaaSession};
use crate::types::identifiers::{AccessToken, DeviceId, RefreshToken, Timestamp, UserId};
use crate::types::internal::{StoredSession, UserAccount};
use crate::types::user::{Device, UserProfile};

#[async_trait]
impl AccountStore for MemoryStorage {
    async fn create_user(&self, account: UserAccount) {
        let mut s = self.write();
        s.localpart_index
            .insert(account.localpart.clone(), account.user_id.to_string());
        s.users_by_id.insert(account.user_id.to_string(), account);
    }

    async fn get_user_by_localpart(&self, localpart: &str) -> Option<UserAccount> {
        let s = self.read();
        let id = s.localpart_index.get(localpart)?;
        s.users_by_id.get(id).cloned()
    }

    async fn get_user_by_id(&self, user_id: &UserId) -> Option<UserAccount> {
        self.read().users_by_id.get(user_id.as_str()).cloned()
    }

    async fn create_session(&self, session: StoredSession) {
        let user_id = session.user_id.to_string();
        {
            let mut s = self.write();
            if let Some(rt) = &session.refresh_token {
                s.refresh_index
                    .insert(rt.to_string(), session.access_token.to_string());
            }
            s.sessions_by_token
                .insert(session.access_token.to_string(), session);
            // A new device/session was added: notify device-list subscribers.
            record_device_key_change(&mut s, &user_id);
        }
        self.wake_waiters();
    }

    async fn get_session_by_access_token(&self, token: &AccessToken) -> Option<StoredSession> {
        self.read().sessions_by_token.get(token.as_str()).cloned()
    }

    async fn get_session_by_refresh_token(&self, token: &RefreshToken) -> Option<StoredSession> {
        let s = self.read();
        let access = s.refresh_index.get(token.as_str())?;
        s.sessions_by_token.get(access).cloned()
    }

    async fn get_sessions_by_user(&self, user_id: &UserId) -> Vec<StoredSession> {
        self.read()
            .sessions_by_token
            .values()
            .filter(|s| s.user_id.as_str() == user_id.as_str())
            .cloned()
            .collect()
    }

    async fn delete_session(&self, token: &AccessToken) {
        let user_id = {
            let mut s = self.write();
            let Some(session) = s.sessions_by_token.remove(token.as_str()) else {
                return;
            };
            if let Some(rt) = &session.refresh_token {
                s.refresh_index.remove(rt.as_str());
            }
            let user_id = session.user_id.to_string();
            // A device/session was removed: notify device-list subscribers.
            record_device_key_change(&mut s, &user_id);
            user_id
        };
        let _ = user_id;
        self.wake_waiters();
    }

    async fn delete_all_sessions(&self, user_id: &UserId) {
        {
            let mut s = self.write();
            let uid = user_id.as_str();
            let to_remove: Vec<String> = s
                .sessions_by_token
                .iter()
                .filter(|(_, sess)| sess.user_id.as_str() == uid)
                .map(|(tok, _)| tok.clone())
                .collect();
            for tok in to_remove {
                if let Some(sess) = s.sessions_by_token.remove(&tok) {
                    if let Some(rt) = &sess.refresh_token {
                        s.refresh_index.remove(rt.as_str());
                    }
                }
            }
            record_device_key_change(&mut s, uid);
        }
        self.wake_waiters();
    }

    async fn rotate_token(
        &self,
        old_access_token: &AccessToken,
        new_access_token: &AccessToken,
        new_refresh_token: Option<&RefreshToken>,
        expires_at: Option<Timestamp>,
    ) -> Option<StoredSession> {
        let mut s = self.write();
        let mut session = s.sessions_by_token.remove(old_access_token.as_str())?;
        if let Some(rt) = &session.refresh_token {
            s.refresh_index.remove(rt.as_str());
        }
        session.access_token = new_access_token.clone();
        session.refresh_token = new_refresh_token.cloned();
        session.expires_at = expires_at;
        if let Some(rt) = new_refresh_token {
            s.refresh_index
                .insert(rt.to_string(), new_access_token.to_string());
        }
        s.sessions_by_token
            .insert(new_access_token.to_string(), session.clone());
        Some(session)
    }

    async fn touch_session(&self, token: &AccessToken, ip: &str, user_agent: &str) {
        let mut s = self.write();
        if let Some(session) = s.sessions_by_token.get_mut(token.as_str()) {
            session.last_seen_ip = Some(ip.to_string());
            session.last_seen_ts = Some(now_ms());
            session.user_agent = Some(user_agent.to_string());
        }
    }

    async fn create_uiaa_session(&self, session_id: &str) {
        self.write()
            .uiaa_sessions
            .insert(session_id.to_string(), UiaaSession::default());
    }

    async fn get_uiaa_session(&self, session_id: &str) -> Option<UiaaSession> {
        self.read().uiaa_sessions.get(session_id).cloned()
    }

    async fn add_uiaa_completed(&self, session_id: &str, stage_type: &str) {
        if let Some(sess) = self.write().uiaa_sessions.get_mut(session_id) {
            sess.completed.push(stage_type.to_string());
        }
    }

    async fn delete_uiaa_session(&self, session_id: &str) {
        self.write().uiaa_sessions.remove(session_id);
    }

    async fn get_device(&self, user_id: &UserId, device_id: &DeviceId) -> Option<Device> {
        let s = self.read();
        s.sessions_by_token
            .values()
            .find(|sess| {
                sess.user_id.as_str() == user_id.as_str()
                    && sess.device_id.as_str() == device_id.as_str()
            })
            .map(session_to_device)
    }

    async fn get_all_devices(&self, user_id: &UserId) -> Vec<Device> {
        self.read()
            .sessions_by_token
            .values()
            .filter(|sess| sess.user_id.as_str() == user_id.as_str())
            .map(session_to_device)
            .collect()
    }

    async fn update_device_display_name(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
        display_name: &str,
    ) {
        let changed = {
            let mut s = self.write();
            let mut found = false;
            for sess in s.sessions_by_token.values_mut() {
                if sess.user_id.as_str() == user_id.as_str()
                    && sess.device_id.as_str() == device_id.as_str()
                {
                    sess.display_name = Some(display_name.to_string());
                    found = true;
                    break;
                }
            }
            if found {
                record_device_key_change(&mut s, user_id.as_str());
            }
            found
        };
        if changed {
            self.wake_waiters();
        }
    }

    async fn delete_device_session(&self, user_id: &UserId, device_id: &DeviceId) {
        {
            let mut s = self.write();
            let tok = s
                .sessions_by_token
                .iter()
                .find(|(_, sess)| {
                    sess.user_id.as_str() == user_id.as_str()
                        && sess.device_id.as_str() == device_id.as_str()
                })
                .map(|(t, _)| t.clone());
            if let Some(tok) = tok {
                if let Some(sess) = s.sessions_by_token.remove(&tok) {
                    if let Some(rt) = &sess.refresh_token {
                        s.refresh_index.remove(rt.as_str());
                    }
                }
            }
            record_device_key_change(&mut s, user_id.as_str());
        }
        self.wake_waiters();
    }

    async fn update_password(&self, user_id: &UserId, new_password_hash: &str) {
        if let Some(user) = self.write().users_by_id.get_mut(user_id.as_str()) {
            user.password_hash = new_password_hash.to_string();
        }
    }

    async fn deactivate_user(&self, user_id: &UserId) {
        {
            let mut s = self.write();
            if let Some(user) = s.users_by_id.get_mut(user_id.as_str()) {
                user.is_deactivated = true;
            }
            // Inline delete-all-sessions (avoid re-locking).
            let uid = user_id.as_str();
            let to_remove: Vec<String> = s
                .sessions_by_token
                .iter()
                .filter(|(_, sess)| sess.user_id.as_str() == uid)
                .map(|(tok, _)| tok.clone())
                .collect();
            for tok in to_remove {
                if let Some(sess) = s.sessions_by_token.remove(&tok) {
                    if let Some(rt) = &sess.refresh_token {
                        s.refresh_index.remove(rt.as_str());
                    }
                }
            }
            record_device_key_change(&mut s, uid);
        }
        self.wake_waiters();
    }

    async fn get_profile(&self, user_id: &UserId) -> Option<UserProfile> {
        let s = self.read();
        let user = s.users_by_id.get(user_id.as_str())?;
        Some(UserProfile {
            displayname: user.displayname.clone(),
            avatar_url: user.avatar_url.clone().map(Into::into),
        })
    }

    async fn set_display_name(&self, user_id: &UserId, displayname: Option<&str>) {
        if let Some(user) = self.write().users_by_id.get_mut(user_id.as_str()) {
            user.displayname = displayname.map(str::to_string);
        }
    }

    async fn set_avatar_url(&self, user_id: &UserId, avatar_url: Option<&str>) {
        if let Some(user) = self.write().users_by_id.get_mut(user_id.as_str()) {
            user.avatar_url = avatar_url.map(str::to_string);
        }
    }

    async fn get_three_pids(&self, user_id: &UserId) -> Vec<ThreePidRecord> {
        self.read()
            .three_pids
            .get(user_id.as_str())
            .cloned()
            .unwrap_or_default()
    }

    async fn add_three_pid(&self, user_id: &UserId, medium: &str, address: &str) {
        let mut s = self.write();
        let pids = s.three_pids.entry(user_id.to_string()).or_default();
        if pids
            .iter()
            .any(|p| p.medium == medium && p.address == address)
        {
            return;
        }
        pids.push(ThreePidRecord {
            medium: medium.to_string(),
            address: address.to_string(),
            added_at: now_ms(),
        });
    }

    async fn delete_three_pid(&self, user_id: &UserId, medium: &str, address: &str) {
        if let Some(pids) = self.write().three_pids.get_mut(user_id.as_str()) {
            pids.retain(|p| !(p.medium == medium && p.address == address));
        }
    }
}

fn session_to_device(sess: &StoredSession) -> Device {
    Device {
        device_id: sess.device_id.clone(),
        display_name: sess.display_name.clone(),
        last_seen_ip: sess.last_seen_ip.clone(),
        last_seen_ts: sess.last_seen_ts,
    }
}
