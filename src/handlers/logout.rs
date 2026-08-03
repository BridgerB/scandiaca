//! Logout — port of strix `handlers/logout.ts`.

use axum::extract::State;
use axum::response::Json;
use serde_json::{json, Value};

use crate::server::{AppState, AuthCtx};

/// Local notification settings account-data prefix (MSC3890).
pub const LOCAL_NOTIFICATION_SETTINGS_PREFIX: &str = "org.matrix.msc3890.local_notification_settings.";

/// `POST /_matrix/client/v3/logout`.
pub async fn logout(State(st): State<AppState>, auth: AuthCtx) -> Json<Value> {
    st.storage.delete_session(&auth.access_token).await;
    // MSC3890: logging out a device removes its local notification settings.
    st.storage
        .delete_global_account_data(
            &auth.user_id,
            &format!("{LOCAL_NOTIFICATION_SETTINGS_PREFIX}{}", auth.device_id.as_str()),
        )
        .await;
    Json(json!({}))
}

/// `POST /_matrix/client/v3/logout/all`.
pub async fn logout_all(State(st): State<AppState>, auth: AuthCtx) -> Json<Value> {
    st.storage.delete_all_sessions(&auth.user_id).await;
    Json(json!({}))
}
