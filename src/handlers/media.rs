//! Media repository — port of strix `handlers/media.ts` (local paths; remote
//! media fetch over federation arrives with the federation phase).

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::crypto::generate_media_id;
use crate::errors::{forbidden, not_found, MatrixError, MatrixResult};
use crate::server::{now_ms, AppState, AuthCtx};
use crate::types::identifiers::ServerName;
use crate::types::internal::StoredMedia;

const MAX_UPLOAD_SIZE: usize = 52_428_800; // 50 MB

fn content_type_of(headers: &HeaderMap) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string()
}

/// `POST /_matrix/media/v3/upload`.
pub async fn upload(
    State(st): State<AppState>,
    auth: AuthCtx,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    data: Bytes,
) -> MatrixResult<Json<Value>> {
    if data.len() > MAX_UPLOAD_SIZE {
        return Err(MatrixError::new(
            "M_TOO_LARGE",
            format!("Upload exceeds maximum size of {MAX_UPLOAD_SIZE} bytes"),
            413,
        ));
    }
    let media_id = generate_media_id();
    let hash = STANDARD.encode(Sha256::digest(&data));
    let media = StoredMedia {
        media_id: media_id.clone(),
        origin: st.server_name.as_ref().into(),
        user_id: Some(auth.user_id.clone()),
        content_type: content_type_of(&headers),
        upload_name: params.get("filename").cloned(),
        file_size: data.len() as i64,
        content_hash: hash,
        created_at: now_ms(),
        quarantined: false,
    };
    st.storage.store_media(media, data.to_vec()).await;
    Ok(Json(json!({ "content_uri": format!("mxc://{}/{media_id}", st.server_name) })))
}

/// `GET /_matrix/media/v3/download/{serverName}/{mediaId}` (and `/{fileName}`,
/// and the authenticated `client/v1/media/download/...`).
pub async fn download(
    State(st): State<AppState>,
    Path(params): Path<Vec<String>>,
) -> Response {
    let server_name = params.first().cloned().unwrap_or_default();
    let media_id = params.get(1).cloned().unwrap_or_default();
    let file_name = params.get(2).cloned();
    serve_media(&st, &server_name, &media_id, file_name, true).await
}

/// `GET /_matrix/media/v3/thumbnail/{serverName}/{mediaId}` — serves the
/// original (no server-side resizing).
pub async fn thumbnail(State(st): State<AppState>, Path(params): Path<Vec<String>>) -> Response {
    let server_name = params.first().cloned().unwrap_or_default();
    let media_id = params.get(1).cloned().unwrap_or_default();
    serve_media(&st, &server_name, &media_id, None, false).await
}

async fn serve_media(
    st: &AppState,
    server_name: &str,
    media_id: &str,
    file_name: Option<String>,
    with_disposition: bool,
) -> Response {
    let result = match st.storage.get_media(&ServerName::from(server_name), media_id).await {
        Some(r) => r,
        None => {
            // Media owned by another server: fetch it over federation and cache.
            if server_name != st.server_name.as_ref() {
                if let Some(r) = fetch_remote_media(st, server_name, media_id).await {
                    r
                } else {
                    return not_found("Media not found").into_response();
                }
            } else {
                return not_found("Media not found").into_response();
            }
        }
    };
    if result.metadata.file_size == 0 {
        return (
            StatusCode::GATEWAY_TIMEOUT,
            Json(json!({ "errcode": "M_NOT_YET_UPLOADED", "error": "Content has not yet been uploaded" })),
        )
            .into_response();
    }
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        header::CONTENT_TYPE,
        result.metadata.content_type.parse().unwrap_or(header::HeaderValue::from_static("application/octet-stream")),
    );
    resp_headers.insert(header::CONTENT_SECURITY_POLICY, header::HeaderValue::from_static("sandbox"));
    if with_disposition {
        let name = file_name.or(result.metadata.upload_name);
        if let Some(name) = name {
            if let Ok(v) = format!("inline; filename=\"{}\"", name.replace('"', "")).parse() {
                resp_headers.insert(header::CONTENT_DISPOSITION, v);
            }
        }
    }
    (StatusCode::OK, resp_headers, result.data).into_response()
}

/// Fetch media owned by a remote server over federation and cache it locally
/// (strix defers this; here it mirrors Synapse's remote-media proxy). Returns
/// the fetched media, or `None` on any failure.
async fn fetch_remote_media(
    st: &AppState,
    server_name: &str,
    media_id: &str,
) -> Option<crate::storage::interface::MediaWithData> {
    let fed = st.federation_client.as_ref()?;
    let path = format!("/_matrix/federation/v1/media/download/{media_id}");
    let resp = fed.request_raw(server_name, &path).await.ok()?;
    if resp.status != 200 {
        return None;
    }
    // Content-Type: multipart/mixed; boundary=<b>
    let boundary = resp
        .content_type
        .split(';')
        .find_map(|p| p.trim().strip_prefix("boundary="))?
        .trim_matches('"')
        .to_string();
    let (content_type, filename, data) =
        crate::handlers::federation::media::parse_multipart(&boundary, &resp.body)?;

    let hash = STANDARD.encode(Sha256::digest(&data));
    let media = StoredMedia {
        media_id: media_id.to_string(),
        origin: ServerName::from(server_name),
        user_id: None,
        content_type: content_type.clone(),
        upload_name: filename,
        file_size: data.len() as i64,
        content_hash: hash,
        created_at: now_ms(),
        quarantined: false,
    };
    st.storage.store_media(media.clone(), data.clone()).await;
    Some(crate::storage::interface::MediaWithData { metadata: media, data })
}

/// `GET /_matrix/media/v3/config` (and `client/v1/media/config`).
pub async fn config() -> Json<Value> {
    Json(json!({ "m.upload.size": MAX_UPLOAD_SIZE }))
}

/// `POST /_matrix/media/v1/create` — reserve a media id for async upload.
pub async fn create_media(State(st): State<AppState>, auth: AuthCtx) -> Json<Value> {
    let media_id = generate_media_id();
    let media = StoredMedia {
        media_id: media_id.clone(),
        origin: st.server_name.as_ref().into(),
        user_id: Some(auth.user_id.clone()),
        content_type: "application/octet-stream".to_string(),
        upload_name: None,
        file_size: 0,
        content_hash: String::new(),
        created_at: now_ms(),
        quarantined: false,
    };
    st.storage.reserve_media(media).await;
    Json(json!({
        "content_uri": format!("mxc://{}/{media_id}", st.server_name),
        "unused_expires_at": now_ms() + 24 * 60 * 60 * 1000,
    }))
}

/// `PUT /_matrix/media/v3/upload/{serverName}/{mediaId}` — async upload body.
pub async fn async_upload(
    State(st): State<AppState>,
    auth: AuthCtx,
    Path((server_name, media_id)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    data: Bytes,
) -> MatrixResult<Json<Value>> {
    if server_name != st.server_name.as_ref() {
        return Err(forbidden("Cannot upload media to a different server"));
    }
    let existing = st
        .storage
        .get_media(&ServerName::from(server_name.as_str()), &media_id)
        .await
        .ok_or_else(|| not_found("Media not found"))?;
    if existing.metadata.user_id.as_ref() != Some(&auth.user_id) {
        return Err(forbidden("Cannot upload to media created by another user"));
    }
    if existing.metadata.file_size > 0 {
        return Err(MatrixError::new("M_CANNOT_OVERWRITE_MEDIA", "Media has already been uploaded", 409));
    }
    if data.is_empty() {
        return Err(MatrixError::new("M_BAD_JSON", "No content provided", 400));
    }
    if data.len() > MAX_UPLOAD_SIZE {
        return Err(MatrixError::new("M_TOO_LARGE", "Upload too large", 413));
    }
    st.storage
        .update_media_content(
            &ServerName::from(server_name.as_str()),
            &media_id,
            &content_type_of(&headers),
            params.get("filename").map(String::as_str),
            data.to_vec(),
        )
        .await;
    Ok(Json(json!({ "content_uri": format!("mxc://{server_name}/{media_id}") })))
}
