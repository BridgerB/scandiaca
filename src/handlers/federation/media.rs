//! Federation media — port of strix `handlers/federation/media.ts`.
//!
//! A remote server fetches OUR media via `GET
//! /_matrix/federation/v1/media/{download,thumbnail}/{mediaId}`. The response is
//! a `multipart/mixed` body: part 1 is JSON metadata (`{}`), part 2 is the media
//! bytes (MSC3916 authenticated media transport).

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::crypto::generate_token;
use crate::middleware::federation_auth::FedAuth;
use crate::server::AppState;
use crate::types::identifiers::ServerName;

/// Build a `multipart/mixed` body (JSON metadata part + binary media part).
/// Returns `(boundary, body_bytes)`.
pub fn build_multipart(content_type: &str, file_name: Option<&str>, data: &[u8]) -> (String, Vec<u8>) {
    let boundary = generate_token();
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Type: application/json\r\n\r\n");
    body.extend_from_slice(b"{}\r\n");
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
    if let Some(name) = file_name {
        body.extend_from_slice(
            format!("Content-Disposition: inline; filename=\"{}\"\r\n", name.replace('"', "")).as_bytes(),
        );
    }
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(data);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (boundary, body)
}

/// Extract the media bytes + content-type + filename from a `multipart/mixed`
/// federation media response. Returns `(content_type, filename, data)` for the
/// first non-JSON part.
pub fn parse_multipart(boundary: &str, body: &[u8]) -> Option<(String, Option<String>, Vec<u8>)> {
    let delim = format!("--{boundary}");
    // Split the body on the boundary delimiter.
    let sections = split_on(body, delim.as_bytes());
    for section in sections {
        // Each section: headers\r\n\r\n<data>. Skip empty/closing sections.
        let sep = find_subslice(&section, b"\r\n\r\n")?;
        let headers = &section[..sep];
        let mut data = &section[sep + 4..];
        // Trim a single trailing CRLF that precedes the next boundary.
        if data.ends_with(b"\r\n") {
            data = &data[..data.len() - 2];
        }
        let headers_str = String::from_utf8_lossy(headers);
        let mut content_type = String::new();
        let mut filename: Option<String> = None;
        for line in headers_str.lines() {
            let lower = line.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("content-type:") {
                content_type = v.trim().to_string();
            } else if lower.starts_with("content-disposition:") {
                filename = parse_disposition_filename(line);
            }
        }
        if content_type.is_empty() || content_type.starts_with("application/json") {
            continue;
        }
        return Some((content_type, filename, data.to_vec()));
    }
    None
}

/// Pull the filename from a `Content-Disposition` header value, preferring the
/// RFC 5987 `filename*=utf-8''<pct-encoded>` form over plain `filename="…"`.
fn parse_disposition_filename(line: &str) -> Option<String> {
    let value = line.split_once(':')?.1;
    for part in value.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("filename*=") {
            // filename*=utf-8''<pct-encoded>
            if let Some(enc) = v.splitn(3, '\'').nth(2) {
                return Some(percent_decode(enc));
            }
        }
    }
    for part in value.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("filename=") {
            return Some(v.trim_matches('"').to_string());
        }
    }
    None
}

/// Minimal percent-decoder for RFC 5987 filenames (UTF-8).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn split_on(haystack: &[u8], needle: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = haystack;
    while let Some(idx) = find_subslice(rest, needle) {
        if idx > 0 {
            out.push(rest[..idx].to_vec());
        }
        rest = &rest[idx + needle.len()..];
    }
    if !rest.is_empty() {
        out.push(rest.to_vec());
    }
    out
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// `GET /_matrix/federation/v1/media/download/{mediaId}` and
/// `.../thumbnail/{mediaId}` — serve our own media to a remote server as
/// `multipart/mixed`.
pub async fn serve_media(
    State(st): State<AppState>,
    Path(media_id): Path<String>,
    _auth: FedAuth,
) -> Response {
    let sn = ServerName::from(st.server_name.as_ref());
    let Some(result) = st.storage.get_media(&sn, &media_id).await else {
        return (StatusCode::NOT_FOUND, "Media not found").into_response();
    };
    if result.metadata.file_size == 0 {
        return (StatusCode::NOT_FOUND, "Media not yet uploaded").into_response();
    }
    let (boundary, body) = build_multipart(
        &result.metadata.content_type,
        result.metadata.upload_name.as_deref(),
        &result.data,
    );
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, format!("multipart/mixed; boundary={boundary}"))],
        body,
    )
        .into_response()
}
