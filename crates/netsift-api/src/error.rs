//! `application/problem+json` errors (RFC 9457).

use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// API error rendered as a problem document. Messages are short and never contain secrets.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("authentication required")]
    Unauthorized,
    #[error("resource not found")]
    NotFound,
    #[error("method not allowed")]
    MethodNotAllowed,
    #[error("server is read-only")]
    ReadOnly,
    #[error("forbidden: {0}")]
    Forbidden(&'static str),
    #[error("invalid request: {0}")]
    BadRequest(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("too many imports running")]
    TooManyImports,
    #[error("session created by a newer version")]
    SessionTooNew,
    #[error("session upgrade failed")]
    SessionUpgradeFailed,
    #[error("session upgrade needed")]
    SessionUpgradeNeeded,
    #[error("session busy")]
    SessionBusy,
    #[error("GeoIP download failed")]
    GeoipDownloadFailed,
    #[error("invalid GeoIP database")]
    GeoipInvalid,
    #[error("GeoIP database too large")]
    GeoipTooLarge,
    #[error("GeoIP update already running")]
    GeoipUpdateRunning,
    #[error("too many exports running")]
    TooManyExports,
    /// Detail: the file name of the chunk (never its full path).
    #[error("export source missing: {0}")]
    ExportSourceMissing(String),
    #[error("export source modified: {0}")]
    ExportSourceModified(String),
    #[error("internal error")]
    Internal,
}

#[derive(Serialize)]
struct Problem<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    title: &'a str,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

impl ApiError {
    fn parts(&self) -> (StatusCode, &'static str, &'static str) {
        match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authentication required",
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "not-found", "Resource not found"),
            Self::MethodNotAllowed => (
                StatusCode::METHOD_NOT_ALLOWED,
                "method-not-allowed",
                "Method not allowed",
            ),
            Self::ReadOnly => (StatusCode::FORBIDDEN, "read-only", "Server is read-only"),
            Self::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden", "Forbidden"),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad-request", "Invalid request"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "conflict", "Conflict"),
            Self::TooManyImports => (
                StatusCode::CONFLICT,
                "too-many-imports",
                "Too many imports running; wait for one to end",
            ),
            Self::SessionTooNew => (
                StatusCode::CONFLICT,
                "session-too-new",
                "The session was created by a newer version of NetSift",
            ),
            Self::SessionUpgradeFailed => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "session-upgrade-failed",
                "The session could not be upgraded to this version of NetSift",
            ),
            Self::SessionUpgradeNeeded => (
                StatusCode::CONFLICT,
                "session-upgrade-needed",
                "The session must be upgraded to this version of NetSift, which a read-only server does not do",
            ),
            Self::SessionBusy => (
                StatusCode::SERVICE_UNAVAILABLE,
                "session-busy",
                "The session is being upgraded by another request; try again",
            ),
            Self::GeoipDownloadFailed => (
                StatusCode::BAD_GATEWAY,
                "geoip-download-failed",
                "The GeoIP database could not be downloaded",
            ),
            Self::GeoipInvalid => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "geoip-invalid",
                "The file is not a usable country database",
            ),
            Self::GeoipTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "geoip-too-large",
                "The GeoIP database is larger than allowed",
            ),
            Self::GeoipUpdateRunning => (
                StatusCode::CONFLICT,
                "geoip-update-running",
                "A GeoIP update is already running",
            ),
            Self::TooManyExports => (
                StatusCode::CONFLICT,
                "too-many-exports",
                "Too many exports running; wait for one to end",
            ),
            Self::ExportSourceMissing(_) => (
                StatusCode::CONFLICT,
                "export-source-missing",
                "A capture file of the session is missing or unreadable",
            ),
            Self::ExportSourceModified(_) => (
                StatusCode::CONFLICT,
                "export-source-modified",
                "A capture file of the session changed since the import",
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "Internal error",
            ),
        }
    }
}

impl ApiError {
    /// Problem type URI (`urn:netsift:problem:<kind>`) and detail, as sent in the response.
    pub(crate) fn problem(&self) -> (String, Option<String>) {
        let (_, kind, _) = self.parts();
        let detail = match self {
            Self::BadRequest(d)
            | Self::Conflict(d)
            | Self::ExportSourceMissing(d)
            | Self::ExportSourceModified(d) => Some(d.clone()),
            Self::Forbidden(d) => Some((*d).to_owned()),
            _ => None,
        };
        (format!("urn:netsift:problem:{kind}"), detail)
    }

    /// Title of the problem (fixed text of its type).
    pub(crate) fn title(&self) -> &'static str {
        self.parts().2
    }

    /// HTTP status of the problem.
    pub(crate) fn status(&self) -> u16 {
        self.parts().0.as_u16()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, _, title) = self.parts();
        let (kind, detail) = self.problem();
        let body = Problem {
            kind: &kind,
            title,
            status: status.as_u16(),
            detail,
        };
        let mut res = (status, Json(body)).into_response();
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/problem+json"),
        );
        if matches!(self, Self::SessionBusy) {
            res.headers_mut()
                .insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
        }
        if matches!(self, Self::Unauthorized) {
            res.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Bearer"),
            );
        }
        res
    }
}

impl From<netsift_store::StoreError> for ApiError {
    fn from(e: netsift_store::StoreError) -> Self {
        use netsift_store::StoreError as E;
        match e {
            E::SessionNotFound(_) | E::InvalidSessionId | E::SessionFilesMissing { .. } => {
                Self::NotFound
            }
            E::InvalidCursor => Self::BadRequest("invalid pagination cursor".to_owned()),
            E::InvalidValue { field, reason } => Self::BadRequest(format!("{field}: {reason}")),
            E::SchemaTooNew { .. } => Self::SessionTooNew,
            // Only reachable for sessions that are not upgraded on opening (importing, failed).
            E::SchemaOutdated { .. } => Self::Conflict(
                "the session was created by an older version and is not upgraded in this state"
                    .to_owned(),
            ),
            E::UpgradeNeeded => Self::SessionUpgradeNeeded,
            E::SessionBusy => Self::SessionBusy,
            E::UpgradeFailed(source) => {
                tracing::error!("session upgrade failed: {source}");
                Self::SessionUpgradeFailed
            }
            other => {
                // Store errors carry paths and SQL details: logged, never returned.
                tracing::error!("store error: {other}");
                Self::Internal
            }
        }
    }
}

pub(crate) async fn not_found() -> ApiError {
    ApiError::NotFound
}

pub(crate) async fn method_not_allowed() -> ApiError {
    ApiError::MethodNotAllowed
}
