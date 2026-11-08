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
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "Internal error",
            ),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, kind, title) = self.parts();
        let detail = match &self {
            Self::BadRequest(d) | Self::Conflict(d) => Some(d.clone()),
            Self::Forbidden(d) => Some((*d).to_owned()),
            _ => None,
        };
        let body = Problem {
            kind: &format!("urn:netsift:problem:{kind}"),
            title,
            status: status.as_u16(),
            detail,
        };
        let mut res = (status, Json(body)).into_response();
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/problem+json"),
        );
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
