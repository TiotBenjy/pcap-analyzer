//! Bearer-token authentication for every route except health.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::Response;

use crate::{ApiError, AppState};

pub(crate) async fn require_bearer(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match provided {
        Some(token) if token_matches(token.as_bytes(), state.config.token.as_bytes()) => {
            Ok(next.run(req).await)
        }
        _ => Err(ApiError::Unauthorized),
    }
}

/// Constant-time comparison (no early exit on the first differing byte). An empty expected
/// token never matches, so a misconfigured server cannot run unauthenticated.
fn token_matches(provided: &[u8], expected: &[u8]) -> bool {
    if expected.is_empty() || provided.len() != expected.len() {
        return false;
    }
    provided
        .iter()
        .zip(expected)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::token_matches;

    #[test]
    fn compares_tokens() {
        assert!(token_matches(b"abc", b"abc"));
        assert!(!token_matches(b"abd", b"abc"));
        assert!(!token_matches(b"ab", b"abc"));
        assert!(!token_matches(b"", b""));
    }
}
