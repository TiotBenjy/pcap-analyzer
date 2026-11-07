use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

use super::*;

fn config() -> ApiConfig {
    ApiConfig {
        token: "s3cret-token".to_owned(),
        data_dir: PathBuf::from("/nonexistent"),
        captures_roots: vec![],
        read_only: true,
        cors_origins: vec![HeaderValue::from_static("tauri://localhost")],
    }
}

async fn send(req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
    let res = router(config()).oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, headers, json)
}

fn get(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).unwrap()
}

#[test]
fn smoke() {
    assert_eq!(CRATE_NAME, "netsift-api");
}

#[tokio::test]
async fn health_is_public() {
    let (status, _, json) = send(get("/api/v1/health")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "ok");
    assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn protected_routes_require_the_token() {
    let (status, headers, json) = send(get("/api/v1/server-info")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json");
    assert_eq!(headers[header::WWW_AUTHENTICATE], "Bearer");
    assert_eq!(json["status"], 401);

    let wrong = Request::get("/api/v1/server-info")
        .header(header::AUTHORIZATION, "Bearer nope")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(wrong).await.0, StatusCode::UNAUTHORIZED);

    let ok = Request::get("/api/v1/server-info")
        .header(header::AUTHORIZATION, "Bearer s3cret-token")
        .body(Body::empty())
        .unwrap();
    let (status, _, json) = send(ok).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["read_only"], true);
    assert_eq!(json["can_browse"], false);
}

#[tokio::test]
async fn unknown_routes_are_problem_json_404() {
    for uri in ["/api/v1/nope", "/elsewhere"] {
        let (status, headers, json) = send(get(uri)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json");
        assert_eq!(json["type"], "urn:netsift:problem:not-found");
    }
}

#[tokio::test]
async fn cors_allows_only_configured_origins() {
    let preflight = |origin: &'static str| {
        Request::builder()
            .method("OPTIONS")
            .uri("/api/v1/server-info")
            .header(header::ORIGIN, origin)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
            .body(Body::empty())
            .unwrap()
    };
    let (_, headers, _) = send(preflight("tauri://localhost")).await;
    assert_eq!(
        headers[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "tauri://localhost"
    );
    let (_, headers, _) = send(preflight("http://evil.example")).await;
    assert!(headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
}

#[tokio::test]
async fn serve_binds_and_shuts_down() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve(listener, config(), async {
        let _ = rx.await;
    }));
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 200"));
    tx.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn wrong_method_is_problem_json_405() {
    let req = Request::post("/api/v1/health").body(Body::empty()).unwrap();
    let (status, headers, json) = send(req).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json");
    assert_eq!(json["type"], "urn:netsift:problem:method-not-allowed");
}

#[test]
fn debug_never_prints_the_token() {
    let printed = format!("{:?}", config());
    assert!(!printed.contains("s3cret-token"));
    assert!(printed.contains("<redacted>"));
}
