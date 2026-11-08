use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::scenario::{HttpGet, Scenario, TcpOptions};
use netsift_fixtures::scenarios::hosts;
use netsift_fixtures::{Encoding, encode};
use netsift_store::Catalog;
use serde_json::Value;
use tower::ServiceExt;

use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "http-token";

struct Env {
    _tmp: tempfile::TempDir,
    data: PathBuf,
    app: Router,
    id: String,
}

/// Keep-alive connection (GET with a cookie, POST with credentials, 404), a request without
/// response, and the fixtures image download.
fn capture() -> Vec<u8> {
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(
        hosts::workstation(),
        hosts::web_server(),
        &TcpOptions::new(80),
    );
    s.client_send(
        b"GET /index.html?lang=fr HTTP/1.1\r\nHost: www.example.test\r\nUser-Agent: curl/8.5\r\n\
          Cookie: sid=AbCdEf987654\r\n\r\n",
    );
    s.server_send(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: sid=AbCdEf987654\r\n\
          Content-Length: 13\r\n\r\n<p>hello</p>\n",
    );
    s.client_send(
        b"POST /login HTTP/1.1\r\nHost: www.example.test\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\
          Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 13\r\n\r\nuser=a&pass=b",
    );
    s.server_send(b"HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\n\r\n");
    s.client_send(b"GET /missing HTTP/1.1\r\nHost: www.example.test\r\n\r\n");
    s.server_send(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    s.close();
    sc.advance(5_000_000);
    let mut s = sc.tcp_open(
        hosts::workstation(),
        hosts::web_server(),
        &TcpOptions::new(8080),
    );
    s.client_send(b"OPTIONS * HTTP/1.1\r\nHost: other.test:8080\r\n\r\n");
    s.close();
    sc.advance(5_000_000);
    sc.http_get(
        hosts::workstation(),
        hosts::web_server(),
        &HttpGet::default(),
    );
    encode(sc.packets(), &Encoding::pcap()).unwrap()
}

impl Env {
    fn new() -> Self {
        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        let path = tmp.path().join("http.pcap");
        std::fs::write(&path, capture()).unwrap();
        let catalog = Catalog::open(&data).unwrap();
        let report = ingest(
            &catalog,
            &path,
            &IngestOptions::default(),
            &CancelToken::new(),
            &mut |_| {},
        )
        .unwrap();
        let config = ApiConfig {
            token: TOKEN.to_owned(),
            data_dir: data.clone(),
            captures_roots: vec![],
            read_only: true,
            cors_origins: vec![HeaderValue::from_static("tauri://localhost")],
            allow_any_path: false,
            max_imports: DEFAULT_MAX_IMPORTS,
            geoip_path: None,
        };
        let (app, _) = build(config, IngestOptions::default());
        Self {
            _tmp: tmp,
            data,
            app,
            id: report.session.to_string(),
        }
    }

    async fn get(&self, path: &str) -> (StatusCode, Value) {
        let uri = format!("/api/v1/sessions/{}{path}", self.id);
        let req = Request::get(uri)
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
}

fn paths(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["path"].as_str().unwrap_or("-").to_owned())
        .collect()
}

#[tokio::test]
async fn stats_count_methods_statuses_and_tops() {
    let env = Env::new();
    let (status, s) = env.get("/http/stats").await;
    assert_eq!(status, StatusCode::OK, "{s}");
    assert_eq!(s["transactions"], 5);
    assert_eq!(
        s["methods"],
        serde_json::json!([
            { "key": "GET", "count": 3 },
            { "key": "POST", "count": 1 },
            { "key": "OPTIONS", "count": 1 },
        ])
    );
    assert_eq!(
        s["status_classes"],
        serde_json::json!([
            { "key": "2xx", "count": 2 },
            { "key": "3xx", "count": 1 },
            { "key": "4xx", "count": 1 },
            { "key": "none", "count": 1 },
        ])
    );
    assert_eq!(
        s["hosts"][0],
        serde_json::json!({ "key": "www.example.test", "count": 4 })
    );
    assert_eq!(s["host_count"], 2);
    assert_eq!(s["content_types"].as_array().unwrap().len(), 2);
    assert!(s["rare_headers"].as_array().unwrap().len() <= 10);
}

#[tokio::test]
async fn transactions_are_filtered_sorted_and_paginated() {
    let env = Env::new();
    let (status, page) = env.get("/http/transactions?order=asc").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(
        paths(&page),
        ["/index.html", "/login", "/missing", "*", "/images/logo.png"]
    );
    assert_eq!(page["total_estimate"], 5);
    let first = &page["items"][0];
    assert_eq!(first["method"], "GET");
    assert_eq!(first["query"], "lang=fr");
    assert_eq!(first["status"], 200);
    assert_eq!(first["client"]["ip"], "192.168.1.10");
    assert_eq!(first["client"]["category"], "private");
    assert_eq!(first["server_port"], 80);
    assert!(first["server"]["names"].is_array());
    assert!(first["flow_id"].is_string());
    assert!(first["response_time_us"].as_i64().unwrap() > 0);

    let (_, page) = env
        .get("/http/transactions?method=GET&status=2xx,4xx&order=asc")
        .await;
    assert_eq!(
        paths(&page),
        ["/index.html", "/missing", "/images/logo.png"]
    );
    let (_, page) = env.get("/http/transactions?status=none").await;
    assert_eq!(paths(&page), ["*"]);
    let (_, page) = env.get("/http/transactions?method=").await;
    assert_eq!(paths(&page), Vec::<String>::new());
    let (_, page) = env.get("/http/transactions?q=logo").await;
    assert_eq!(paths(&page), ["/images/logo.png"]);
    let (_, page) = env.get("/http/transactions?host=other.test:8080").await;
    assert_eq!(paths(&page), ["*"]);
    let (_, page) = env.get("/http/transactions?sort=size&limit=1").await;
    assert_eq!(paths(&page), ["/images/logo.png"]);

    // Keyset pages, default order (newest first).
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let path = match &cursor {
            Some(c) => format!("/http/transactions?limit=2&cursor={c}"),
            None => "/http/transactions?limit=2".to_owned(),
        };
        let (status, page) = env.get(&path).await;
        assert_eq!(status, StatusCode::OK);
        seen.extend(paths(&page));
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => break,
        }
    }
    assert_eq!(
        seen,
        ["/images/logo.png", "*", "/missing", "/login", "/index.html"]
    );
}

#[tokio::test]
async fn invalid_filters_are_bad_requests() {
    let env = Env::new();
    for q in [
        "method=FOO",
        "status=2x",
        "sort=random",
        "order=up",
        "cursor=zz",
    ] {
        let (status, body) = env.get(&format!("/http/transactions?{q}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{q}: {body}");
    }
    let long = "x".repeat(300);
    let (status, _) = env.get(&format!("/http/headers?q={long}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn detail_returns_both_messages_with_headers() {
    let env = Env::new();
    let (_, page) = env.get("/http/transactions?method=POST").await;
    let id = page["items"][0]["id"].as_i64().unwrap();
    let (status, d) = env.get(&format!("/http/transactions/{id}")).await;
    assert_eq!(status, StatusCode::OK, "{d}");
    assert_eq!(d["summary"]["path"], "/login");
    let req = &d["request"];
    assert_eq!(req["headers"][1]["name"], "Authorization");
    assert_eq!(req["headers"][1]["value"], "Basic dXNlcjpwYXNz");
    assert_eq!(req["body_size"], 13);
    assert_eq!(req["preview"], "user=a&pass=b");
    assert_eq!(d["response"]["headers"][0]["name"], "Location");
    assert!(d["flow_first_ts_us"].as_i64().is_some());

    let (_, page) = env.get("/http/transactions?q=logo").await;
    let id = page["items"][0]["id"].as_i64().unwrap();
    let (_, d) = env.get(&format!("/http/transactions/{id}")).await;
    assert_eq!(d["response"]["mime_magic"], "image/png");
    assert_eq!(d["response"]["preview"], Value::Null);

    for missing in ["999999", "abc"] {
        let (status, _) = env.get(&format!("/http/transactions/{missing}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn header_search_finds_the_cookie_value() {
    let env = Env::new();
    let (status, stats) = env.get("/http/headers/stats").await;
    assert_eq!(status, StatusCode::OK, "{stats}");
    assert_eq!(stats["transactions"], 5);
    let names = stats["names"].as_array().unwrap();
    assert!(
        names.contains(&serde_json::json!({ "key": "host", "count": 5 })),
        "{names:?}"
    );
    let (_, page) = env.get("/http/headers?q=cdef98").await;
    assert_eq!(paths(&page), ["/index.html"]);
    let (_, page) = env.get("/http/headers?name=Authorization").await;
    assert_eq!(paths(&page), ["/login"]);
    let (_, page) = env.get("/http/headers?name=host&method=OPTIONS").await;
    assert_eq!(paths(&page), ["*"]);
}

#[tokio::test]
async fn unknown_sessions_are_not_found() {
    let env = Env::new();
    let uri = "/api/v1/sessions/01JC0000000000000000000000/http/stats";
    let req = Request::get(uri)
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap();
    let res = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(env.data.is_dir());
}
