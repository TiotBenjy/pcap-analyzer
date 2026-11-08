use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::proto::netbios::NetbiosName;
use netsift_fixtures::scenarios::{Kind, hosts};
use netsift_fixtures::{Encoding, Scenario, encode};
use netsift_store::{Catalog, OpenMode, Session, SessionState as StoreState};
use serde_json::Value;
use tower::ServiceExt;

use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "dns-token";

struct Env {
    _tmp: tempfile::TempDir,
    data: PathBuf,
    captures: PathBuf,
    app: Router,
}

impl Env {
    fn new() -> Self {
        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        let captures = tmp.path().join("captures");
        std::fs::create_dir_all(&captures).unwrap();
        let config = ApiConfig {
            token: TOKEN.to_owned(),
            data_dir: data.clone(),
            captures_roots: vec![captures.clone()],
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
            captures,
            app,
        }
    }

    fn catalog(&self) -> Catalog {
        Catalog::open(&self.data).unwrap()
    }

    async fn get(&self, uri: &str) -> (StatusCode, Value) {
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

    /// Demo traffic (DNS, NBNS...) plus an unanswered NBNS query for WPAD.
    fn import_demo(&self) -> String {
        let mut sc = Scenario::new().with_seed(3);
        for _ in 0..3 {
            Kind::Demo.append_to(&mut sc);
            sc.advance(1_000_000_000);
        }
        sc.nbns_query(
            hosts::workstation(),
            hosts::broadcast(),
            0x4444,
            &NetbiosName::new("WPAD", 0),
        );
        let path = self.captures.join("demo.pcap");
        std::fs::write(&path, encode(sc.packets(), &Encoding::pcap()).unwrap()).unwrap();
        let options = IngestOptions {
            name: Some("demo".to_owned()),
            ..IngestOptions::default()
        };
        let report = ingest(
            &self.catalog(),
            &path,
            &options,
            &CancelToken::new(),
            &mut |_| {},
        )
        .unwrap();
        report.session.to_string()
    }
}

fn base(id: &str) -> String {
    format!("/api/v1/sessions/{id}/dns")
}

fn count_of(list: &Value, field: &str, key: &str) -> u64 {
    list.as_array()
        .unwrap()
        .iter()
        .find(|e| e[field] == key)
        .map_or(0, |e| e["count"].as_u64().unwrap())
}

#[tokio::test]
async fn stats_pairs_and_messages() {
    let env = Env::new();
    let id = env.import_demo();

    let (status, stats) = env.get(&format!("{}/stats", base(&id))).await;
    assert_eq!(status, StatusCode::OK, "{stats}");
    // Per round: 4 DNS exchanges, NBNS registration + answered query; plus the WPAD query.
    assert_eq!(stats["total"], 3 * 6 + 1);
    assert_eq!(count_of(&stats["protocols"], "protocol", "dns"), 12);
    assert_eq!(count_of(&stats["protocols"], "protocol", "nbns"), 7);
    assert_eq!(count_of(&stats["rcodes"], "key", "NXDOMAIN"), 3);
    assert_eq!(count_of(&stats["rcodes"], "key", "timeout"), 1);
    assert_eq!(stats["errors"], 4);
    assert_eq!(count_of(&stats["qtypes"], "key", "AAAA"), 3);
    assert_eq!(stats["countries"], serde_json::json!([]));
    assert!(stats["latency_p50_us"].as_i64().is_some());

    let (status, pairs) = env.get(&format!("{}/pairs?limit=2", base(&id))).await;
    assert_eq!(status, StatusCode::OK, "{pairs}");
    let items = pairs["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    let first = &items[0];
    assert_eq!(first["protocol"], "dns");
    assert_eq!(first["client"]["ip"], "192.168.1.10");
    assert_eq!(first["server"]["ip"], "192.168.1.1");
    assert_eq!(first["messages"], 9);
    assert_eq!(first["errors"], 3);
    assert_eq!(first["name_count"], 3);
    assert_eq!(first["server"]["category"], "private");
    let total = pairs["total_estimate"].as_u64().unwrap();
    assert!(total >= 4);

    // Every pair once, page after page.
    let mut seen = items.len();
    let mut cursor = pairs["next_cursor"].as_str().map(str::to_owned);
    while let Some(c) = cursor {
        let (_, page) = env
            .get(&format!("{}/pairs?limit=2&cursor={c}", base(&id)))
            .await;
        seen += page["items"].as_array().unwrap().len();
        cursor = page["next_cursor"].as_str().map(str::to_owned);
    }
    assert_eq!(seen as u64, total);

    let pair = first["id"].as_str().unwrap();
    let (status, msgs) = env
        .get(&format!("{}/messages?pair={pair}&limit=100", base(&id)))
        .await;
    assert_eq!(status, StatusCode::OK, "{msgs}");
    let list = msgs["items"].as_array().unwrap();
    assert_eq!(list.len(), 9);
    assert!(
        list.windows(2)
            .all(|w| w[0]["ts_us"].as_i64() <= w[1]["ts_us"].as_i64())
    );
    let www = list
        .iter()
        .find(|m| m["qname"] == "www.example.test")
        .unwrap();
    assert_eq!(www["rcode"], "NOERROR");
    assert_eq!(www["transport"], "udp");
    assert_eq!(www["answers"][0]["type"], "A");
    assert_eq!(www["answers"][0]["value"], "203.0.113.80");
    assert!(www["latency_us"].as_i64().is_some());
    assert!(www["flow_id"].is_string());
}

#[tokio::test]
async fn search_and_filters() {
    let env = Env::new();
    let id = env.import_demo();

    // Search "wpad" finds the NBNS query.
    let (status, found) = env.get(&format!("{}/messages?q=wpad", base(&id))).await;
    assert_eq!(status, StatusCode::OK, "{found}");
    let items = found["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["protocol"], "nbns");
    assert_eq!(items[0]["qname"], "WPAD");
    assert_eq!(items[0]["nb_suffix"], 0);
    assert_eq!(items[0]["rcode"], "timeout");
    let (_, pairs) = env.get(&format!("{}/pairs?q=WPAD", base(&id))).await;
    assert_eq!(pairs["total_estimate"], 1);

    let (_, nbns) = env
        .get(&format!("{}/pairs?protocols=nbns", base(&id)))
        .await;
    assert!(
        nbns["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["protocol"] == "nbns")
    );
    let (_, none) = env.get(&format!("{}/pairs?protocols=", base(&id))).await;
    assert_eq!(none["total_estimate"], 0);
    let (_, errors) = env
        .get(&format!("{}/messages?errors=true", base(&id)))
        .await;
    assert_eq!(errors["total_estimate"], 4);
    let (_, short) = env.get(&format!("{}/messages?q=mi", base(&id))).await;
    assert_eq!(short["total_estimate"], 3);

    let (status, servers) = env.get(&format!("{}/servers", base(&id))).await;
    assert_eq!(status, StatusCode::OK, "{servers}");
    assert_eq!(servers["items"][0]["host"]["ip"], "192.168.1.1");
    assert_eq!(servers["items"][0]["protocols"], serde_json::json!(["dns"]));
}

#[tokio::test]
async fn invalid_requests() {
    let env = Env::new();
    let id = env.import_demo();
    for uri in [
        format!("{}/pairs?protocols=dns,ftp", base(&id)),
        format!("{}/messages?pair=abc", base(&id)),
        format!("{}/pairs?cursor=zz", base(&id)),
        format!("{}/messages?errors=maybe", base(&id)),
        format!("{}/messages?q={}", base(&id), "a".repeat(300)),
    ] {
        let (status, body) = env.get(&uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
    }
    let (status, _) = env
        .get("/api/v1/sessions/01ARZ3NDEKTSV4RRFFQ69G5FAV/dns/stats")
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn sessions_without_dns_tables_answer_empty() {
    let env = Env::new();
    let catalog = env.catalog();
    let info = catalog.create("old", &[], 0).unwrap();
    let session = Session::open(catalog.session_dir(&info.id), OpenMode::ReadWrite).unwrap();
    session
        .conn()
        .execute_batch("DROP TABLE dns_fts; DROP TABLE dns_pairs; DROP TABLE dns_messages;")
        .unwrap();
    drop(session);
    catalog
        .set_state(&info.id, StoreState::Ready, None)
        .unwrap();
    let id = info.id.to_string();
    let (status, stats) = env.get(&format!("{}/stats", base(&id))).await;
    assert_eq!(status, StatusCode::OK, "{stats}");
    assert_eq!(stats["total"], 0);
    for list in ["pairs", "messages", "servers"] {
        let (status, page) = env.get(&format!("{}/{list}", base(&id))).await;
        assert_eq!(status, StatusCode::OK, "{list}: {page}");
        assert_eq!(page["items"], serde_json::json!([]));
    }
}
