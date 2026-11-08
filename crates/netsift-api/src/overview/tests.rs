use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::Packet;
use netsift_fixtures::scenarios::{Kind, generate};
use netsift_fixtures::{Encoding, encode};
use netsift_store::{Catalog, OpenMode, Session, SessionState as StoreState};
use serde_json::Value;
use tower::ServiceExt;

use super::*;
use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "overview-token";

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

    async fn get(&self, uri: &str) -> (StatusCode, Option<String>, Value) {
        let req = Request::get(uri)
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let kind = res
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|v| v.to_str().unwrap().to_owned());
        let bytes = axum::body::to_bytes(res.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap();
        (status, kind, serde_json::from_slice(&bytes).unwrap())
    }

    /// Imports `packets` as one pcap file (blocking ingest, like `netsift ingest`).
    fn import(&self, name: &str, packets: &[Packet]) -> String {
        let path = self.captures.join(format!("{name}.pcap"));
        std::fs::write(&path, encode(packets, &Encoding::pcap()).unwrap()).unwrap();
        let options = IngestOptions {
            name: Some(name.to_owned()),
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

    /// Session registered in the catalog with hand-written time series rows.
    fn synthetic(&self, state: StoreState, sql: &str) -> String {
        let catalog = self.catalog();
        let info = catalog.create("synthetic", &[], 0).unwrap();
        let session = Session::open(catalog.session_dir(&info.id), OpenMode::ReadWrite).unwrap();
        session.conn().execute_batch(sql).unwrap();
        catalog.set_state(&info.id, state, None).unwrap();
        info.id.to_string()
    }
}

fn wire(packets: &[Packet]) -> (u64, u64) {
    let bytes = packets.iter().map(|p| p.data.len() as u64).sum();
    (bytes, packets.len() as u64)
}

fn series<'a>(json: &'a Value, protocol: &str) -> Option<&'a Value> {
    json["series"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["protocol"] == protocol)
}

fn sum(values: &Value) -> u64 {
    values
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .sum()
}

#[tokio::test]
async fn mixed_capture_shows_dns_http_and_tls_with_exact_totals() {
    let env = Env::new();
    let dns = generate(Kind::Dns, 4, 1);
    let http = generate(Kind::Http, 3, 2);
    let tls = generate(Kind::Tls, 5, 3);
    let mut all: Vec<Packet> = [dns.clone(), http.clone(), tls.clone()].concat();
    all.sort_by_key(|p| p.ts_ns);
    let id = env.import("mixed", &all);

    let (status, _, json) = env.get(&format!("/api/v1/sessions/{id}/timeseries")).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let ids: Vec<&str> = json["series"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["protocol"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["dns", "http", "tls"], "display order, nothing else");
    assert!(json["points"].as_u64().unwrap() <= u64::from(MAX_POINTS));
    for (protocol, packets) in [("dns", &dns), ("http", &http), ("tls", &tls)] {
        let s = series(&json, protocol).unwrap();
        let (bytes, count) = wire(packets);
        assert_eq!(s["total_bytes"], bytes, "{protocol}");
        assert_eq!(s["total_packets"], count, "{protocol}");
        // The buckets add up to the totals.
        assert_eq!(sum(&s["bytes"]), bytes, "{protocol}");
        assert_eq!(sum(&s["packets"]), count, "{protocol}");
        let points = usize::try_from(json["points"].as_u64().unwrap()).unwrap();
        assert_eq!(s["bytes"].as_array().unwrap().len(), points);
    }

    let (status, _, summary) = env.get(&format!("/api/v1/sessions/{id}/summary")).await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    let (bytes, count) = wire(&all);
    assert_eq!(summary["name"], "mixed");
    assert_eq!(summary["state"], "ready");
    assert_eq!(summary["packets"], count);
    assert_eq!(summary["bytes"], bytes);
    assert_eq!(summary["chunk_count"], 1);
    assert_eq!(summary["linktypes"], serde_json::json!([1]));
    assert_eq!(summary["anomaly_count"], 0);
    let first = summary["first_ts_us"].as_i64().unwrap();
    let last = summary["last_ts_us"].as_i64().unwrap();
    assert_eq!(summary["duration_us"], last - first);
    assert_eq!(first, all[0].ts_ns / 1000);
    assert!(summary["host_count"].as_u64().unwrap() >= 4);
    let flows = summary["flow_count"].as_u64().unwrap();
    assert!(flows > 0);
    // Modules backed by an existing table only; no table yet for DNS, HTTP, TLS.
    assert_eq!(
        summary["modules"],
        serde_json::json!([
            { "id": "connections", "count": flows },
            { "id": "hosts", "count": summary["host_count"] },
        ])
    );
}

#[tokio::test]
async fn a_day_of_traffic_is_resampled_to_at_most_2000_points() {
    let env = Env::new();
    let start: i64 = 1_767_225_600; // 2026-01-01T00:00:00Z
    // One row per second for TLS and NTP, one per minute for FTP.
    let sql = format!(
        "WITH RECURSIVE s(n) AS (SELECT 0 UNION ALL SELECT n + 1 FROM s WHERE n < 86399) \
         INSERT INTO timeseries (bucket_s, proto, bytes, packets) \
         SELECT {start} + n, 'tls', 1500, 1 FROM s \
         UNION ALL SELECT {start} + n, 'ntp', 90, 1 FROM s \
         UNION ALL SELECT {start} + n, 'ftp', 60, 1 FROM s WHERE n % 60 = 0;"
    );
    let id = env.synthetic(StoreState::Ready, &sql);

    // Warm: the first request opens the catalog.
    let _ = env.get(&format!("/api/v1/sessions/{id}/summary")).await;
    let started = std::time::Instant::now();
    let (status, _, json) = env.get(&format!("/api/v1/sessions/{id}/timeseries")).await;
    let elapsed = started.elapsed();
    assert_eq!(status, StatusCode::OK, "{json}");
    assert!(json["points"].as_u64().unwrap() <= u64::from(DEFAULT_POINTS));
    eprintln!("24 h resampled in {elapsed:?}");

    for points in ["2000", "5000", "4294967295"] {
        let (status, _, json) = env
            .get(&format!("/api/v1/sessions/{id}/timeseries?points={points}"))
            .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let n = json["points"].as_u64().unwrap();
        assert!((1000..=2000).contains(&n), "{n}");
        assert_eq!(json["step_us"], 60_000_000, "one-minute buckets");
        assert_eq!(json["start_us"], start * 1_000_000);
        let tls = series(&json, "tls").unwrap();
        assert_eq!(tls["bytes"].as_array().unwrap().len() as u64, n);
        assert_eq!(tls["total_bytes"], 86_400 * 1500);
        assert_eq!(tls["bytes"][0], 60 * 1500);
        assert_eq!(series(&json, "other_udp").unwrap()["total_packets"], 86_400);
        assert_eq!(series(&json, "other_tcp").unwrap()["total_packets"], 1_440);
    }

    // A zoomed period, a single metric, a subset of protocols.
    let from = (start + 3_600) * 1_000_000;
    let to = (start + 3_659) * 1_000_000 + 999_999;
    let (status, _, json) = env
        .get(&format!(
            "/api/v1/sessions/{id}/timeseries?from_us={from}&to_us={to}&metric=bytes&protocols=tls,dns"
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["points"], 60);
    assert_eq!(json["step_us"], 1_000_000);
    assert_eq!(
        json["series"].as_array().unwrap().len(),
        1,
        "no DNS traffic"
    );
    let tls = series(&json, "tls").unwrap();
    assert_eq!(tls["packets"], Value::Null);
    assert_eq!(tls["total_bytes"], 60 * 1500);
    assert_eq!(tls["total_packets"], 60);

    // `protocols=` (empty): nothing selected.
    let (_, _, json) = env
        .get(&format!("/api/v1/sessions/{id}/timeseries?protocols="))
        .await;
    assert_eq!(json["series"], serde_json::json!([]));
    assert!(json["points"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn empty_sessions_have_no_points_and_zero_figures() {
    let env = Env::new();
    let id = env.synthetic(StoreState::Incomplete, "");
    let (status, _, json) = env.get(&format!("/api/v1/sessions/{id}/timeseries")).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["points"], 0);
    assert_eq!(json["series"], serde_json::json!([]));
    let (status, _, summary) = env.get(&format!("/api/v1/sessions/{id}/summary")).await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    assert_eq!(summary["state"], "incomplete");
    assert_eq!(summary["packets"], 0);
    assert_eq!(summary["first_ts_us"], Value::Null);
    assert_eq!(summary["duration_us"], Value::Null);
    assert_eq!(summary["linktypes"], serde_json::json!([]));
}

#[tokio::test]
async fn unknown_importing_failed_and_invalid_requests_are_problems() {
    let env = Env::new();
    let importing = env.synthetic(StoreState::Importing, "");
    let failed = env.synthetic(StoreState::Failed, "");
    let ready = env.synthetic(StoreState::Ready, "");
    for route in ["summary", "timeseries"] {
        for (id, expected) in [
            ("01JC0000000000000000000000", StatusCode::NOT_FOUND),
            ("not-an-id", StatusCode::NOT_FOUND),
            (importing.as_str(), StatusCode::CONFLICT),
            (failed.as_str(), StatusCode::CONFLICT),
        ] {
            let (status, kind, json) = env.get(&format!("/api/v1/sessions/{id}/{route}")).await;
            assert_eq!(status, expected, "{route} {id}: {json}");
            assert_eq!(kind.as_deref(), Some("application/problem+json"));
        }
    }
    for query in [
        "protocols=dns,bogus",
        "metric=volume",
        "points=-1",
        "from_us=10000000&to_us=0",
        // Reversed within the same second.
        "from_us=1500000&to_us=1000000",
        "from_us=abc",
    ] {
        let (status, kind, json) = env
            .get(&format!("/api/v1/sessions/{ready}/timeseries?{query}"))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {json}");
        assert_eq!(kind.as_deref(), Some("application/problem+json"));
    }

    // The token is required.
    let req = Request::get(format!("/api/v1/sessions/{ready}/summary"))
        .body(Body::empty())
        .unwrap();
    let res = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn stored_labels_fold_into_the_chart_series() {
    use TrafficProtocol as P;
    for (label, expected) in [
        ("dns", P::Dns),
        ("http", P::Http),
        ("tls", P::Tls),
        ("smb", P::Smb),
        ("netbios", P::Netbios),
        ("ssh", P::Ssh),
        ("dhcp", P::Dhcp),
        ("snmp", P::Snmp),
        ("ftp", P::OtherTcp),
        ("tcp", P::OtherTcp),
        ("ldap", P::OtherTcp),
        ("udp", P::OtherUdp),
        ("ntp", P::OtherUdp),
        ("ssdp", P::OtherUdp),
        ("kerberos", P::Other),
        ("icmp", P::Other),
        ("non_ip", P::Other),
        ("ip", P::Other),
        ("other_tcp", P::Other),
        ("someday", P::Other),
    ] {
        assert_eq!(TrafficProtocol::of_label(label), expected, "{label}");
    }
    // Ids round-trip and match the serialized names.
    for p in TrafficProtocol::ALL {
        assert_eq!(TrafficProtocol::from_id(p.id()), Some(p));
        assert_eq!(serde_json::to_value(p).unwrap(), p.id());
    }
}

#[test]
fn module_registry_is_sorted_and_unique() {
    for pair in MODULES.windows(2) {
        assert!(pair[0].0 < pair[1].0, "{pair:?}");
    }
}
