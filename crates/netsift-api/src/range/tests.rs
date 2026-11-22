//! Global time filter over the routes of P5.2a, on the spread fixture: three bursts of mixed
//! traffic ten minutes apart and one long connection across them (`netsift_fixtures::spread`).
//! The aggregated views (P5.2b) are tested in `aggregate_tests.rs` with the same environment.

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::spread::{Spread, spread, spread_with};
use netsift_fixtures::{Encoding, encode};
use netsift_store::Catalog;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::{ApiConfig, AppState, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "range-token";

pub(super) struct Env {
    pub(super) tmp: tempfile::TempDir,
    app: Router,
    pub(super) id: String,
    pub(super) spread: Spread,
    pub(super) state: Arc<AppState>,
}

/// The filtered routes (paths relative to the session): P5.2a, then the aggregated views (P5.2b).
const ROUTES: &[&str] = &[
    "/modules",
    "/connections",
    "/connections?sort=first_ts&order=asc",
    "/connections/stats",
    "/connections/top",
    "/open-ports",
    "/open-ports/stats",
    "/servers",
    "/network/graph",
    "/network/graph?mode=countries",
    "/network/graph?include_orphans=true",
    "/summary",
    "/dns/stats",
    "/dns/pairs",
    "/dns/servers",
    "/dns/messages",
    "/ethernet/stats",
    "/ethernet/macs",
    "/ethernet/pairs",
    "/http/stats",
    "/http/transactions",
    "/http/transactions?sort=size&order=desc",
    "/http/headers/stats",
    "/http/headers",
    "/tls/stats",
    "/tls/sessions",
    "/tls/certificates",
    "/smb/announces",
    "/smb/stats",
    "/smb/auth",
    "/credentials",
    "/credentials/stats",
    "/credentials/paths",
    "/objects",
    "/objects/stats",
];

impl Env {
    pub(super) fn new() -> Self {
        Self::with(spread(), true)
    }

    /// A server that may write: range databases go to the session directory.
    pub(super) fn writable() -> Self {
        Self::with(spread(), false)
    }

    /// Many bursts: one burst is a narrow share of every table (narrow plan of the aggregates).
    fn many() -> Self {
        Self::with(spread_with(40), true)
    }

    fn with(spread: Spread, read_only: bool) -> Self {
        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        let captures = tmp.path().join("captures");
        std::fs::create_dir_all(&captures).unwrap();
        let path: PathBuf = captures.join("spread.pcap");
        std::fs::write(&path, encode(&spread.packets, &Encoding::pcap()).unwrap()).unwrap();
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
            data_dir: data,
            captures_roots: vec![captures],
            read_only,
            cors_origins: vec![HeaderValue::from_static("tauri://localhost")],
            allow_any_path: false,
            max_imports: DEFAULT_MAX_IMPORTS,
            geoip_fallback_path: None,
        };
        let (app, state) = build(config, IngestOptions::default());
        Self {
            tmp,
            app,
            id: report.session.to_string(),
            spread,
            state,
        }
    }

    /// `method` on a path of the session.
    pub(super) async fn request(&self, method: &str, path: &str) -> StatusCode {
        let req = Request::builder()
            .method(method)
            .uri(format!("/api/v1/sessions/{}{path}", self.id))
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .header(header::ORIGIN, "tauri://localhost")
            .body(Body::empty())
            .unwrap();
        self.app.clone().oneshot(req).await.unwrap().status()
    }

    pub(super) async fn raw(&self, path: &str) -> (StatusCode, Vec<u8>) {
        let req = Request::get(format!("/api/v1/sessions/{}{path}", self.id))
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 24)
            .await
            .unwrap();
        (status, bytes.to_vec())
    }

    pub(super) async fn json(&self, path: &str) -> Value {
        let (status, body) = self.raw(path).await;
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(status, StatusCode::OK, "{path}: {json}");
        json
    }

    /// `path` with the range of burst `i` (its first and last packet, inclusive microseconds).
    pub(super) fn burst(&self, path: &str, i: usize) -> String {
        self.bursts(path, i, i)
    }

    /// `path` with the range from the start of burst `first` to the end of burst `last`.
    pub(super) fn bursts(&self, path: &str, first: usize, last: usize) -> String {
        with_range(
            path,
            self.spread.bursts[first].0.div_euclid(1000),
            self.spread.bursts[last].1.div_euclid(1000),
        )
    }
}

pub(super) fn with_range(path: &str, from_us: i64, to_us: i64) -> String {
    let sep = if path.contains('?') { '&' } else { '?' };
    format!("{path}{sep}from_us={from_us}&to_us={to_us}")
}

pub(super) fn total(page: &Value) -> u64 {
    page["total_estimate"].as_u64().unwrap()
}

pub(super) fn items(page: &Value) -> &Vec<Value> {
    page["items"].as_array().unwrap()
}

pub(super) fn module(summary: &Value, id: &str) -> (u64, Value) {
    let m = summary["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == id)
        .unwrap_or_else(|| panic!("module {id} missing: {summary}"));
    (m["count"].as_u64().unwrap(), m["scope"].clone())
}

#[tokio::test]
async fn invalid_ranges_are_problem_documents() {
    let env = Env::new();
    for query in [
        "from_us=20&to_us=10",
        "from_us=abc",
        "to_us=1.5",
        "from_us=9223372036854775807",
        "to_us=-9223372036854775807",
    ] {
        for route in ["/summary", "/dns/messages", "/tls/stats"] {
            let (status, body) = env.raw(&format!("{route}?{query}")).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{route}?{query}");
            let doc: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(doc["type"], "urn:netsift:problem:bad-request", "{doc}");
        }
    }
    let (status, body) = env.raw("/dns/messages?from_us=20&to_us=10").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let doc: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        doc["detail"]
            .as_str()
            .unwrap()
            .contains("end is before the start"),
        "{doc}"
    );
}

#[tokio::test]
async fn a_range_covering_the_session_changes_nothing() {
    let env = Env::new();
    for route in ROUTES {
        let (_, plain) = env.raw(route).await;
        for (from, to) in [
            (0, i64::MAX / 1000 - 1),
            (-1_000_000, 4_000_000_000_000_000),
        ] {
            let (status, ranged) = env.raw(&with_range(route, from, to)).await;
            assert_eq!(status, StatusCode::OK, "{route}");
            assert_eq!(
                String::from_utf8_lossy(&plain),
                String::from_utf8_lossy(&ranged),
                "{route}"
            );
        }
        // One bound alone covers the session too.
        let (_, ranged) = env
            .raw(&format!(
                "{route}{}from_us=0",
                if route.contains('?') { '&' } else { '?' }
            ))
            .await;
        assert_eq!(plain, ranged, "{route}");
    }
}

#[tokio::test]
async fn a_range_outside_the_session_is_empty() {
    let env = Env::new();
    let path = |p: &str| with_range(p, 1_000, 2_000);
    for route in [
        "/dns/messages",
        "/dns/pairs",
        "/http/transactions",
        "/tls/sessions",
    ] {
        let page = env.json(&path(route)).await;
        assert!(items(&page).is_empty(), "{route}: {page}");
        assert_eq!(total(&page), 0, "{route}");
    }
    for route in [
        "/smb/announces",
        "/smb/auth",
        "/credentials",
        "/objects",
        "/tls/certificates",
        "/connections",
        "/open-ports",
    ] {
        let page = env.json(&path(route)).await;
        assert!(items(&page).is_empty(), "{route}: {page}");
    }
    let summary = env.json(&path("/summary")).await;
    let range = &summary["range"];
    assert_eq!(range["packets"], 0);
    assert_eq!(range["flow_count"], 0);
    assert_eq!(range["duration_us"], 0);
    for m in summary["modules"].as_array().unwrap() {
        if m["scope"] == "range" {
            assert_eq!(m["count"], 0, "{m}");
        }
    }
    assert_eq!(env.json(&path("/dns/stats")).await["total"], 0);
    assert_eq!(env.json(&path("/http/stats")).await["transactions"], 0);
    assert_eq!(env.json(&path("/tls/stats")).await["sessions"], 0);
    let stats = env.json(&path("/connections/stats")).await;
    assert_eq!(stats["sources"]["total_bytes"], 0);
    assert_eq!(
        env.json(&path("/connections/top")).await["conversations"],
        0
    );
    assert_eq!(env.json(&path("/open-ports/stats")).await["open_ports"], 0);
    let modules = env.json(&path("/modules")).await;
    assert!(
        modules["modules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["count"] == 0),
        "{modules}"
    );
    assert_eq!(env.json(&path("/network/graph")).await["hosts"], 0);
    let servers = env.json(&path("/servers")).await;
    assert!(
        servers["roles"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["total"] == 0),
        "{servers}"
    );
}

#[tokio::test]
async fn dns_and_http_keep_the_records_of_the_middle_burst() {
    let env = Env::new();
    let b = |p: &str| env.burst(p, 1);
    let summary = env.json(&b("/summary")).await;

    // DNS: the two exchanges of the burst, one pair, the same totals everywhere.
    let messages = env.json(&b("/dns/messages")).await;
    let names: Vec<&str> = items(&messages)
        .iter()
        .map(|m| m["qname"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "burst1.example.test",
            "missing1.example.test",
            "burst1.example.test"
        ]
    );
    let dns = env.json(&b("/dns/stats")).await;
    assert_eq!(dns["total"], 3);
    assert_eq!(dns["errors"], 1);
    assert_eq!(module(&summary, "dns"), (3, json!("range")));
    let pairs = env.json(&b("/dns/pairs")).await;
    assert_eq!(total(&pairs), 2);
    let pair = &items(&pairs)[0];
    assert_eq!(pair["messages"], 2);
    assert_eq!(pair["errors"], 1);
    assert_eq!(pair["name_count"], 2);
    let session_pairs = env.json("/dns/pairs").await;
    let session_pair = &items(&session_pairs)[0];
    assert_eq!(session_pair["messages"], 6);
    assert_eq!(pair["id"], session_pair["id"]);
    let expanded = env
        .json(&b(&format!(
            "/dns/messages?pair={}",
            pair["id"].as_str().unwrap()
        )))
        .await;
    assert_eq!(total(&expanded), 2);
    let servers = env.json(&b("/dns/servers")).await;
    assert_eq!(items(&servers)[0]["messages"], 2);

    // HTTP: the image of the burst and the shared one.
    let http = env.json(&b("/http/transactions")).await;
    assert_eq!(total(&http), 2);
    let http_stats = env.json(&b("/http/stats")).await;
    assert_eq!(http_stats["transactions"], 2);
    assert_eq!(module(&summary, "http"), (2, json!("range")));
    let by_size = env
        .json(&b("/http/transactions?sort=size&order=desc"))
        .await;
    assert_eq!(total(&by_size), 2);
    let header_stats = env.json(&b("/http/headers/stats")).await;
    assert_eq!(header_stats["transactions"], 2);
    let session_headers = env.json("/http/headers/stats").await;
    assert_eq!(
        header_stats["header_count"].as_u64().unwrap() * 3,
        session_headers["header_count"].as_u64().unwrap()
    );
    assert_eq!(
        module(&summary, "httpHeaders"),
        (
            header_stats["header_count"].as_u64().unwrap(),
            json!("range")
        )
    );
    assert_eq!(total(&env.json(&b("/http/headers")).await), 2);
}

#[tokio::test]
async fn tls_and_smb_keep_the_records_of_the_middle_burst() {
    let env = Env::new();
    let b = |p: &str| env.burst(p, 1);
    let summary = env.json(&b("/summary")).await;
    // TLS: one session, its certificate only.
    let tls = env.json(&b("/tls/sessions")).await;
    assert_eq!(total(&tls), 1);
    assert_eq!(items(&tls)[0]["sni"], "burst1.example.test");
    let tls_stats = env.json(&b("/tls/stats")).await;
    assert_eq!(tls_stats["sessions"], 1);
    assert_eq!(tls_stats["certificates"], 1);
    let certs = env.json(&b("/tls/certificates")).await;
    assert_eq!(total(&certs), 1);
    assert_eq!(items(&certs)[0]["sessions"], 1);
    assert_eq!(module(&summary, "tls"), (1, json!("range")));

    // SMB: the announcement folded over the three bursts overlaps, with its session count;
    // one NTLM session of its own.
    let announces = env.json(&b("/smb/announces")).await;
    assert_eq!(total(&announces), 1);
    assert_eq!(items(&announces)[0]["announce_count"], 3);
    let auth = env.json(&b("/smb/auth")).await;
    assert_eq!(total(&auth), 1);
    assert_eq!(items(&auth)[0]["account"], "user1");
    let smb = env.json(&b("/smb/stats")).await;
    assert_eq!(smb["announce_count"], 1);
    assert_eq!(smb["auth_count"], 1);
    let smb_rows = smb["announce_count"].as_u64().unwrap() + smb["session_count"].as_u64().unwrap();
    assert_eq!(module(&summary, "smb"), (smb_rows, json!("range")));
}

#[tokio::test]
async fn credentials_and_pictures_keep_the_records_of_the_middle_burst() {
    let env = Env::new();
    let b = |p: &str| env.burst(p, 1);
    let summary = env.json(&b("/summary")).await;
    // Credentials: the FTP and NTLM accounts of the burst, and the SNMP community folded over
    // the three bursts (its count is that of the session).
    let creds = env.json(&b("/credentials")).await;
    let stats = env.json(&b("/credentials/stats")).await;
    assert_eq!(total(&creds), stats["total"].as_u64().unwrap());
    assert_eq!(module(&summary, "credentials").0, total(&creds));
    let users: Vec<&str> = items(&creds)
        .iter()
        .filter_map(|c| c["username"].as_str())
        .collect();
    assert!(
        users.contains(&"ftpuser1") && users.contains(&"user1"),
        "{users:?}"
    );
    assert!(
        !users.contains(&"ftpuser0") && !users.contains(&"ftpuser2"),
        "{users:?}"
    );
    let snmp = items(&creds)
        .iter()
        .find(|c| c["protocol"] == "snmp")
        .expect("snmp community");
    // Its count is that of the session (shown "whole session" in the UI).
    let session_creds = env.json("/credentials").await;
    let session_snmp = items(&session_creds)
        .iter()
        .find(|c| c["protocol"] == "snmp")
        .unwrap();
    assert_eq!(snmp["seen_count"], session_snmp["seen_count"]);
    assert!(snmp["seen_count"].as_u64().unwrap() >= 3);
    let paths = env.json(&b("/credentials/paths")).await;
    let entries: u64 = paths["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["entries"].as_u64().unwrap())
        .sum();
    assert_eq!(entries, total(&creds));

    // Pictures: the image of the burst and the shared one, seen once in the range.
    let objects = env.json(&b("/objects")).await;
    assert_eq!(total(&objects), 2);
    let shared = items(&objects)
        .iter()
        .find(|o| o["uri"] == "/images/logo.png")
        .expect("shared image");
    assert_eq!(shared["occurrences"], 1);
    let session_shared = items(&env.json("/objects").await)
        .iter()
        .find(|o| o["uri"] == "/images/logo.png")
        .cloned()
        .unwrap();
    assert_eq!(session_shared["occurrences"], 3);
    let objects_stats = env.json(&b("/objects/stats")).await;
    assert_eq!(objects_stats["count"], 2);
    assert_eq!(objects_stats["occurrences"], 2);
    assert_eq!(module(&summary, "pictures"), (2, json!("range")));

    // Every module counts the range; the aggregated ones in /modules (P5.2b).
    for m in summary["modules"].as_array().unwrap() {
        let aggregated = ["connections", "hosts", "network", "openPorts", "servers"]
            .contains(&m["id"].as_str().unwrap());
        assert_eq!(
            m["scope"],
            if aggregated { "pending" } else { "range" },
            "{m}"
        );
    }
}

#[tokio::test]
async fn the_middle_burst_snapshot() {
    let env = Env::new();
    let b = |p: &str| env.burst(p, 1);
    let names: Vec<String> = items(&env.json(&b("/dns/messages")).await)
        .iter()
        .map(|m| m["qname"].as_str().unwrap().to_owned())
        .collect();
    let dns = env.json(&b("/dns/stats")).await;
    let http_stats = env.json(&b("/http/stats")).await;
    let tls_stats = env.json(&b("/tls/stats")).await;
    let smb = env.json(&b("/smb/stats")).await;
    let stats = env.json(&b("/credentials/stats")).await;
    let objects_stats = env.json(&b("/objects/stats")).await;
    insta::assert_json_snapshot!(
        "middle_burst",
        json!({
            "dns": names,
            "dns_stats": { "total": dns["total"], "errors": dns["errors"], "answered": dns["answered"] },
            "http_hosts": http_stats["hosts"],
            "tls_sni": tls_stats["sni"],
            "smb_os": smb["os"],
            "credential_protocols": stats["protocols"],
            "picture_types": objects_stats["types"],
        })
    );
}

#[tokio::test]
async fn summary_figures_follow_the_range() {
    let env = Env::new();
    let (first, last) = env.spread.bursts[1];
    let (from_us, to_us) = (first.div_euclid(1000), last.div_euclid(1000));
    let summary = env.json(&with_range("/summary", from_us, to_us)).await;
    let range = &summary["range"];
    assert_eq!(range["from_us"], from_us);
    assert_eq!(range["to_us"], to_us);
    assert_eq!(range["duration_us"], to_us - from_us);
    // Every connection of the burst plus the long one, active across the bursts.
    let flows = range["flow_count"].as_u64().unwrap();
    assert!(flows >= 2, "{range}");
    // Volumes: those of the chart over the same range (one-second buckets).
    let series = env
        .json(&with_range("/timeseries?points=2000", from_us, to_us))
        .await;
    let (bytes, packets) = series["series"]
        .as_array()
        .unwrap()
        .iter()
        .fold((0, 0), |(b, p), s| {
            (
                b + s["total_bytes"].as_u64().unwrap(),
                p + s["total_packets"].as_u64().unwrap(),
            )
        });
    assert_eq!(
        (
            range["bytes"].as_u64().unwrap(),
            range["packets"].as_u64().unwrap()
        ),
        (bytes, packets)
    );
    // Session figures unchanged.
    let plain = env.json("/summary").await;
    assert_eq!(summary["packets"], plain["packets"]);
    assert!(plain["range"].is_null());
    assert!(
        plain["modules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["scope"].is_null())
    );

    // Between two bursts, only the long connection is active.
    let gap_from = (last + 60_000_000_000).div_euclid(1000);
    let gap = env
        .json(&with_range("/summary", gap_from, gap_from + 60_000_000))
        .await;
    assert_eq!(gap["range"]["flow_count"], 1, "{gap}");
    assert_eq!(module(&gap, "dns").0, 0);
}

#[tokio::test]
async fn bounds_are_inclusive_to_the_microsecond() {
    let env = Env::new();
    let messages = env.json(&env.burst("/dns/messages", 1)).await;
    let ts = items(&messages)[0]["ts_us"].as_i64().unwrap();
    let count = |from: i64, to: i64| {
        let path = with_range("/dns/messages", from, to);
        let env = &env;
        async move { total(&env.json(&path).await) }
    };
    assert_eq!(count(ts, ts).await, 1);
    assert_eq!(count(ts - 5, ts - 1).await, 0);
    assert_eq!(count(ts + 1, ts + 5).await, 0);
    assert_eq!(count(ts - 1, ts).await, 1);
}

#[tokio::test]
async fn pages_under_a_range_have_no_gap_nor_duplicate() {
    let env = Env::new();
    for route in [
        "/dns/messages",
        "/dns/pairs",
        "/http/transactions?sort=size&order=desc",
        "/tls/sessions",
        "/credentials",
    ] {
        // Two bursts of three: several rows of every list.
        let full = env.json(&env.bursts(route, 0, 1)).await;
        let mut seen = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut path = env.bursts(route, 0, 1);
            path.push_str("&limit=1");
            if let Some(c) = &cursor {
                path.push_str("&cursor=");
                path.push_str(c);
            }
            let page = env.json(&path).await;
            seen.extend(items(&page).iter().map(|i| i["id"].clone()));
            match page["next_cursor"].as_str() {
                Some(c) => cursor = Some(c.to_owned()),
                None => break,
            }
        }
        let expected: Vec<Value> = items(&full).iter().map(|i| i["id"].clone()).collect();
        assert_eq!(seen, expected, "{route}");
        assert!(seen.len() >= 2, "{route}");
        assert_eq!(total(&full), seen.len() as u64, "{route}");
    }
}

/// One burst of forty is under a twentieth of every table: the aggregates read the time index
/// (narrow plan, `range::PointSql`); the answers are those of the wide plan.
#[tokio::test]
async fn a_narrow_range_reads_the_time_index_with_the_same_answers() {
    let env = Env::many();
    let b = |p: &str| env.burst(p, 20);
    let dns = env.json(&b("/dns/stats")).await;
    assert_eq!(
        (dns["total"].as_u64(), dns["errors"].as_u64()),
        (Some(3), Some(1))
    );
    assert_eq!(dns["protocols"][0]["count"], 3);
    let pairs = env.json(&b("/dns/pairs")).await;
    assert_eq!(total(&pairs), 2);
    let http = env.json(&b("/http/stats")).await;
    assert_eq!(http["transactions"], 2);
    assert_eq!(http["hosts"][0]["count"], 2);
    let by_size = env
        .json(&b("/http/transactions?sort=size&order=desc"))
        .await;
    assert_eq!(total(&by_size), 2);
    let sizes: Vec<u64> = items(&by_size)
        .iter()
        .map(|t| t["response_size"].as_u64().unwrap_or(0))
        .collect();
    assert!(sizes.windows(2).all(|w| w[0] >= w[1]), "{sizes:?}");
    let tls = env.json(&b("/tls/stats")).await;
    assert_eq!(
        (tls["sessions"].as_u64(), tls["certificates"].as_u64()),
        (Some(1), Some(1))
    );
    let certs = env.json(&b("/tls/certificates")).await;
    assert_eq!(total(&certs), 1);
    assert_eq!(items(&certs)[0]["sessions"], 1);
    // A single record: the first DNS message of the burst, alone in its microsecond.
    let first = env.json(&b("/dns/messages")).await;
    let ts = items(&first)[0]["ts_us"].as_i64().unwrap();
    let one = env.json(&with_range("/dns/stats", ts, ts)).await;
    assert_eq!(one["total"], 1);
    let tx = env.json(&b("/http/transactions")).await;
    let tts = items(&tx)[0]["ts_us"].as_i64().unwrap();
    assert_eq!(
        env.json(&with_range("/http/stats", tts, tts)).await["transactions"],
        1
    );
    let session = env.json(&b("/tls/sessions")).await;
    let sts = items(&session)[0]["ts_us"].as_i64().unwrap();
    assert_eq!(
        env.json(&with_range("/tls/stats", sts, sts)).await["sessions"],
        1
    );
    assert_eq!(
        total(&env.json(&with_range("/tls/certificates", sts, sts)).await),
        1
    );
    assert_eq!(
        total(
            &env.json(&with_range(
                "/http/transactions?sort=size&order=desc",
                tts,
                tts
            ))
            .await
        ),
        1
    );
}
