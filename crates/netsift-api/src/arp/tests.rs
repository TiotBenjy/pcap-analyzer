//! API tests of the ARP routes on a synthetic capture: three bursts ten minutes apart, the first
//! one being the ARP showcase (conflicts, unsolicited replies).

use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::arp::{arp_hosts, arp_showcase};
use netsift_fixtures::scenarios::hosts;
use netsift_fixtures::time::NS_PER_SEC;
use netsift_fixtures::{Encoding, Scenario, encode};
use netsift_store::Catalog;
use serde_json::Value;
use tower::ServiceExt;

use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "arp-token";

struct Env {
    _tmp: tempfile::TempDir,
    app: Router,
    id: String,
    /// First and last packet (the announcement) of the middle burst, microseconds.
    middle: (i64, i64),
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
            geoip_fallback_path: None,
        };
        let (app, _) = build(config, IngestOptions::default());

        let mut sc = Scenario::new();
        arp_showcase(&mut sc);
        // Middle burst: the file server resolves the router twice, the laptop announces itself.
        sc.advance(600 * NS_PER_SEC);
        let first = sc.now();
        sc.arp_exchange(hosts::file_server(), hosts::router());
        sc.arp_exchange(hosts::file_server(), hosts::router());
        let last = sc.now();
        assert_eq!(sc.arp_announce(arp_hosts::laptop()), sc.len() - 1);
        sc.advance(600 * NS_PER_SEC);
        sc.arp_exchange(hosts::workstation(), hosts::file_server());

        let path: PathBuf = captures.join("arp.pcap");
        std::fs::write(&path, encode(sc.packets(), &Encoding::pcap()).unwrap()).unwrap();
        let options = IngestOptions {
            name: Some("arp".to_owned()),
            ..IngestOptions::default()
        };
        let catalog = Catalog::open(&data).unwrap();
        let id = ingest(&catalog, &path, &options, &CancelToken::new(), &mut |_| {})
            .unwrap()
            .session
            .to_string();
        Self {
            _tmp: tmp,
            app,
            id,
            middle: (first / 1000, last / 1000),
        }
    }

    async fn get(&self, uri: &str) -> (StatusCode, Value) {
        let req = Request::get(format!("/api/v1/sessions/{}/{uri}", self.id))
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

    async fn ok(&self, uri: &str) -> Value {
        let (status, json) = self.get(uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {json}");
        json
    }

    fn middle_range(&self) -> String {
        format!("from_us={}&to_us={}", self.middle.0, self.middle.1)
    }
}

fn module(summary: &Value, id: &str) -> Value {
    summary["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == id)
        .cloned()
        .unwrap_or(Value::Null)
}

#[tokio::test]
async fn stats_count_every_type_and_the_conflicts() {
    let env = Env::new();
    let stats = env.ok("arp/stats").await;
    insta::assert_json_snapshot!("arp_stats", stats);
    // Showcase plus the two later bursts.
    assert_eq!(stats["messages"], 26);
    assert_eq!(stats["kinds"]["request"], 9);
    assert_eq!(stats["kinds"]["probe"], 1);
    assert_eq!(stats["kinds"]["gratuitous"], 2);
    assert_eq!(stats["unsolicited"], 6);
    assert_eq!(stats["conflicts"], 2);
    let summary = env.ok("summary").await;
    assert_eq!(module(&summary, "arp")["count"], stats["messages"]);
    let all = env.ok("arp/messages?limit=1").await;
    assert_eq!(all["total_estimate"], stats["messages"]);
}

#[tokio::test]
async fn conflicts_name_the_intruder_and_their_signs() {
    let env = Env::new();
    let json = env.ok("arp/conflicts").await;
    assert_eq!(json["total"], 2);
    let items = json["items"].as_array().unwrap();
    let router = items
        .iter()
        .find(|c| c["ip"]["ip"] == "192.168.1.1")
        .unwrap();
    assert_eq!(router["mac_count"], 2);
    let macs: Vec<&str> = router["macs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["mac"].as_str().unwrap())
        .collect();
    assert_eq!(macs, vec!["02:00:5e:10:00:01", "02:00:5e:10:00:66"]);
    assert_eq!(router["macs"][1]["unsolicited"], 3);
    // The intruder MAC also claims its own address and the workstation's.
    assert_eq!(router["macs"][1]["other_ips"], 2);
    assert_eq!(
        router["signs"],
        serde_json::json!(["simultaneous", "unsolicited", "multiple_ips"])
    );
}

#[tokio::test]
async fn message_filters() {
    let env = Env::new();
    let count = |json: &Value| json["total_estimate"].as_u64().unwrap();
    let probes = env.ok("arp/messages?kind=probe").await;
    assert_eq!(count(&probes), 1);
    assert_eq!(probes["items"][0]["sender"]["ip"], "0.0.0.0");
    let both = env.ok("arp/messages?kind=probe,gratuitous").await;
    assert_eq!(count(&both), 3);
    let unsolicited = env.ok("arp/messages?unsolicited=true").await;
    assert_eq!(count(&unsolicited), 6);
    assert!(
        unsolicited["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["sender_mac"] == "02:00:5e:10:00:66" && m["kind"] == "reply")
    );
    // MAC filter: any case and separator.
    let by_mac = env.ok("arp/messages?mac=02-00-5E-10-00-66").await;
    // Its own request and the six spoofed replies.
    assert_eq!(count(&by_mac), 7);
    let by_ip = env.ok("arp/messages?ip=192.168.1.30").await;
    // Probe (target), two announcements (sender and target).
    assert_eq!(count(&by_ip), 3);
    for bad in ["kind=bogus", "ip=nope", "mac=02:00", "unsolicited=maybe"] {
        let (status, json) = env.get(&format!("arp/messages?{bad}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {json}");
    }
}

#[tokio::test]
async fn binding_filters() {
    let env = Env::new();
    let all = env.ok("arp/bindings").await;
    let items = all["items"].as_array().unwrap();
    assert_eq!(all["total_estimate"], items.len());
    assert_eq!(items[0]["ip"]["ip"], "192.168.1.10");
    let conflicts = env.ok("arp/bindings?conflicts=true").await;
    let rows = conflicts["items"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    assert!(rows.iter().all(|b| b["conflict"] == true));
    let search = env.ok("arp/bindings?q=10:00:66").await;
    assert_eq!(search["total_estimate"], 3);
    let (status, _) = env.get(&format!("arp/bindings?q={}", "a".repeat(65))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_middle_burst_only_under_its_range() {
    let env = Env::new();
    let range = env.middle_range();
    let stats = env.ok(&format!("arp/stats?{range}")).await;
    // Two exchanges and the announcement.
    assert_eq!(stats["messages"], 5);
    assert_eq!(stats["kinds"]["request"], 2);
    assert_eq!(stats["kinds"]["reply"], 2);
    assert_eq!(stats["kinds"]["gratuitous"], 1);
    assert_eq!(stats["first_ts_us"], env.middle.0);
    assert_eq!(stats["last_ts_us"], env.middle.1);
    // The conflicts of the showcase are over.
    assert_eq!(stats["conflicts"], 0);
    let senders: Vec<&str> = stats["top_senders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["ip"]["ip"].as_str().unwrap())
        .collect();
    assert_eq!(senders, vec!["192.168.1.1", "192.168.1.20", "192.168.1.30"]);
    let messages = env.ok(&format!("arp/messages?{range}")).await;
    assert_eq!(messages["total_estimate"], 5);
    let summary = env.ok(&format!("summary?{range}")).await;
    assert_eq!(module(&summary, "arp")["count"], 5);
    assert_eq!(module(&summary, "arp")["scope"], "range");
    // Folded bindings active in the range, with their session counters.
    let bindings = env.ok(&format!("arp/bindings?{range}")).await;
    let ips: Vec<&str> = bindings["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["ip"]["ip"].as_str().unwrap())
        .collect();
    assert!(ips.contains(&"192.168.1.20"));
    assert!(
        ips.contains(&"192.168.1.10"),
        "the workstation spans the range"
    );
    assert!(!ips.contains(&"192.168.1.66"));
    let conflicts = env.ok(&format!("arp/conflicts?{range}")).await;
    assert_eq!(conflicts["total"], 0);

    // Bounds are inclusive at the microsecond.
    let (from, to) = env.middle;
    let before_last = env
        .ok(&format!("arp/stats?from_us={from}&to_us={}", to - 1))
        .await;
    assert_eq!(before_last["messages"], 4);
    assert_eq!(before_last["kinds"]["gratuitous"], 0);
    let after_first = env
        .ok(&format!("arp/stats?from_us={}&to_us={to}", from + 1))
        .await;
    assert_eq!(after_first["messages"], 4);
    assert_eq!(after_first["kinds"]["request"], 1);

    // Disjoint range: empty, never an error.
    let empty = env.ok("arp/stats?from_us=0&to_us=1").await;
    assert_eq!(empty["messages"], 0);
    assert_eq!(empty["first_ts_us"], Value::Null);
}

#[tokio::test]
async fn pages_follow_without_duplicate_or_gap() {
    let env = Env::new();
    for (route, extra) in [("arp/messages", ""), ("arp/bindings", "")] {
        let first = env.ok(&format!("{route}?limit=1000{extra}")).await;
        let expected: Vec<Value> = first["items"].as_array().unwrap().clone();
        let mut seen = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let uri = match &cursor {
                None => format!("{route}?limit=3{extra}"),
                Some(c) => format!("{route}?limit=3&cursor={c}{extra}"),
            };
            let page = env.ok(&uri).await;
            if cursor.is_some() {
                assert_eq!(page["total_estimate"], Value::Null);
            }
            seen.extend(page["items"].as_array().unwrap().iter().cloned());
            match page["next_cursor"].as_str() {
                Some(c) => cursor = Some(c.to_owned()),
                None => break,
            }
        }
        assert_eq!(seen, expected, "{route}");
    }
    // Under the middle range too.
    let range = env.middle_range();
    let mut ids = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let uri = match &cursor {
            None => format!("arp/messages?limit=3&{range}"),
            Some(c) => format!("arp/messages?limit=3&cursor={c}&{range}"),
        };
        let page = env.ok(&uri).await;
        ids.extend(
            page["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["id"].as_str().unwrap().to_owned()),
        );
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => break,
        }
    }
    assert_eq!(ids.len(), 5);
}
