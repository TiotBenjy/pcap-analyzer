//! SSDP routes on a synthetic capture of three bursts ten minutes apart: the showcase (every
//! message kind, four devices, IPv4 and IPv6, malformed datagrams), then two periodic rounds of
//! the gateway and the TV (`netsift_fixtures::ssdp`).

use std::collections::HashSet;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::ssdp::{self, ShowcaseCounts};
use netsift_fixtures::time::NS_PER_SEC;
use netsift_fixtures::{Encoding, Scenario, encode};
use netsift_store::Catalog;
use serde_json::Value;
use tower::ServiceExt;

use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "ssdp-token";
/// Gap between two bursts.
const BURST_GAP_NS: i64 = 600 * NS_PER_SEC;

struct Env {
    _tmp: tempfile::TempDir,
    app: Router,
    id: String,
    counts: ShowcaseCounts,
    /// `[first, last]` packet time of each burst, microseconds.
    bursts: Vec<(i64, i64)>,
}

impl Env {
    fn new() -> Self {
        let mut sc = Scenario::new();
        let mut bursts = Vec::new();
        let start = sc.now();
        let counts = ssdp::ssdp_showcase(&mut sc);
        bursts.push((start, last_ts(&sc)));
        for round in 0..2 {
            sc.advance(BURST_GAP_NS);
            let start = sc.now();
            // The first periodic round includes a search answered by both devices.
            ssdp::ssdp_round(&mut sc, round, 2);
            bursts.push((start, last_ts(&sc)));
        }
        let bursts = bursts
            .into_iter()
            .map(|(a, b)| (a / 1000, b / 1000))
            .collect();

        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        let captures = tmp.path().join("captures");
        std::fs::create_dir_all(&captures).unwrap();
        let path = captures.join("ssdp.pcap");
        std::fs::write(&path, encode(sc.packets(), &Encoding::pcap()).unwrap()).unwrap();
        let catalog = Catalog::open(&data).unwrap();
        let id = ingest(
            &catalog,
            &path,
            &IngestOptions::default(),
            &CancelToken::new(),
            &mut |_| {},
        )
        .unwrap()
        .session
        .to_string();
        let config = ApiConfig {
            token: TOKEN.to_owned(),
            data_dir: data,
            captures_roots: vec![captures],
            read_only: true,
            cors_origins: vec![HeaderValue::from_static("tauri://localhost")],
            allow_any_path: false,
            max_imports: DEFAULT_MAX_IMPORTS,
            geoip_fallback_path: None,
        };
        let (app, _) = build(config, IngestOptions::default());
        Self {
            _tmp: tmp,
            app,
            id,
            counts,
            bursts,
        }
    }

    async fn get(&self, rel: &str) -> (StatusCode, Value) {
        let uri = format!("/api/v1/sessions/{}{rel}", self.id);
        let req = Request::get(&uri)
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

    async fn ok(&self, rel: &str) -> Value {
        let (status, json) = self.get(rel).await;
        assert_eq!(status, StatusCode::OK, "{rel}: {json}");
        json
    }

    /// `from_us=..&to_us=..` of burst `i`.
    fn burst(&self, i: usize) -> String {
        let (a, b) = self.bursts[i];
        format!("from_us={a}&to_us={b}")
    }

    /// Every item of a list, following its cursors with `limit`.
    async fn all(&self, rel: &str, limit: u32) -> Vec<Value> {
        let sep = if rel.contains('?') { '&' } else { '?' };
        let mut items = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let c = cursor.map_or(String::new(), |c| format!("&cursor={c}"));
            let page = self.ok(&format!("{rel}{sep}limit={limit}{c}")).await;
            items.extend(page["items"].as_array().unwrap().iter().cloned());
            match page["next_cursor"].as_str() {
                Some(c) => cursor = Some(c.to_owned()),
                None => return items,
            }
        }
    }
}

fn last_ts(sc: &Scenario) -> i64 {
    sc.packets().last().unwrap().ts_ns
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

/// Messages of a periodic round: five targets each for the gateway and the TV, plus (with a
/// search) one search and two answers.
const ROUND_WITH_SEARCH: u64 = 13;
const ROUND_PLAIN: u64 = 10;

#[tokio::test]
async fn counters_agree_between_list_stats_and_module() {
    let env = Env::new();
    let n = env.counts;
    let total = n.total() as u64 + ROUND_WITH_SEARCH + ROUND_PLAIN;
    let stats = env.ok("/ssdp/stats").await;
    assert_eq!(stats["messages"], total);
    assert_eq!(stats["search"], n.search as u64 + 1);
    assert_eq!(stats["response"], n.response as u64 + 2);
    assert_eq!(stats["byebye"], n.byebye as u64);
    assert_eq!(stats["invalid"], n.invalid as u64);
    assert_eq!(
        stats["notify"],
        stats["alive"].as_u64().unwrap() + stats["byebye"].as_u64().unwrap()
    );
    // Gateway, TV, printer, NAS and the host of the oversized NOTIFY.
    assert_eq!(stats["devices"], 5);
    let messages = env.ok("/ssdp/messages?limit=1").await;
    assert_eq!(messages["total_estimate"], total);
    let summary = env.ok("/summary").await;
    assert_eq!(module(&summary, "ssdp")["count"], total);
    // The TV sends the most messages (it answers one more search).
    assert_eq!(stats["top_senders"][0]["address"]["ip"], "192.168.1.40");
    assert_eq!(stats["targets"][0]["name"], ssdp::ROOT_DEVICE);
}

#[tokio::test]
async fn devices_carry_their_targets_and_session_counters() {
    let env = Env::new();
    let page = env.ok("/ssdp/devices").await;
    assert_eq!(page["total_estimate"], 5);
    let items = page["items"].as_array().unwrap();
    let device = ssdp::gateway();
    // The TV answers one more search than the gateway: it comes first.
    assert_eq!(items[0]["uuid"], ssdp::tv().uuid);
    let gw = items.iter().find(|d| d["uuid"] == device.uuid).unwrap();
    assert_eq!(gw["uuid"], device.uuid);
    assert_eq!(gw["address"]["ip"], "192.168.1.1");
    assert_eq!(gw["device_type"], device.device_type);
    assert_eq!(gw["location"], device.location);
    assert_eq!(gw["server"], device.server);
    // 5 announcements per burst and one answer per search.
    assert_eq!(gw["message_count"], 5 * 3 + 2);
    assert_eq!(gw["response_count"], 2);
    let targets: Vec<&str> = gw["targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    assert_eq!(targets.len(), device.targets().len());
    let printer = items
        .iter()
        .find(|d| d["uuid"] == ssdp::printer().uuid)
        .unwrap();
    assert_eq!(printer["byebye_count"], 4);
    let nas = items
        .iter()
        .find(|d| d["uuid"] == ssdp::nas().uuid)
        .unwrap();
    assert_eq!(nas["address"]["ip"], "2001:db8:1::60");
    // Search in the device type.
    let found = env.ok("/ssdp/devices?q=mediaserver").await;
    assert_eq!(found["total_estimate"], 1);
}

#[tokio::test]
async fn message_filters_and_validation() {
    let env = Env::new();
    let count = |json: &Value| json["total_estimate"].as_u64().unwrap();
    let search = env.ok("/ssdp/messages?kind=search").await;
    assert_eq!(count(&search), env.counts.search as u64 + 1);
    assert!(
        search["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["kind"] == "search" && m["mx"] == 2)
    );
    let bye = env.ok("/ssdp/messages?kind=notify&nts=byebye").await;
    assert_eq!(count(&bye), env.counts.byebye as u64);
    let tv = ssdp::tv();
    let of_tv = env
        .ok(&format!(
            "/ssdp/messages?uuid={}&src=192.168.1.40",
            tv.uuid.to_uppercase()
        ))
        .await;
    assert_eq!(count(&of_tv), 5 * 3 + 2 + 1);
    let dial = env
        .ok("/ssdp/messages?target=urn:dial-multiscreen-org:service:dial:1")
        .await;
    assert_eq!(count(&dial), 3 + 2);
    let by_location = env.ok("/ssdp/messages?q=printer.xml").await;
    assert_eq!(count(&by_location), 4 + 1);
    let invalid = env.ok("/ssdp/messages?kind=invalid").await;
    let raw = invalid["items"][0]["raw"].as_str().unwrap();
    assert!(
        !raw.chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
    );
    // The oversized notification: raw text cut, flag set, server bounded.
    let big = env.ok("/ssdp/messages?q=0000dead").await;
    assert_eq!(big["items"][0]["raw_truncated"], true);
    assert_eq!(big["items"][0]["server"].as_str().unwrap().len(), 512);

    for bad in [
        "/ssdp/messages?kind=other",
        "/ssdp/messages?nts=dead",
        "/ssdp/messages?src=not-an-ip",
        "/ssdp/messages?cursor=zz",
        "/ssdp/devices?limit=x",
        "/ssdp/stats?from_us=10&to_us=1",
    ] {
        let (status, json) = env.get(bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {json}");
    }
    let long = "x".repeat(600);
    let (status, _) = env.get(&format!("/ssdp/messages?q={long}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn middle_burst_range() {
    let env = Env::new();
    let range = env.burst(1);
    let stats = env.ok(&format!("/ssdp/stats?{range}")).await;
    assert_eq!(stats["messages"], ROUND_WITH_SEARCH);
    assert_eq!(
        (stats["search"].as_u64(), stats["response"].as_u64()),
        (Some(1), Some(2))
    );
    // Devices overlapping the burst: the gateway and the TV (seen in every burst).
    assert_eq!(stats["devices"], 2);
    let messages = env.all(&format!("/ssdp/messages?{range}"), 4).await;
    assert_eq!(messages.len() as u64, ROUND_WITH_SEARCH);
    let (a, b) = env.bursts[1];
    assert!(messages.iter().all(|m| {
        let t = m["ts_us"].as_i64().unwrap();
        t >= a && t <= b
    }));
    let summary = env.ok(&format!("/summary?{range}")).await;
    let m = module(&summary, "ssdp");
    assert_eq!(m["count"], ROUND_WITH_SEARCH);
    assert_eq!(m["scope"], "range");
    let devices = env.ok(&format!("/ssdp/devices?{range}")).await;
    assert_eq!(devices["total_estimate"], 2);
    // Folded counters stay those of the session.
    assert_eq!(devices["items"][0]["message_count"], 5 * 3 + 2 + 1);

    insta::assert_json_snapshot!("middle_burst", (stats, devices));
}

#[tokio::test]
async fn range_bounds_and_whole_session() {
    let env = Env::new();
    // A range of one microsecond at the first message of the last burst.
    let t = env.bursts[2].0;
    let one = env
        .ok(&format!("/ssdp/messages?from_us={t}&to_us={t}"))
        .await;
    assert_eq!(one["total_estimate"], 1);
    let after = env
        .ok(&format!("/ssdp/messages?from_us={}&to_us={}", t + 1, t + 1))
        .await;
    assert_eq!(after["total_estimate"], 0);
    let before = env
        .ok(&format!("/ssdp/messages?from_us={}&to_us={}", t - 1, t - 1))
        .await;
    assert_eq!(before["total_estimate"], 0);
    // Disjoint range: empty, never an error.
    let empty = env.ok("/ssdp/stats?from_us=1&to_us=2").await;
    assert_eq!(
        (empty["messages"].as_u64(), empty["devices"].as_u64()),
        (Some(0), Some(0))
    );
    // A range covering the session answers exactly as without range.
    let whole = format!(
        "from_us={}&to_us={}",
        env.bursts[0].0 - 5,
        env.bursts[2].1 + 5
    );
    for rel in ["/ssdp/stats", "/ssdp/devices", "/ssdp/messages"] {
        let plain = env.ok(rel).await;
        let ranged = env.ok(&format!("{rel}?{whole}")).await;
        assert_eq!(plain, ranged, "{rel}");
    }
}

#[tokio::test]
async fn pages_have_no_duplicate_nor_gap() {
    let env = Env::new();
    let total = env.ok("/ssdp/stats").await["messages"].as_u64().unwrap();
    let messages = env.all("/ssdp/messages", 7).await;
    assert_eq!(messages.len() as u64, total);
    let ids: HashSet<i64> = messages.iter().map(|m| m["id"].as_i64().unwrap()).collect();
    assert_eq!(ids.len() as u64, total);
    let times: Vec<i64> = messages
        .iter()
        .map(|m| m["ts_us"].as_i64().unwrap())
        .collect();
    assert!(times.windows(2).all(|w| w[0] <= w[1]));
    let devices = env.all("/ssdp/devices", 1).await;
    assert_eq!(devices.len(), 5);
    let counts: Vec<u64> = devices
        .iter()
        .map(|d| d["message_count"].as_u64().unwrap())
        .collect();
    assert!(counts.windows(2).all(|w| w[0] >= w[1]));
    // Under a range too.
    let ranged = env
        .all(&format!("/ssdp/messages?kind=notify&{}", env.burst(2)), 3)
        .await;
    assert_eq!(ranged.len() as u64, ROUND_PLAIN);
}
