use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::ethernet::ethernet_showcase;
use netsift_fixtures::{Encoding, Scenario, encode};
use netsift_store::Catalog;
use serde_json::Value;
use tower::ServiceExt;

use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "ethernet-token";
/// First frame of the capture: 1 s after the epoch, then 0.5 ms per frame.
const START_US: i64 = 1_000_000;
/// Frames of one showcase round.
const ROUND: u64 = 14;

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
            geoip_fallback_path: None,
        };
        let (app, _) = build(config, IngestOptions::default());
        Self {
            _tmp: tmp,
            data,
            captures,
            app,
        }
    }

    /// Two showcase rounds, one minute apart, imported with two shards.
    fn import(&self) -> String {
        let mut sc = Scenario::starting_at(START_US * 1000);
        ethernet_showcase(&mut sc);
        sc.advance(60_000_000_000);
        ethernet_showcase(&mut sc);
        let path = self.captures.join("ethernet.pcap");
        std::fs::write(&path, encode(sc.packets(), &Encoding::pcap()).unwrap()).unwrap();
        let options = IngestOptions {
            name: Some("ethernet".to_owned()),
            shards: Some(2),
            ..IngestOptions::default()
        };
        let catalog = Catalog::open(&self.data).unwrap();
        ingest(&catalog, &path, &options, &CancelToken::new(), &mut |_| {})
            .unwrap()
            .session
            .to_string()
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

    async fn ok(&self, uri: &str) -> Value {
        let (status, json) = self.get(uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {json}");
        json
    }

    /// Every item of a paginated list, page by page (`limit` per page).
    async fn all(&self, uri: &str, limit: u32) -> Vec<Value> {
        let sep = if uri.contains('?') { '&' } else { '?' };
        let mut items = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page_uri = match &cursor {
                Some(c) => format!("{uri}{sep}limit={limit}&cursor={c}"),
                None => format!("{uri}{sep}limit={limit}"),
            };
            let json = self.ok(&page_uri).await;
            items.extend(json["items"].as_array().unwrap().iter().cloned());
            match json["next_cursor"].as_str() {
                Some(c) => cursor = Some(c.to_owned()),
                None => break,
            }
        }
        items
    }
}

fn macs_of(items: &[Value]) -> Vec<&str> {
    items
        .iter()
        .map(|i| i["address"]["mac"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn stats_snapshot() {
    let env = Env::new();
    let id = env.import();
    let json = env
        .ok(&format!("/api/v1/sessions/{id}/ethernet/stats"))
        .await;
    assert_eq!(json["frames"], 2 * ROUND);
    insta::assert_json_snapshot!(json);
}

#[tokio::test]
async fn addresses_with_vendor_class_and_counters() {
    let env = Env::new();
    let id = env.import();
    let base = format!("/api/v1/sessions/{id}/ethernet/macs");
    let items = env.all(&base, 4).await;
    assert_eq!(items.len(), 14);
    let page = env.ok(&format!("{base}?limit=4")).await;
    assert_eq!(page["total_estimate"], 14);

    let find = |mac: &str| items.iter().find(|i| i["address"]["mac"] == mac).unwrap();
    let vbox = find("08:00:27:09:d9:cb");
    assert_eq!(vbox["address"]["vendor"], "PCS Systemtechnik GmbH");
    assert_eq!(vbox["address"]["kind"], "unicast");
    assert_eq!(vbox["address"]["local"], false);
    assert_eq!(vbox["registry"], "ma-l");
    assert_eq!(vbox["frames_sent"], 6);
    assert_eq!(find("1c:87:74:01:02:03")["registry"], "ma-m");
    assert_eq!(find("70:b3:d5:00:1a:bc")["registry"], "ma-s");
    assert_eq!(
        find("1c:87:74:01:02:03")["vlans"],
        serde_json::json!(["100.20"])
    );
    let qemu = find("52:55:0a:00:02:01");
    assert_eq!(qemu["address"]["local"], true);
    assert_eq!(qemu["address"]["vendor"], Value::Null);
    let bcast = find("ff:ff:ff:ff:ff:ff");
    assert_eq!(bcast["address"]["kind"], "broadcast");
    let v6 = find("33:33:00:00:00:01");
    assert_eq!(v6["address"]["kind"], "multicast");
    assert_eq!(v6["address"]["group"], "ipv6_multicast");
    assert_eq!(
        find("01:00:5e:00:00:fb")["address"]["group"],
        "ipv4_multicast"
    );
    assert_eq!(
        find("01:80:c2:00:00:00")["address"]["group"],
        "ieee8021_reserved"
    );

    // Default order: frames, descending; keyset pages give the same rows as one page.
    let one = env.ok(&format!("{base}?limit=100")).await;
    assert_eq!(macs_of(one["items"].as_array().unwrap()), macs_of(&items));
    let by_mac = env.all(&format!("{base}?sort=mac"), 3).await;
    let mut sorted = macs_of(&items);
    sorted.sort_unstable();
    assert_eq!(macs_of(&by_mac), sorted);
}

#[tokio::test]
async fn address_filters() {
    let env = Env::new();
    let id = env.import();
    let base = format!("/api/v1/sessions/{id}/ethernet/macs");
    let count = |items: Vec<Value>| items.len();
    assert_eq!(count(env.all(&format!("{base}?q=08-00-27"), 10).await), 2);
    assert_eq!(count(env.all(&format!("{base}?q=raspberry"), 10).await), 1);
    // 9 unicast addresses, 2 of them locally administered; 5 group addresses.
    assert_eq!(
        count(env.all(&format!("{base}?class=unicast"), 10).await),
        9
    );
    assert_eq!(
        macs_of(&env.all(&format!("{base}?class=local&sort=mac"), 10).await),
        vec!["52:55:0a:00:02:01", "da:a1:19:3c:4e:7f"]
    );
    assert_eq!(count(env.all(&format!("{base}?class=group"), 10).await), 5);
    assert_eq!(
        count(
            env.all(&format!("{base}?vendor=PCS%20Systemtechnik%20GmbH"), 10)
                .await
        ),
        2
    );
    assert_eq!(
        count(env.all(&format!("{base}?vendor=~local"), 10).await),
        2
    );
    assert_eq!(
        count(env.all(&format!("{base}?vendor=~unknown"), 10).await),
        0
    );
    assert_eq!(count(env.all(&format!("{base}?vlan=10"), 10).await), 4);
    assert_eq!(count(env.all(&format!("{base}?vlan=100.20"), 10).await), 2);
    // Stored without leading zeros: the filter is normalized the same way.
    assert_eq!(
        count(env.all(&format!("{base}?vlan=0100.020"), 10).await),
        2
    );
    for bad in [
        "sort=size",
        "class=device",
        "vlan=4096",
        "vlan=1.2.3.4.5",
        "vlan=x",
        "vlan=%2B7",
        "vlan=1..2",
    ] {
        let (status, _) = env.get(&format!("{base}?{bad}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[tokio::test]
async fn pairs_with_filters_and_pages() {
    let env = Env::new();
    let id = env.import();
    let base = format!("/api/v1/sessions/{id}/ethernet/pairs");
    let items = env.all(&base, 5).await;
    assert_eq!(items.len(), 14);
    let p = items
        .iter()
        .find(|p| p["src"]["mac"] == "00:00:0c:9f:f0:01" && p["dst"]["mac"] == "01:80:c2:00:00:00")
        .unwrap();
    assert_eq!(p["frames"], 2);
    assert_eq!(p["src"]["vendor"], "Cisco Systems, Inc");
    assert_eq!(p["dst"]["group"], "ieee8021_reserved");
    assert_eq!(
        p["ethertypes"],
        serde_json::json!([{ "value": 0x42, "kind": "llc", "code": "0x42", "name": "Spanning tree" }])
    );
    let lldp = items
        .iter()
        .find(|p| p["dst"]["mac"] == "01:80:c2:00:00:0e")
        .unwrap();
    assert_eq!(lldp["ethertypes"][0]["code"], "0x88cc");
    assert_eq!(lldp["ethertypes"][0]["name"], "LLDP");

    let n = |items: Vec<Value>| items.len();
    assert_eq!(
        n(env.all(&format!("{base}?mac=08:00:27:09:d9:cb"), 10).await),
        4
    );
    assert_eq!(n(env.all(&format!("{base}?q=philips"), 10).await), 2);
    assert_eq!(n(env.all(&format!("{base}?vlan=10"), 10).await), 4);
    assert_eq!(n(env.all(&format!("{base}?ethertype=0x86dd"), 10).await), 1);
    assert_eq!(n(env.all(&format!("{base}?ethertype=66"), 10).await), 1);
    assert_eq!(n(env.all(&format!("{base}?sort=first_seen"), 3).await), 14);
    for bad in ["sort=mac", "ethertype=0x10000", "ethertype=ip"] {
        let (status, _) = env.get(&format!("{base}?{bad}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[tokio::test]
async fn time_range_keeps_overlapping_rows() {
    let env = Env::new();
    let id = env.import();
    let api = format!("/api/v1/sessions/{id}/ethernet");
    // The second round only (from 30 s on): addresses of both rounds span both, so all stay,
    // with their session counters; a range before the capture is empty.
    let second = format!(
        "from_us={}&to_us={}",
        START_US + 30_000_000,
        START_US + 120_000_000
    );
    let macs = env.all(&format!("{api}/macs?{second}"), 50).await;
    assert_eq!(macs.len(), 14);
    let vbox = macs
        .iter()
        .find(|m| m["address"]["mac"] == "08:00:27:09:d9:cb")
        .unwrap();
    assert_eq!(vbox["frames_sent"], 6);
    // The first 0.4 ms: only the spanning tree frame of the switch (its rows start there).
    let early = format!("from_us={START_US}&to_us={}", START_US + 400);
    let macs = env.all(&format!("{api}/macs?{early}&sort=mac"), 50).await;
    assert_eq!(
        macs_of(&macs),
        vec!["00:00:0c:9f:f0:01", "01:80:c2:00:00:00"]
    );
    let pairs = env.all(&format!("{api}/pairs?{early}"), 50).await;
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0]["frames"], 2, "session counters");
    let stats = env.ok(&format!("{api}/stats?{early}")).await;
    assert_eq!(stats["mac_count"], 2);
    assert_eq!(stats["pair_count"], 1);
    assert_eq!(stats["ethertypes"].as_array().unwrap().len(), 1);
    assert_eq!(stats["vlan_count"], 0);

    let before = "from_us=0&to_us=10";
    assert_eq!(env.all(&format!("{api}/macs?{before}"), 50).await.len(), 0);
    assert_eq!(env.all(&format!("{api}/pairs?{before}"), 50).await.len(), 0);
    let empty = env.ok(&format!("{api}/stats?{before}")).await;
    assert_eq!(empty["mac_count"], 0);
    assert_eq!(empty["frames"], 0);
    assert_eq!(empty["vendors"], serde_json::json!([]));

    // Overview module card: addresses, over the range too.
    let summary = env.ok(&format!("/api/v1/sessions/{id}/summary")).await;
    let module = summary["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == "ethernet")
        .unwrap();
    assert_eq!(module["count"], 14);
    let summary = env
        .ok(&format!("/api/v1/sessions/{id}/summary?{before}"))
        .await;
    let module = summary["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == "ethernet")
        .unwrap();
    assert_eq!(
        (module["count"].as_u64(), module["scope"].as_str()),
        (Some(0), Some("range"))
    );
}

#[tokio::test]
async fn rejects_invalid_ranges() {
    let env = Env::new();
    let id = env.import();
    let (status, _) = env
        .get(&format!(
            "/api/v1/sessions/{id}/ethernet/stats?from_us=10&to_us=5"
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
