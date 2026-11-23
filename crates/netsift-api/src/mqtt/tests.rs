//! MQTT routes on a synthetic capture of three bursts ten minutes apart: the showcase (thirteen
//! connections: telemetry, 5.0 with aliases, an anonymous legacy client of a public broker, a
//! dashboard subscribed to `#`, rejected logins then an accepted one, a gateway on port 11883, a
//! connection picked up in the middle), then periodic rounds (`netsift_fixtures::mqtt`).

use std::collections::HashSet;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::mqtt::{self, SHOWCASE};
use netsift_fixtures::time::NS_PER_SEC;
use netsift_fixtures::{Encoding, Scenario, encode};
use netsift_store::Catalog;
use serde_json::Value;
use tower::ServiceExt;

use super::payload_text;
use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "mqtt-token";
/// Gap between two bursts.
const BURST_GAP_NS: i64 = 600 * NS_PER_SEC;
/// Connections of the capture: the showcase, then round 0 (sensor and PLC) and round 1 (sensor).
const TOTAL: u64 = SHOWCASE.connections + 3;

struct Env {
    tmp: tempfile::TempDir,
    app: Router,
    id: String,
    /// `[first, last]` packet time of each burst, microseconds.
    bursts: Vec<(i64, i64)>,
}

fn last_ts(sc: &Scenario) -> i64 {
    sc.packets().last().unwrap().ts_ns
}

impl Env {
    fn new() -> Self {
        let mut sc = Scenario::new();
        let mut bursts = Vec::new();
        let start = sc.now();
        mqtt::mqtt_showcase(&mut sc);
        bursts.push((start, last_ts(&sc)));
        for round in 0..2 {
            sc.advance(BURST_GAP_NS);
            let start = sc.now();
            mqtt::mqtt_round(&mut sc, round);
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
        let path = captures.join("mqtt.pcap");
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
            tmp,
            app,
            id,
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

    fn burst(&self, i: usize) -> String {
        let (a, b) = self.bursts[i];
        format!("from_us={a}&to_us={b}")
    }

    fn whole(&self) -> String {
        format!(
            "from_us={}&to_us={}",
            self.bursts[0].0 - 5,
            self.bursts[2].1 + 5
        )
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

fn module(summary: &Value, id: &str) -> Value {
    summary["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == id)
        .cloned()
        .unwrap_or(Value::Null)
}

fn total(json: &Value) -> u64 {
    json["total_estimate"].as_u64().unwrap()
}

#[tokio::test]
async fn counters_agree_between_list_stats_and_module() {
    let env = Env::new();
    let stats = env.ok("/mqtt/stats").await;
    assert_eq!(stats["connections"], TOTAL);
    assert_eq!(stats["accepted"], SHOWCASE.accepted + 3);
    assert_eq!(stats["rejected"], SHOWCASE.rejected);
    assert_eq!(stats["no_answer"], SHOWCASE.no_answer);
    assert_eq!(stats["brokers"], SHOWCASE.brokers);
    assert_eq!(stats["public_brokers"], 1);
    assert_eq!(total(&env.ok("/mqtt/connections?limit=1").await), TOTAL);
    let summary = env.ok("/summary").await;
    assert_eq!(module(&summary, "mqtt")["count"], TOTAL);
    let signals: Vec<&str> = stats["signals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        signals,
        vec![
            "anonymous",
            "public-broker",
            "exposed-broker",
            "wildcard",
            "auth-failures",
            "cleartext-credentials"
        ]
    );
    // MQTT logins reach the Credentials view.
    let creds = env.ok("/credentials?protocol=mqtt&limit=1").await;
    assert_eq!(total(&creds), SHOWCASE.credentials);
    // The signal filter of the list agrees with the counts of the statistics.
    for s in stats["signals"].as_array().unwrap() {
        let kind = s["kind"].as_str().unwrap();
        let list = env.ok(&format!("/mqtt/connections?signal={kind}")).await;
        assert_eq!(total(&list), s["connections"].as_u64().unwrap(), "{kind}");
    }
}

#[tokio::test]
async fn lists_never_carry_a_password() {
    let env = Env::new();
    for rel in [
        "/mqtt/connections?limit=100",
        "/mqtt/clients",
        "/mqtt/brokers",
        "/mqtt/messages?limit=200",
        "/mqtt/signals",
        "/mqtt/stats",
    ] {
        let (_, raw) = env.get(rel).await;
        let text = raw.to_string();
        assert!(!text.contains("-fixture"), "{rel}: {text}");
        assert!(!text.contains("\"password\":"), "{rel}");
    }
}

#[tokio::test]
async fn detail_carries_the_password_and_the_transcript() {
    let env = Env::new();
    let first = env.ok("/mqtt/connections?limit=1").await["items"][0].clone();
    assert_eq!(first["client_id"], "sensor-01");
    assert_eq!(first["version"], "3.1.1");
    assert_eq!(
        first["signals"],
        serde_json::json!(["cleartext-credentials"])
    );
    let flow = first["flow_id"].as_i64().unwrap();
    let detail = env.ok(&format!("/mqtt/connections/{flow}")).await;
    assert_eq!(detail["connection"], first);
    assert_eq!(detail["password"], "sensor-fixture");
    // The DTO never prints the password.
    let catalog = Catalog::open(env.tmp.path().join("data")).unwrap();
    let session = catalog
        .open_session(&env.id.parse().unwrap(), netsift_store::OpenMode::ReadOnly)
        .unwrap();
    let stored = netsift_store::mqtt::connection_detail(session.conn(), flow)
        .unwrap()
        .unwrap();
    let typed = super::detail_info(stored);
    assert_eq!(typed.password.as_deref(), Some("sensor-fixture"));
    assert!(!format!("{typed:?}").contains("sensor-fixture"));
    assert_eq!(detail["will"]["topic"], "plant/line1/sensor-01/status");
    assert_eq!(detail["will"]["payload"]["text"], "offline");
    assert_eq!(detail["subscriptions"][0]["granted"], 1);
    let packets = env.ok(&format!("/mqtt/connections/{flow}/packets")).await;
    assert_eq!(total(&packets), 9);
    let types: Vec<&str> = packets["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["type"].as_str().unwrap())
        .collect();
    assert_eq!(
        types,
        vec![
            "CONNECT",
            "CONNACK",
            "SUBSCRIBE",
            "PUBLISH",
            "PUBLISH",
            "PUBLISH",
            "PUBLISH",
            "PUBLISH",
            "DISCONNECT"
        ]
    );
    let only = env
        .ok(&format!("/mqtt/connections/{flow}/packets?type=PUBLISH"))
        .await;
    assert_eq!(total(&only), 5);
    // Row ids follow the arrival order of the shards: left out.
    let mut items = packets["items"].clone();
    for item in items.as_array_mut().unwrap() {
        item.as_object_mut().unwrap().remove("id");
    }
    insta::assert_json_snapshot!("sensor_transcript", items);
    for missing in ["/mqtt/connections/999999", "/mqtt/connections/abc"] {
        let (status, _) = env.get(missing).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{missing}");
    }
}

#[tokio::test]
async fn clients_brokers_topics_and_messages() {
    let env = Env::new();
    let clients = env.all("/mqtt/clients", 2).await;
    let keys: HashSet<&str> = clients.iter().map(|c| c["key"].as_str().unwrap()).collect();
    assert!(keys.contains("id:sensor-01"));
    assert!(keys.contains("id:probe"));
    // The PLC of the showcase has an empty identifier: grouped by address.
    assert!(keys.contains("ip:192.168.1.61"), "{keys:?}");
    assert_eq!(keys.len() as u64, total(&env.ok("/mqtt/clients").await));
    let probe = clients.iter().find(|c| c["key"] == "id:probe").unwrap();
    assert_eq!(
        (probe["connections"].as_u64(), probe["rejected"].as_u64()),
        (Some(7), Some(6))
    );
    let filtered = env.ok("/mqtt/connections?client=id:probe").await;
    assert_eq!(total(&filtered), 7);
    let flow = filtered["items"][0]["flow_id"].as_i64().unwrap();
    let one = env.ok(&format!("/mqtt/connections?flow={flow}")).await;
    assert_eq!(total(&one), 1);

    let brokers = env.all("/mqtt/brokers", 1).await;
    assert_eq!(brokers.len() as u64, SHOWCASE.brokers);
    let lan = &brokers[0];
    assert_eq!(lan["broker"]["ip"], "192.168.1.40");
    assert_eq!(lan["exposed"], true);
    assert_eq!(lan["software"], "mosquitto version 2.0.18");
    let cloud = brokers
        .iter()
        .find(|b| b["broker"]["ip"] == "82.165.30.12")
        .unwrap();
    assert_eq!(cloud["public"], true);
    let by_broker = env
        .ok("/mqtt/connections?broker=192.168.1.40&broker_port=11883")
        .await;
    assert_eq!(total(&by_broker), 1);

    let root = env.ok("/mqtt/topics").await;
    let names: Vec<&str> = root["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["$SYS", "firmware", "plant", "telemetry"]);
    let plant = env.ok("/mqtt/topics?parent=plant").await;
    let lines: Vec<&str> = plant["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["name"].as_str().unwrap())
        .collect();
    assert_eq!(lines, vec!["line1", "line2", "line3"]);
    let node = env.ok("/mqtt/topics/node?path=plant/line2/pressure").await;
    assert!(node["node"]["is_topic"].as_bool().unwrap());
    assert_eq!(node["publishers"][0]["client_id"], "");
    // The dashboard's `#` covers it.
    assert!(
        node["subscribers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["filter"] == "#")
    );
    let search = env.ok("/mqtt/topics?q=PRESS").await;
    assert_eq!(search["items"][0]["path"], "plant/line2/pressure");
    let (status, _) = env.get("/mqtt/topics/node?path=no/such").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let note = env.ok("/mqtt/messages?topic=plant/line1/note").await;
    let payload = &note["items"][0]["payload"];
    // Markup stays text; the bidirectional override is escaped.
    assert_eq!(
        payload["text"],
        "<script>alert(1)</script> \\u{202e}txt.exe"
    );
    let raw = env.ok("/mqtt/messages?topic=telemetry/legacy-gw/raw").await;
    assert_eq!(raw["items"][0]["payload"]["text"], Value::Null);
    assert_eq!(raw["items"][0]["payload"]["excerpt_len"], 64);
    let big = env.ok("/mqtt/messages?prefix=firmware").await;
    assert_eq!(total(&big), 3);
    let image = &big["items"][0]["payload"];
    assert_eq!(
        (image["len"].as_u64(), image["truncated"].as_bool()),
        (Some(1_048_576), Some(true))
    );
    let delivered = env.ok("/mqtt/messages?dir=broker").await;
    assert!(total(&delivered) >= 6);
}

#[tokio::test]
async fn filters_validation() {
    let env = Env::new();
    assert_eq!(total(&env.ok("/mqtt/connections?login=rejected").await), 6);
    assert_eq!(total(&env.ok("/mqtt/connections?login=none").await), 1);
    assert_eq!(total(&env.ok("/mqtt/connections?version=3.1").await), 1);
    assert_eq!(total(&env.ok("/mqtt/connections?version=unknown").await), 0);
    assert_eq!(total(&env.ok("/mqtt/connections?auth=username").await), 1);
    assert_eq!(total(&env.ok("/mqtt/connections?q=legacy").await), 1);
    for bad in [
        "/mqtt/connections?login=maybe",
        "/mqtt/connections?version=4",
        "/mqtt/connections?signal=loud",
        "/mqtt/connections?transport=udp",
        "/mqtt/connections?broker=192.168.1.40",
        "/mqtt/connections?client=dev",
        "/mqtt/connections?cursor=zz",
        "/mqtt/messages?qos=3",
        "/mqtt/messages?dir=up",
        "/mqtt/connections/1/packets?type=HELLO",
        "/mqtt/topics/node",
        "/mqtt/stats?from_us=10&to_us=1",
    ] {
        let (status, json) = env.get(bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {json}");
    }
}

#[tokio::test]
async fn ranges_overlap_points_and_whole_session() {
    let env = Env::new();
    let range = env.burst(1);
    let stats = env.ok(&format!("/mqtt/stats?{range}")).await;
    assert_eq!(stats["connections"], 2);
    let summary = env.ok(&format!("/summary?{range}")).await;
    let m = module(&summary, "mqtt");
    assert_eq!(
        (m["count"].as_u64(), m["scope"].as_str()),
        (Some(2), Some("range"))
    );
    let messages = env.ok(&format!("/mqtt/messages?{range}")).await;
    assert_eq!(total(&messages), 4);
    let topics = env.ok(&format!("/mqtt/topics?parent=plant&{range}")).await;
    let names: Vec<&str> = topics["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["line1", "line2"]);
    let empty = env.ok("/mqtt/stats?from_us=1&to_us=2").await;
    assert_eq!(empty["connections"], 0);
    let whole = env.whole();
    for rel in [
        "/mqtt/stats",
        "/mqtt/connections",
        "/mqtt/clients",
        "/mqtt/brokers",
        "/mqtt/topics",
        "/mqtt/messages",
        "/mqtt/signals",
    ] {
        let plain = env.ok(rel).await;
        let ranged = env.ok(&format!("{rel}?{whole}")).await;
        assert_eq!(plain, ranged, "{rel}");
    }
}

#[tokio::test]
async fn pages_have_no_duplicate_nor_gap() {
    let env = Env::new();
    let all = env.all("/mqtt/connections", 4).await;
    assert_eq!(all.len() as u64, TOTAL);
    let ids: HashSet<i64> = all.iter().map(|c| c["flow_id"].as_i64().unwrap()).collect();
    assert_eq!(ids.len() as u64, TOTAL);
    let messages = env.all("/mqtt/messages", 7).await;
    assert_eq!(
        messages.len() as u64,
        total(&env.ok("/mqtt/messages").await)
    );
    let times: Vec<i64> = messages
        .iter()
        .map(|m| m["ts_us"].as_i64().unwrap())
        .collect();
    assert!(times.windows(2).all(|w| w[0] <= w[1]));
    let topics = env.all("/mqtt/topics?parent=plant/line1", 2).await;
    let names: HashSet<&str> = topics.iter().map(|n| n["name"].as_str().unwrap()).collect();
    assert_eq!(names.len(), topics.len());
}

#[test]
fn payload_text_rules() {
    assert_eq!(
        payload_text(b"a\tb\r\nc", false, false).as_deref(),
        Some("a\tb\nc")
    );
    assert_eq!(payload_text(b"a\x01b", false, false), None);
    assert_eq!(
        payload_text(b"a\x01b", false, true).as_deref(),
        Some("a\\x01b")
    );
    assert_eq!(payload_text(&[0xff, 0xfe], false, false), None);
    // A character cut by the end of the excerpt.
    assert_eq!(
        payload_text("été".as_bytes().get(..4).unwrap(), true, false).as_deref(),
        Some("ét")
    );
    assert_eq!(
        payload_text("x\u{200b}y".as_bytes(), false, false).as_deref(),
        Some("x\\u{200b}y")
    );
}
