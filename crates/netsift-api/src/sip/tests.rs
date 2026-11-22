//! SIP routes on a synthetic capture of three bursts ten minutes apart: the showcase (complete,
//! rejected, cancelled and TCP calls, a Digest registration, a scanner sweep, an oversized
//! message), then two periodic rounds (`netsift_fixtures::sip`).

use std::collections::HashSet;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::sip::{self, ShowcaseCounts};
use netsift_fixtures::time::NS_PER_SEC;
use netsift_fixtures::{Encoding, Scenario, encode};
use netsift_store::Catalog;
use serde_json::Value;
use tower::ServiceExt;

use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "sip-token";
/// Gap between two bursts.
const BURST_GAP_NS: i64 = 600 * NS_PER_SEC;
/// Messages of round 0 (a call and a registration) and of round 1 (a call).
const ROUND_0: u64 = 7 + 4;
const ROUND_1: u64 = 7;

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
        let counts = sip::sip_showcase(&mut sc);
        bursts.push((start, last_ts(&sc)));
        for round in 0..2 {
            sc.advance(BURST_GAP_NS);
            let start = sc.now();
            sip::sip_round(&mut sc, round);
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
        let path = captures.join("sip.pcap");
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

    fn burst(&self, i: usize) -> String {
        let (a, b) = self.bursts[i];
        format!("from_us={a}&to_us={b}")
    }

    fn total(&self) -> u64 {
        self.counts.messages() as u64 + ROUND_0 + ROUND_1
    }

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

fn count(json: &Value) -> u64 {
    json["total_estimate"].as_u64().unwrap()
}

#[tokio::test]
async fn counters_agree_between_list_stats_and_module() {
    let env = Env::new();
    let total = env.total();
    let stats = env.ok("/sip/stats").await;
    assert_eq!(stats["messages"], total);
    assert_eq!(
        stats["requests"].as_u64().unwrap() + stats["responses"].as_u64().unwrap(),
        total
    );
    assert_eq!(stats["dialogs"], env.counts.dialogs as u64 + 3);
    assert_eq!(stats["calls"], env.counts.calls as u64 + 2);
    assert_eq!(stats["registrations"], 2);
    assert_eq!(stats["scanner_messages"], env.counts.scanner as u64);
    let invite = stats["methods"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["name"] == "INVITE")
        .unwrap();
    assert_eq!(invite["count"], 6);
    let completed = stats["call_states"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["state"] == "completed")
        .unwrap();
    assert_eq!(completed["count"], 4);
    assert!(stats["call_duration_us"].as_i64().unwrap() > 0);
    assert!(
        stats["top_user_agents"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["name"] == sip::FRIENDLY_SCANNER && a["scanner"] == "SIPVicious")
    );
    let messages = env.ok("/sip/messages?limit=1").await;
    assert_eq!(count(&messages), total);
    let summary = env.ok("/summary").await;
    assert_eq!(module(&summary, "sip")["count"], total);
}

#[tokio::test]
async fn dialogs_carry_state_steps_and_rtp_media() {
    let env = Env::new();
    let calls = env.ok("/sip/dialogs?type=call").await;
    assert_eq!(count(&calls), 6);
    let items = calls["items"].as_array().unwrap();
    let call = items
        .iter()
        .find(|d| d["call_id"] == sip::CALL_COMPLETE)
        .unwrap();
    assert_eq!(call["state"], "completed");
    assert_eq!(call["dialog_type"], "call");
    assert_eq!(call["final_status"], 200);
    assert_eq!(call["client"]["ip"], "10.20.0.21");
    assert_eq!(call["server"]["ip"], "10.20.0.22");
    assert_eq!(call["user_agent"], "Deskphone 7.4.2");
    assert_eq!(call["server_agent"], "Softphone/3.1");
    for step in ["invite_ts_us", "ringing_ts_us", "answer_ts_us", "bye_ts_us"] {
        assert!(call[step].is_i64(), "{step}");
    }
    // Three seconds of RTP, then the BYE.
    let duration = call["duration_us"].as_i64().unwrap();
    assert!((3_000_000..3_100_000).contains(&duration), "{duration}");
    let media = call["media"].as_array().unwrap();
    assert_eq!(media.len(), 2);
    for m in media {
        assert_eq!(m["media"], "audio");
        assert_eq!(m["flow_count"], 1);
        assert_eq!(m["packets"], 2 * sip::RTP_PACKETS as u64);
        assert_eq!(m["codecs"][0], "PCMU");
    }
    let rejected = items
        .iter()
        .find(|d| d["call_id"] == sip::CALL_REJECTED)
        .unwrap();
    assert_eq!(
        (
            rejected["state"].as_str(),
            rejected["final_status"].as_u64()
        ),
        (Some("rejected"), Some(486))
    );
    assert_eq!(rejected["media"][0]["flow_count"], 0);
    let tcp = items
        .iter()
        .find(|d| d["call_id"] == sip::CALL_TCP)
        .unwrap();
    assert_eq!(
        (tcp["transport"].as_str(), tcp["state"].as_str()),
        (Some("tcp"), Some("completed"))
    );

    let registers = env.ok("/sip/dialogs?type=register").await;
    assert_eq!(count(&registers), 2);
    let reg = &registers["items"][0];
    assert_eq!(reg["state"], "ok");
    assert_eq!(reg["challenged"], true);
    assert_eq!(reg["auth_user"], "201");
    assert_eq!(reg["to_uri"], format!("sip:201@{}", sip::REALM));
    let cancelled = env.ok("/sip/dialogs?state=cancelled").await;
    assert_eq!(count(&cancelled), 1);
    let other = env.ok("/sip/dialogs?type=other").await;
    assert_eq!(count(&other), env.counts.scanner as u64 + 1);
    let found = env.ok("/sip/dialogs?q=call-tcp").await;
    assert_eq!(count(&found), 1);
}

#[tokio::test]
async fn message_filters_scanners_credentials_and_validation() {
    let env = Env::new();
    let options = env.ok("/sip/messages?method=options").await;
    assert_eq!(count(&options), env.counts.scanner as u64 + 2);
    let by_call = env
        .ok(&format!("/sip/messages?call_id={}", sip::CALL_COMPLETE))
        .await;
    assert_eq!(count(&by_call), 7);
    let scan = env.ok("/sip/messages?scanner=true").await;
    assert_eq!(count(&scan), env.counts.scanner as u64);
    let raw = scan["items"][0]["raw"].as_str().unwrap();
    assert!(raw.starts_with("OPTIONS sip:100@"));
    assert!(
        !raw.chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
    );
    let agent = env
        .ok(&format!("/sip/messages?agent={}", sip::FRIENDLY_SCANNER))
        .await;
    assert_eq!(count(&agent), env.counts.scanner as u64);
    let from = env.ok("/sip/messages?src=203.0.113.66&kind=request").await;
    assert_eq!(count(&from), env.counts.scanner as u64);
    let big = env.ok("/sip/messages?q=oversized").await;
    assert_eq!(big["items"][0]["raw_truncated"], true);

    let scanners = env.ok("/sip/scanners").await;
    let list = scanners.as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["tool"], "SIPVicious");
    assert_eq!(list[0]["address"]["ip"], "203.0.113.66");
    assert_eq!(list[0]["targets"], env.counts.scanner as u64);
    assert_eq!(list[0]["methods"][0], "OPTIONS");

    // The Digest registrations reach the Credentials view, without secret.
    let creds = env.ok("/credentials?protocol=sip").await;
    let items = creds["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|c| c["kind"] == "sip-digest"
        && c["secret_state"] == "metadata-only"
        && c.get("secret").is_none_or(Value::is_null)));

    for bad in [
        "/sip/dialogs?type=video",
        "/sip/dialogs?state=lost",
        "/sip/messages?kind=other",
        "/sip/messages?src=not-an-ip",
        "/sip/messages?scanner=maybe",
        "/sip/messages?cursor=zz",
        "/sip/dialogs?limit=x",
        "/sip/stats?from_us=10&to_us=1",
        "/sip/scanners?from_us=x",
    ] {
        let (status, json) = env.get(bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {json}");
    }
    let long = "x".repeat(600);
    let (status, _) = env.get(&format!("/sip/messages?q={long}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn middle_burst_range() {
    let env = Env::new();
    let range = env.burst(1);
    let stats = env.ok(&format!("/sip/stats?{range}")).await;
    assert_eq!(stats["messages"], ROUND_0);
    assert_eq!(
        (stats["calls"].as_u64(), stats["registrations"].as_u64()),
        (Some(1), Some(1))
    );
    assert_eq!(stats["scanner_messages"], 0);
    let messages = env.all(&format!("/sip/messages?{range}"), 4).await;
    assert_eq!(messages.len() as u64, ROUND_0);
    let (a, b) = env.bursts[1];
    assert!(messages.iter().all(|m| {
        let t = m["ts_us"].as_i64().unwrap();
        t >= a && t <= b
    }));
    let summary = env.ok(&format!("/summary?{range}")).await;
    let m = module(&summary, "sip");
    assert_eq!(m["count"], ROUND_0);
    assert_eq!(m["scope"], "range");
    let dialogs = env.ok(&format!("/sip/dialogs?{range}")).await;
    assert_eq!(count(&dialogs), 2);
    assert_eq!(
        env.ok(&format!("/sip/scanners?{range}")).await,
        Value::Array(Vec::new())
    );

    insta::assert_json_snapshot!("middle_burst", (stats, dialogs));
}

#[tokio::test]
async fn dialogs_overlap_and_whole_session_range() {
    let env = Env::new();
    // One microsecond inside the complete call (between its 180 and its BYE): the call
    // overlaps, with its session counters; no message is in the range.
    let call = env
        .ok(&format!("/sip/dialogs?q={}", sip::CALL_COMPLETE))
        .await;
    let answer = call["items"][0]["answer_ts_us"].as_i64().unwrap() + 1;
    let one = format!("from_us={answer}&to_us={answer}");
    let overlap = env.ok(&format!("/sip/dialogs?{one}")).await;
    assert_eq!(count(&overlap), 1);
    assert_eq!(overlap["items"][0]["requests"], 3);
    assert_eq!(count(&env.ok(&format!("/sip/messages?{one}")).await), 0);
    // Disjoint range: empty, never an error.
    let empty = env.ok("/sip/stats?from_us=1&to_us=2").await;
    assert_eq!(
        (empty["messages"].as_u64(), empty["dialogs"].as_u64()),
        (Some(0), Some(0))
    );
    // A range covering the session answers exactly as without range.
    let whole = format!(
        "from_us={}&to_us={}",
        env.bursts[0].0 - 5,
        env.bursts[2].1 + 5
    );
    for rel in [
        "/sip/stats",
        "/sip/dialogs",
        "/sip/messages",
        "/sip/scanners",
    ] {
        let plain = env.ok(rel).await;
        let ranged = env.ok(&format!("{rel}?{whole}")).await;
        assert_eq!(plain, ranged, "{rel}");
    }
}

#[tokio::test]
async fn pages_have_no_duplicate_nor_gap() {
    let env = Env::new();
    let total = env.total();
    let messages = env.all("/sip/messages", 7).await;
    assert_eq!(messages.len() as u64, total);
    let ids: HashSet<i64> = messages.iter().map(|m| m["id"].as_i64().unwrap()).collect();
    assert_eq!(ids.len() as u64, total);
    let times: Vec<i64> = messages
        .iter()
        .map(|m| m["ts_us"].as_i64().unwrap())
        .collect();
    assert!(times.windows(2).all(|w| w[0] <= w[1]));
    let dialogs = env.all("/sip/dialogs", 2).await;
    assert_eq!(dialogs.len(), env.counts.dialogs + 3);
    let starts: Vec<i64> = dialogs
        .iter()
        .map(|d| d["first_ts_us"].as_i64().unwrap())
        .collect();
    assert!(starts.windows(2).all(|w| w[0] <= w[1]));
    let ranged = env
        .all(&format!("/sip/messages?kind=response&{}", env.burst(2)), 2)
        .await;
    assert_eq!(ranged.len(), 4);
}
