//! Telnet routes on a synthetic capture of three bursts ten minutes apart: the showcase (six
//! sessions: logins accepted and rejected, rich negotiation, truncated transcript, split `IAC`
//! sequences), then two periodic switch logins (`netsift_fixtures::telnet`).

use std::collections::HashSet;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::telnet::{self, SHOWCASE};
use netsift_fixtures::time::NS_PER_SEC;
use netsift_fixtures::{Encoding, Scenario, encode};
use netsift_store::Catalog;
use serde_json::Value;
use tower::ServiceExt;

use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "telnet-token";
/// Gap between two bursts.
const BURST_GAP_NS: i64 = 600 * NS_PER_SEC;

struct Env {
    _tmp: tempfile::TempDir,
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
        telnet::telnet_showcase(&mut sc);
        bursts.push((start, last_ts(&sc)));
        for round in 0..2 {
            sc.advance(BURST_GAP_NS);
            let start = sc.now();
            telnet::telnet_round(&mut sc, round);
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
        let path = captures.join("telnet.pcap");
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

fn module(summary: &Value, id: &str) -> Value {
    summary["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == id)
        .cloned()
        .unwrap_or(Value::Null)
}

/// Sessions of the whole capture: the showcase and two accepted switch logins.
const TOTAL: u64 = SHOWCASE.sessions + 2;

#[tokio::test]
async fn counters_agree_between_list_stats_and_module() {
    let env = Env::new();
    let stats = env.ok("/telnet/stats").await;
    assert_eq!(stats["sessions"], TOTAL);
    assert_eq!(stats["clients"], SHOWCASE.clients);
    assert_eq!(stats["servers"], SHOWCASE.servers);
    assert_eq!(stats["logins"], SHOWCASE.logins + 2);
    assert_eq!(stats["accepted"], SHOWCASE.accepted + 2);
    assert_eq!(stats["rejected"], SHOWCASE.rejected);
    assert_eq!(stats["truncated"], SHOWCASE.truncated);
    let list = env.ok("/telnet/sessions?limit=1").await;
    assert_eq!(list["total_estimate"], TOTAL);
    let summary = env.ok("/summary").await;
    assert_eq!(module(&summary, "telnet")["count"], TOTAL);
    // Telnet logins reach the Credentials view.
    let creds = env.ok("/credentials?protocol=telnet&limit=1").await;
    assert_eq!(creds["total_estimate"], SHOWCASE.credentials + 2);
}

#[tokio::test]
async fn list_never_carries_a_transcript_nor_a_secret() {
    let env = Env::new();
    let (_, raw) = env.get("/telnet/sessions").await;
    let text = raw.to_string();
    assert!(!text.contains("fixture"), "{text}");
    assert!(!text.contains("\"runs\""));
    let first = &raw["items"][0];
    assert_eq!(first["client"]["ip"], "192.168.1.10");
    assert_eq!(first["server"]["ip"], "192.168.1.23");
    assert_eq!(first["server_port"], 23);
    assert_eq!(first["username"], "fake");
    assert_eq!(first["login"], "accepted");
    assert_eq!(first["terminal"], "XTERM");
    assert_eq!(first["window"]["cols"], 80);
    assert!(first["client_bytes"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn detail_rebuilds_the_transcript_with_its_secrets() {
    let env = Env::new();
    let first = env.ok("/telnet/sessions?limit=1").await["items"][0].clone();
    let flow = first["flow_id"].as_i64().unwrap();
    let detail = env.ok(&format!("/telnet/sessions/{flow}")).await;
    assert_eq!(detail["session"], first);
    let runs = detail["runs"].as_array().unwrap();
    let secrets: Vec<&str> = runs
        .iter()
        .filter(|r| r["speaker"] == "secret")
        .map(|r| r["text"].as_str().unwrap())
        .collect();
    assert_eq!(secrets, vec!["user-fixture"]);
    let text: String = runs.iter().map(|r| r["text"].as_str().unwrap()).collect();
    assert!(
        text.contains("login: fake\nPassword:user-fixture\n"),
        "{text}"
    );
    assert!(!text.contains('\u{1b}'));
    insta::assert_json_snapshot!("unix_login_detail", detail);

    for missing in ["/telnet/sessions/999999", "/telnet/sessions/abc"] {
        let (status, _) = env.get(missing).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{missing}");
    }
}

#[tokio::test]
async fn filters_search_and_validation() {
    let env = Env::new();
    let count = |json: &Value| json["total_estimate"].as_u64().unwrap();
    assert_eq!(count(&env.ok("/telnet/sessions?login=rejected").await), 1);
    assert_eq!(
        count(&env.ok("/telnet/sessions?login=accepted").await),
        SHOWCASE.accepted + 2
    );
    assert_eq!(count(&env.ok("/telnet/sessions?login=none").await), 0);
    assert_eq!(count(&env.ok("/telnet/sessions?login=unknown").await), 0);
    // Search in the transcripts (the commands typed), the terminal and the user names.
    assert_eq!(count(&env.ok("/telnet/sessions?q=logread").await), 1);
    assert_eq!(count(&env.ok("/telnet/sessions?q=vt100").await), 1);
    assert_eq!(count(&env.ok("/telnet/sessions?q=netadmin").await), 1);
    assert_eq!(
        count(&env.ok("/telnet/sessions?q=show%20interfaces").await),
        2
    );
    // Never in the secrets.
    assert_eq!(count(&env.ok("/telnet/sessions?q=switch-fixture").await), 0);

    for bad in [
        "/telnet/sessions?login=maybe",
        "/telnet/sessions?cursor=zz",
        "/telnet/sessions?limit=x",
        "/telnet/stats?from_us=10&to_us=1",
    ] {
        let (status, json) = env.get(bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {json}");
    }
    let long = "x".repeat(600);
    let (status, _) = env.get(&format!("/telnet/sessions?q={long}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ranges_overlap_and_whole_session() {
    let env = Env::new();
    let range = env.burst(1);
    let stats = env.ok(&format!("/telnet/stats?{range}")).await;
    assert_eq!(
        (stats["sessions"].as_u64(), stats["accepted"].as_u64()),
        (Some(1), Some(1))
    );
    let list = env.ok(&format!("/telnet/sessions?{range}")).await;
    assert_eq!(list["total_estimate"], 1);
    assert_eq!(list["items"][0]["username"], "monitor");
    let summary = env.ok(&format!("/summary?{range}")).await;
    let m = module(&summary, "telnet");
    assert_eq!(
        (m["count"].as_u64(), m["scope"].as_str()),
        (Some(1), Some("range"))
    );
    // One microsecond inside a session keeps it (overlap), its counters are the session's.
    let (a, b) = env.bursts[2];
    let mid = a + (b - a) / 2;
    let one = env
        .ok(&format!("/telnet/sessions?from_us={mid}&to_us={mid}"))
        .await;
    assert_eq!(one["total_estimate"], 1);
    let list = env.ok("/telnet/sessions").await;
    let whole_session = list["items"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(one["items"][0], whole_session);
    // Disjoint range: empty, never an error.
    let empty = env.ok("/telnet/stats?from_us=1&to_us=2").await;
    assert_eq!(empty["sessions"], 0);
    // A range covering the session answers exactly as without range.
    let whole = format!(
        "from_us={}&to_us={}",
        env.bursts[0].0 - 5,
        env.bursts[2].1 + 5
    );
    for rel in ["/telnet/stats", "/telnet/sessions"] {
        let plain = env.ok(rel).await;
        let ranged = env.ok(&format!("{rel}?{whole}")).await;
        assert_eq!(plain, ranged, "{rel}");
    }
}

#[tokio::test]
async fn pages_have_no_duplicate_nor_gap() {
    let env = Env::new();
    let sessions = env.all("/telnet/sessions", 3).await;
    assert_eq!(sessions.len() as u64, TOTAL);
    let ids: HashSet<i64> = sessions
        .iter()
        .map(|s| s["flow_id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids.len() as u64, TOTAL);
    let times: Vec<i64> = sessions
        .iter()
        .map(|s| s["first_ts_us"].as_i64().unwrap())
        .collect();
    assert!(times.windows(2).all(|w| w[0] <= w[1]));
    let accepted = env.all("/telnet/sessions?login=accepted", 2).await;
    assert_eq!(accepted.len() as u64, SHOWCASE.accepted + 2);
}
