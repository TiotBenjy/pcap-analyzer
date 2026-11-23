//! FTP routes on a synthetic capture: the showcase (`netsift_fixtures::ftp`), then two small
//! passive sessions ten minutes later.

use std::collections::HashSet;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::ftp::{self, FtpShowcase};
use netsift_fixtures::time::NS_PER_SEC;
use netsift_fixtures::{Encoding, Scenario, encode};
use netsift_store::Catalog;
use serde_json::Value;
use tower::ServiceExt;

use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "ftp-token";
const GAP_NS: i64 = 600 * NS_PER_SEC;

struct Env {
    _tmp: tempfile::TempDir,
    app: Router,
    id: String,
    showcase: FtpShowcase,
    /// `[first, last]` packet time of the showcase and of the later rounds, microseconds.
    parts: Vec<(i64, i64)>,
}

impl Env {
    fn new() -> Self {
        let mut sc = Scenario::new();
        let start = sc.now();
        let showcase = ftp::ftp_showcase(&mut sc);
        let mut parts = vec![(start, last_ts(&sc))];
        sc.advance(GAP_NS);
        let start = sc.now();
        ftp::ftp_round(&mut sc, 1);
        ftp::ftp_round(&mut sc, 2);
        parts.push((start, last_ts(&sc)));
        let parts = parts
            .into_iter()
            .map(|(a, b)| (a / 1000, b / 1000))
            .collect();

        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        let captures = tmp.path().join("captures");
        std::fs::create_dir_all(&captures).unwrap();
        let path = captures.join("ftp.pcap");
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
            showcase,
            parts,
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
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn ok(&self, rel: &str) -> Value {
        let (status, json) = self.get(rel).await;
        assert_eq!(status, StatusCode::OK, "{rel}: {json}");
        json
    }

    fn part(&self, i: usize) -> String {
        let (a, b) = self.parts[i];
        format!("from_us={a}&to_us={b}")
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

#[tokio::test]
async fn counters_agree_between_lists_stats_and_module() {
    let env = Env::new();
    let sessions = env.showcase.sessions as u64 + 2;
    let transfers = env.showcase.transfers as u64 + 2;
    let stats = env.ok("/ftp/stats").await;
    assert_eq!(stats["sessions"], sessions);
    assert_eq!(stats["transfers"], transfers);
    assert_eq!(stats["stored"], env.showcase.stored as u64 + 2);
    assert_eq!(stats["logins_rejected"], 1);
    assert_eq!(stats["tls_sessions"], 1);
    assert_eq!(stats["listings"], 1);
    assert_eq!(stats["uploads"], 1);
    assert_eq!(stats["failed"], 1);
    let page = env.ok("/ftp/sessions?limit=1").await;
    assert_eq!(page["total_estimate"], sessions);
    let page = env.ok("/ftp/transfers?limit=1").await;
    assert_eq!(page["total_estimate"], transfers);
    let summary = env.ok("/summary").await;
    assert_eq!(module(&summary, "ftp")["count"], sessions);
    // The image downloaded by FTP is a picture.
    let pictures = env.ok("/objects").await;
    let ftp_items: Vec<&Value> = pictures["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["source"] == "ftp")
        .collect();
    assert_eq!(ftp_items.len(), 1);
    assert_eq!(ftp_items[0]["uri"], "photos/harbour.png");
    assert_eq!(ftp_items[0]["mime"], "image/png");
    // A path, not a URL.
    assert_eq!(ftp_items[0]["url"], Value::Null);
    assert_eq!(ftp_items[0]["source"], "ftp");
}

#[tokio::test]
async fn lists_never_carry_the_password() {
    let env = Env::new();
    for rel in [
        "/ftp/sessions",
        "/ftp/transfers",
        "/ftp/stats",
        "/objects?kind=all",
    ] {
        let json = env.ok(rel).await.to_string();
        assert!(!json.contains(ftp::SECRET), "{rel}");
    }
}

#[tokio::test]
async fn detail_carries_the_transcript_and_transfers() {
    let env = Env::new();
    let page = env.ok("/ftp/sessions?q=alice").await;
    assert_eq!(page["total_estimate"], 1);
    let s = &page["items"][0];
    assert_eq!(s["username"], "alice");
    assert_eq!(s["login"], "accepted");
    assert_eq!(s["files"], 2);
    let flow = s["flow_id"].as_str().unwrap();
    let detail = env.ok(&format!("/ftp/sessions/{flow}")).await;
    let lines = detail["lines"].as_array().unwrap();
    assert_eq!(lines.len() as u64, s["lines"].as_u64().unwrap());
    let pass = lines.iter().find(|l| l["head"] == "PASS").unwrap();
    assert_eq!(pass["secret"], true);
    assert_eq!(pass["text"], ftp::SECRET);
    assert_eq!(pass["kind"], "command");
    let transfers = detail["transfers"].as_array().unwrap();
    assert_eq!(transfers.len(), 2);
    assert_eq!(transfers[0]["direction"], "download");
    assert_eq!(transfers[0]["status"], 226);
    let sha = transfers[0]["sha256"].as_str().unwrap();
    // The stored file is served by the objects routes.
    let (status, _) = env.get(&format!("/objects/{sha}/thumb")).await;
    assert_ne!(status, StatusCode::NOT_FOUND);
    assert_eq!(transfers[1]["direction"], "upload");
    // Unknown or invalid session.
    assert_eq!(
        env.get("/ftp/sessions/999999").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(env.get("/ftp/sessions/abc").await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn filters_and_validation() {
    let env = Env::new();
    let count = |json: Value| json["total_estimate"].as_u64().unwrap();
    assert_eq!(count(env.ok("/ftp/sessions?login=rejected").await), 1);
    assert_eq!(count(env.ok("/ftp/sessions?login=none").await), 1);
    assert_eq!(count(env.ok("/ftp/transfers?direction=listing").await), 1);
    assert_eq!(count(env.ok("/ftp/transfers?q=README").await), 1);
    let alice = env.ok("/ftp/sessions?q=alice").await;
    let flow = alice["items"][0]["flow_id"].as_str().unwrap().to_owned();
    assert_eq!(
        count(env.ok(&format!("/ftp/transfers?session={flow}")).await),
        2
    );
    for bad in [
        "/ftp/sessions?login=maybe",
        "/ftp/transfers?direction=sideways",
        "/ftp/transfers?session=x",
        "/ftp/stats?from_us=10&to_us=1",
    ] {
        assert_eq!(env.get(bad).await.0, StatusCode::BAD_REQUEST, "{bad}");
    }
    let long = "a".repeat(600);
    assert_eq!(
        env.get(&format!("/ftp/sessions?q={long}")).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn ranges_select_sessions_by_overlap_and_transfers_by_point() {
    let env = Env::new();
    let later = env.ok(&format!("/ftp/stats?{}", env.part(1))).await;
    assert_eq!(later["sessions"], 2);
    assert_eq!(later["transfers"], 2);
    assert_eq!(later["tls_sessions"], 0);
    let sessions = env.ok(&format!("/ftp/sessions?{}", env.part(1))).await;
    assert_eq!(sessions["total_estimate"], 2);
    let transfers = env.ok(&format!("/ftp/transfers?{}", env.part(1))).await;
    assert_eq!(transfers["total_estimate"], 2);
    let summary = env.ok(&format!("/summary?{}", env.part(1))).await;
    assert_eq!(module(&summary, "ftp")["count"], 2);
    // A range covering the session answers like no range.
    let (a, _) = env.parts[0];
    let (_, b) = env.parts[1];
    let whole = env.ok(&format!("/ftp/stats?from_us={a}&to_us={b}")).await;
    assert_eq!(whole, env.ok("/ftp/stats").await);
    // A disjoint range: empty, never an error.
    let empty = env
        .ok(&format!(
            "/ftp/stats?from_us={}&to_us={}",
            b + 1_000_000,
            b + 2_000_000
        ))
        .await;
    assert_eq!(empty["sessions"], 0);
    assert_eq!(empty["transfers"], 0);
}

#[tokio::test]
async fn pages_follow_the_keyset_without_holes() {
    let env = Env::new();
    let total = env.ok("/ftp/sessions").await["total_estimate"]
        .as_u64()
        .unwrap();
    let all = env.all("/ftp/sessions", 3).await;
    assert_eq!(all.len() as u64, total);
    let ids: HashSet<&str> = all.iter().map(|s| s["flow_id"].as_str().unwrap()).collect();
    assert_eq!(ids.len(), all.len());
    let total = env.ok("/ftp/transfers").await["total_estimate"]
        .as_u64()
        .unwrap();
    let all = env.all("/ftp/transfers", 2).await;
    assert_eq!(all.len() as u64, total);
    let ids: HashSet<i64> = all.iter().map(|t| t["id"].as_i64().unwrap()).collect();
    assert_eq!(ids.len(), all.len());
}

#[tokio::test]
async fn showcase_snapshot() {
    let env = Env::new();
    let stats = env.ok(&format!("/ftp/stats?{}", env.part(0))).await;
    let mut transfers = env.ok(&format!("/ftp/transfers?{}", env.part(0))).await;
    // Row ids follow the arrival order of the records: not part of the snapshot.
    for t in transfers["items"].as_array_mut().unwrap() {
        t.as_object_mut().unwrap().remove("id");
    }
    insta::assert_json_snapshot!("showcase", (stats, transfers["items"].clone()));
}
