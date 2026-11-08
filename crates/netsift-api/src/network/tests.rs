//! Route tests of the Network view, on imported synthetic captures.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::scenario::DnsExchange;
use netsift_fixtures::{Encoding, Host, Packet, Scenario, encode};
use netsift_geo::test_util::MmdbBuilder;
use netsift_store::{Catalog, OpenMode, Session, SessionState as StoreState};
use serde_json::Value;
use tower::ServiceExt;

use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "network-token";

struct Env {
    _tmp: tempfile::TempDir,
    data: PathBuf,
    captures: PathBuf,
    geoip: PathBuf,
    app: Router,
}

impl Env {
    fn new() -> Self {
        let tmp = tempfile::TempDir::new().unwrap();
        let data = tmp.path().join("data");
        let captures = tmp.path().join("captures");
        std::fs::create_dir_all(&captures).unwrap();
        let geoip = tmp.path().join("country.mmdb");
        MmdbBuilder::new()
            .network(IpAddr::V4(Ipv4Addr::new(81, 0, 0, 0)), 8, "FR")
            .network(IpAddr::V4(Ipv4Addr::new(5, 0, 0, 0)), 8, "DE")
            .network(IpAddr::V4(Ipv4Addr::new(3, 0, 0, 0)), 8, "US")
            .write(&geoip)
            .unwrap();
        let config = ApiConfig {
            token: TOKEN.to_owned(),
            data_dir: data.clone(),
            captures_roots: vec![captures.clone()],
            read_only: true,
            cors_origins: vec![HeaderValue::from_static("tauri://localhost")],
            allow_any_path: false,
            max_imports: DEFAULT_MAX_IMPORTS,
            geoip_fallback_path: Some(geoip.clone()),
        };
        let (app, _) = build(config, IngestOptions::default());
        Self {
            _tmp: tmp,
            data,
            captures,
            geoip,
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

    async fn ok(&self, uri: &str) -> Value {
        let (status, json) = self.get(uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {json}");
        json
    }

    fn import(&self, name: &str, packets: &[Packet]) -> String {
        let path = self.captures.join(format!("{name}.pcap"));
        std::fs::write(&path, encode(packets, &Encoding::pcap()).unwrap()).unwrap();
        let options = IngestOptions {
            name: Some(name.to_owned()),
            geoip_path: Some(self.geoip.clone()),
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

fn server() -> Host {
    Host::v4([0x02, 0, 0x5e, 0x10, 0, 0x01], [192, 168, 1, 1])
}

/// Spec fixture: 200 public clients (FR, DE, US, and 44.x without country) sending UDP to one
/// LAN server, client `i` sending `i * 10` bytes; client 1 also resolves a name.
fn two_hundred_public() -> Vec<Packet> {
    let mut sc = Scenario::new();
    for i in 1..=200_u16 {
        let first = [81, 5, 3, 44][usize::from(i % 4)];
        let [hi, lo] = i.to_be_bytes();
        let client = Host::v4([0x02, 0, 0x5e, 0x20, hi, lo], [first, 0, hi, lo]);
        sc.udp(
            client,
            server(),
            40_000,
            5_000,
            &vec![0x41; usize::from(i) * 10],
        );
        sc.udp(server(), client, 5_000, 40_000, &[0x42; 10]);
    }
    let first = Host::v4([0x02, 0, 0x5e, 0x20, 0, 1], [5, 0, 0, 1]);
    sc.dns(
        first,
        server(),
        &DnsExchange::a("www.example.test", [81, 0, 0, 80]),
    );
    sc.into_packets()
}

fn node_ids(g: &Value) -> Vec<String> {
    g["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn the_default_graph_is_bounded_and_clustered() {
    let env = Env::new();
    let id = env.import("two-hundred", &two_hundred_public());
    let base = format!("/api/v1/sessions/{id}/network/graph");

    let g = env.ok(&base).await;
    assert_eq!(g["mode"], "hosts");
    assert_eq!(g["hosts"], 201);
    assert_eq!(g["hosts_shown"], 40);
    let nodes = g["nodes"].as_array().unwrap();
    // Spec: about 60 nodes at most by default.
    assert!(nodes.len() <= 60, "{}", nodes.len());
    // The server, the 39 largest clients, the FR/DE/US clusters, and the hosts without country.
    assert_eq!(nodes.len(), 40 + 3 + 1);
    assert_eq!(nodes[0]["id"], "h:192.168.1.1");
    assert_eq!(nodes[0]["kind"], "host");
    assert_eq!(nodes[0]["endpoint"]["category"], "private");
    assert!(nodes[0]["role"].is_null());
    let other = nodes.last().unwrap();
    assert_eq!(other["kind"], "other");
    assert!(other["endpoint"].is_null());
    let clusters: Vec<&Value> = nodes.iter().filter(|n| n["kind"] == "cluster").collect();
    assert_eq!(clusters.len(), 3);
    assert!(clusters.iter().all(|c| c["country"].is_string()));
    let hosts: u64 = nodes.iter().map(|n| n["hosts"].as_u64().unwrap()).sum();
    assert_eq!(hosts, 201);
    let edges = g["edges"].as_array().unwrap();
    assert_eq!(edges.len(), nodes.len() - 1);
    assert_eq!(g["edges_total"], edges.len());
    assert_eq!(g["max_edges"], 400);
    let edge_bytes: u64 = edges.iter().map(|e| e["bytes"].as_u64().unwrap()).sum();
    assert_eq!(edge_bytes, g["total_bytes"].as_u64().unwrap());
    assert_eq!(g["orphans"], 0);
    // Counters of the protocol toggles: every filter, in display order.
    let protocols: Vec<(&str, u64)> = g["protocols"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["protocol"].as_str().unwrap(),
                p["conversations"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(protocols.len(), 11);
    assert_eq!(protocols[0], ("dns", 1));
    assert_eq!(protocols[9], ("udp", 200));

    // Larger limit: every host drawn, no cluster.
    let g = env.ok(&format!("{base}?limit=150")).await;
    assert_eq!(g["hosts_shown"], 150);
    let g = env.ok(&format!("{base}?limit=10&expand=fr")).await;
    let fr = g["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|n| n["endpoint"]["country"] == "FR")
        .count();
    assert_eq!(fr, 30, "the 30 largest FR hosts of the expanded cluster");
    // The other 20 stay in the cluster (bounded expansion).
    let rest = g["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["id"] == "k:FR")
        .unwrap();
    assert_eq!(rest["hosts"], 20);
}

#[tokio::test]
async fn filters_and_country_mode() {
    let env = Env::new();
    let id = env.import("two-hundred", &two_hundred_public());
    let base = format!("/api/v1/sessions/{id}/network/graph");

    let dns = env.ok(&format!("{base}?protocols=dns")).await;
    // Same bytes: sorted by address.
    assert_eq!(node_ids(&dns), ["h:5.0.0.1", "h:192.168.1.1"]);
    assert_eq!(dns["orphans"], 199);
    let orphans = env
        .ok(&format!("{base}?protocols=dns&include_orphans=true"))
        .await;
    assert_eq!(orphans["nodes"].as_array().unwrap().len(), 2 + 30);
    let none = env.ok(&format!("{base}?protocols=")).await;
    assert_eq!(none["nodes"], serde_json::json!([]));
    // Both ends must match: the server is private.
    let public = env.ok(&format!("{base}?category=public")).await;
    assert_eq!(public["hosts"], 0);
    let v4 = env
        .ok(&format!("{base}?ipv6=false&protocols=udp,https"))
        .await;
    assert_eq!(v4["hosts"], 201);

    let c = env.ok(&format!("{base}?mode=countries")).await;
    assert_eq!(c["mode"], "countries");
    let mut ids = node_ids(&c);
    ids.sort();
    assert_eq!(ids, ["c:DE", "c:FR", "c:US", "local", "unknown"]);
    let local = &c["nodes"][0];
    assert_eq!(local["id"], "local");
    assert_eq!(local["kind"], "local");
    assert_eq!(local["hosts"], 1);
    let fr = c["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["id"] == "c:FR")
        .unwrap();
    assert_eq!(fr["kind"], "country");
    assert_eq!(fr["country"], "FR");
    assert_eq!(fr["hosts"], 50);
    assert_eq!(c["edges"].as_array().unwrap().len(), 4);

    for bad in [
        "protocols=gopher",
        "category=lan",
        "mode=planets",
        "expand=FRA",
        "ipv6=maybe",
        "limit=-1",
    ] {
        let (status, json) = env.get(&format!("{base}?{bad}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {json}");
    }
}

#[tokio::test]
async fn node_detail_of_a_host() {
    let env = Env::new();
    let id = env.import("two-hundred", &two_hundred_public());
    let base = format!("/api/v1/sessions/{id}/network/node");
    let d = env.ok(&format!("{base}/192.168.1.1")).await;
    assert_eq!(d["endpoint"]["ip"], "192.168.1.1");
    assert_eq!(d["peers"], 200);
    assert_eq!(d["neighbors"].as_array().unwrap().len(), 10);
    assert_eq!(d["neighbors"][0]["endpoint"]["ip"], "81.0.0.200");
    assert_eq!(d["protocols"], serde_json::json!(["dns", "udp"]));
    assert_eq!(d["macs"], serde_json::json!(["02:00:5e:10:00:01"]));
    assert!(d["first_ts_us"].is_i64());
    assert!(d["role"].is_null());
    let (status, _) = env.get(&format!("{base}/10.9.9.9")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = env.get(&format!("{base}/not-an-ip")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_importing_and_failed_sessions() {
    let env = Env::new();
    let (status, _) = env
        .get("/api/v1/sessions/01J00000000000000000000000/network/graph")
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let catalog = env.catalog();
    for state in [StoreState::Importing, StoreState::Failed] {
        let info = catalog.create("x", &[], 0).unwrap();
        drop(Session::open(catalog.session_dir(&info.id), OpenMode::ReadWrite).unwrap());
        catalog.set_state(&info.id, state, None).unwrap();
        for route in ["network/graph", "network/node/10.0.0.1"] {
            let (status, _) = env
                .get(&format!("/api/v1/sessions/{}/{route}", info.id))
                .await;
            assert_eq!(status, StatusCode::CONFLICT, "{route} {state:?}");
        }
    }
    // A ready session without traffic: an empty graph, not an error.
    let info = catalog.create("empty", &[], 0).unwrap();
    drop(Session::open(catalog.session_dir(&info.id), OpenMode::ReadWrite).unwrap());
    catalog
        .set_state(&info.id, StoreState::Ready, None)
        .unwrap();
    let g = env
        .ok(&format!("/api/v1/sessions/{}/network/graph", info.id))
        .await;
    assert_eq!(g["nodes"], serde_json::json!([]));
    assert_eq!(g["hosts"], 0);
}
