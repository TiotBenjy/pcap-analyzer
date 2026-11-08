//! Route tests of the Connections and Open Ports views, on imported synthetic captures.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::craft::{Side, TcpConv, TcpSeg};
use netsift_fixtures::scenario::DnsExchange;
use netsift_fixtures::scenarios::hosts;
use netsift_fixtures::{Encoding, Host, Packet, Scenario, encode};
use netsift_geo::test_util::MmdbBuilder;
use netsift_store::{Catalog, OpenMode, Session, SessionState as StoreState};
use serde_json::Value;
use tower::ServiceExt;

use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "connections-token";

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
            geoip_path: Some(geoip.clone()),
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

/// Client `i` (1..=30): 10.0.0.i, except 81.0.0.i (FR) for multiples of 5 and 5.0.0.i (DE)
/// for multiples of 7, sends `i * 100` bytes over UDP to the server, which answers 10 bytes.
/// Client 30 also sends a DNS exchange.
fn thirty_endpoints() -> Vec<Packet> {
    let mut sc = Scenario::new();
    for i in 1..=30_u8 {
        let ip = if i % 5 == 0 {
            [81, 0, 0, i]
        } else if i % 7 == 0 {
            [5, 0, 0, i]
        } else {
            [10, 0, 0, i]
        };
        let client = Host::v4([0x02, 0, 0x5e, 0x20, 0, i], ip);
        let payload = vec![0x41; usize::from(i) * 100];
        sc.udp(client, server(), 40_000, 5_000, &payload);
        sc.udp(server(), client, 5_000, 40_000, &[0x42; 10]);
    }
    let ws = Host::v4([0x02, 0, 0x5e, 0x20, 0, 30], [81, 0, 0, 30]);
    sc.dns(
        ws,
        server(),
        &DnsExchange::a("www.example.test", [81, 0, 0, 80]),
    );
    sc.into_packets()
}

fn ips(json: &Value) -> Vec<String> {
    json["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["src"]["ip"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn top_10_matches_the_sql_sort_of_the_table() {
    let env = Env::new();
    let id = env.import("thirty", &thirty_endpoints());

    let table = env
        .ok(&format!("/api/v1/sessions/{id}/connections?limit=10"))
        .await;
    assert!(table["next_cursor"].is_string());
    let top_rows = ips(&table);
    assert_eq!(top_rows.len(), 10);

    let top = env
        .ok(&format!("/api/v1/sessions/{id}/connections/top?n=10"))
        .await;
    assert_eq!(top["conversations"], 10);
    let nodes = top["nodes"].as_array().unwrap();
    // The server first (in every conversation), then the 10 clients by bytes.
    assert_eq!(nodes.len(), 11);
    assert_eq!(nodes[0]["endpoint"]["ip"], "192.168.1.1");
    let node_ips: Vec<String> = nodes[1..]
        .iter()
        .map(|n| n["endpoint"]["ip"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        node_ips, top_rows,
        "same order as the table sorted by bytes"
    );
    // matrix[i][j]: bytes from i to j; the clients only talk to the server.
    let matrix = top["matrix"].as_array().unwrap();
    let total: u64 = matrix
        .iter()
        .flat_map(|r| r.as_array().unwrap())
        .map(|v| v.as_u64().unwrap())
        .sum();
    assert_eq!(total, top["total_bytes"].as_u64().unwrap());
    let first = &table["items"][0];
    assert_eq!(matrix[1][0], first["bytes_fwd"]);
    assert_eq!(matrix[0][1], first["bytes_rev"]);
    assert_eq!(matrix[1][1], 0);

    // Top 50 of 31 hosts: 15 named nodes and the other hosts.
    let top = env
        .ok(&format!("/api/v1/sessions/{id}/connections/top?n=50"))
        .await;
    let nodes = top["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 16);
    assert!(nodes[15]["endpoint"].is_null());
    assert_eq!(top["matrix"].as_array().unwrap().len(), 16);

    // DNS excluded: the DNS bytes of client 30 disappear from its conversation.
    let with = env
        .ok(&format!("/api/v1/sessions/{id}/connections/top?n=20"))
        .await;
    let without = env
        .ok(&format!(
            "/api/v1/sessions/{id}/connections/top?n=20&exclude_dns=true"
        ))
        .await;
    assert_eq!(without["exclude_dns"], true);
    assert!(
        without["total_bytes"].as_u64().unwrap() < with["total_bytes"].as_u64().unwrap(),
        "{without} / {with}"
    );

    for bad in ["n=7", "n=abc", "exclude_dns=maybe"] {
        let (status, _) = env
            .get(&format!("/api/v1/sessions/{id}/connections/top?{bad}"))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[tokio::test]
async fn conversations_are_paginated_filtered_and_sorted() {
    let env = Env::new();
    let id = env.import("thirty", &thirty_endpoints());
    let base = format!("/api/v1/sessions/{id}/connections");

    let first = env.ok(&format!("{base}?limit=12")).await;
    assert_eq!(first["total_estimate"], 30);
    let mut all = ips(&first);
    let mut cursor = first["next_cursor"].as_str().map(str::to_owned);
    while let Some(c) = cursor {
        let page = env.ok(&format!("{base}?limit=12&cursor={c}")).await;
        assert!(
            page["total_estimate"].is_null(),
            "counted on the first page only"
        );
        all.extend(ips(&page));
        cursor = page["next_cursor"].as_str().map(str::to_owned);
    }
    assert_eq!(all.len(), 30);

    let row = &first["items"][0];
    assert_eq!(row["src"]["ip"], "81.0.0.30");
    assert_eq!(row["src"]["country"], "FR");
    assert_eq!(row["src"]["category"], "public");
    assert_eq!(row["dst"]["category"], "private");
    assert_eq!(row["protocols"], serde_json::json!(["dns", "udp"]));
    assert_eq!(row["flows"], 2);
    assert_eq!(
        row["bytes_total"].as_u64().unwrap(),
        row["bytes_fwd"].as_u64().unwrap() + row["bytes_rev"].as_u64().unwrap()
    );

    let asc = env
        .ok(&format!("{base}?sort=bytes&order=asc&limit=1"))
        .await;
    assert_eq!(ips(&asc), ["10.0.0.1"]);
    let flows = env.ok(&format!("{base}?sort=flows&limit=1")).await;
    assert_eq!(ips(&flows), ["81.0.0.30"]);

    let fr = env.ok(&format!("{base}?from=81.0.0.&limit=100")).await;
    assert_eq!(fr["total_estimate"], 6);
    let dns = env.ok(&format!("{base}?protocol=dns")).await;
    assert_eq!(ips(&dns), ["81.0.0.30"]);
    let none = env.ok(&format!("{base}?to=10.0.0.")).await;
    assert_eq!(none["total_estimate"], 0);
    let public = env.ok(&format!("{base}?category=public&limit=100")).await;
    assert_eq!(public["total_estimate"], 10);
    let nothing = env.ok(&format!("{base}?category=")).await;
    assert_eq!(nothing["total_estimate"], 0);

    for bad in [
        "sort=size",
        "order=up",
        "category=lan",
        "cursor=zz",
        "limit=x",
    ] {
        let (status, json) = env.get(&format!("{base}?{bad}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {json}");
    }
    let long = "a".repeat(300);
    let (status, _) = env.get(&format!("{base}?from={long}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn countries_of_sources_and_destinations() {
    let env = Env::new();
    let id = env.import("thirty", &thirty_endpoints());
    let stats = env
        .ok(&format!("/api/v1/sessions/{id}/connections/stats"))
        .await;
    let sources = &stats["sources"];
    let countries: Vec<(&str, u64)> = sources["countries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["country"].as_str().unwrap(), c["hosts"].as_u64().unwrap()))
        .collect();
    // FR: 5, 10, 15, 20, 25, 30 (6 hosts); DE: 7, 14, 21, 28 (35 is past 30).
    assert_eq!(countries, [("FR", 6), ("DE", 4)]);
    assert_eq!(sources["unknown"]["hosts"], 0);
    // The private clients and the server.
    assert_eq!(sources["local"]["hosts"], 21);
    let sum: u64 = sources["countries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["bytes"].as_u64().unwrap())
        .sum::<u64>()
        + sources["local"]["bytes"].as_u64().unwrap()
        + sources["unknown"]["bytes"].as_u64().unwrap();
    assert_eq!(sum, sources["total_bytes"].as_u64().unwrap());
    // Everything is sent to or by the private server: same totals both ways.
    assert_eq!(stats["destinations"]["total_bytes"], sources["total_bytes"]);
    assert_eq!(stats["destinations"]["local"]["hosts"], 21);
}

/// Spec fixture: SYN-ACK on 80/443, RST on 22, a UDP 53 answer.
fn scan() -> Vec<Packet> {
    let mut sc = Scenario::new();
    let target = Host::v4([0x02, 0, 0x5e, 0x10, 0, 0x50], [192, 168, 1, 50]);
    for (client, cport) in [
        (hosts::workstation(), 40_000_u16),
        (hosts::file_server(), 40_100),
    ] {
        for (i, port) in [80_u16, 443, 22].into_iter().enumerate() {
            let conv = TcpConv::new(client, target, cport + u16::try_from(i).unwrap(), port);
            sc.push_frame(conv.syn());
            if port == 22 {
                let rst = TcpSeg::new(0).rst().ack(conv.seq(Side::Client, 0));
                sc.push_frame(conv.frame(Side::Server, &rst, &[]));
            } else {
                sc.push_frame(conv.syn_ack());
                sc.push_frame(conv.rst(Side::Client, 0));
            }
        }
    }
    sc.dns(
        hosts::workstation(),
        hosts::router(),
        &DnsExchange::a("www.example.test", [203, 0, 113, 80]),
    );
    sc.into_packets()
}

/// Port, transport, IANA service and clients of each open port.
type Ports = Vec<(u64, String, Option<String>, u64)>;

#[tokio::test]
async fn open_ports_of_the_spec_fixture() {
    let env = Env::new();
    let id = env.import("scan", &scan());
    let base = format!("/api/v1/sessions/{id}/open-ports");

    let page = env.ok(&base).await;
    assert_eq!(page["total_estimate"], 2);
    let summary: Vec<(String, Ports)> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            (
                h["host"]["ip"].as_str().unwrap().to_owned(),
                h["ports"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| {
                        (
                            p["port"].as_u64().unwrap(),
                            p["transport"].as_str().unwrap().to_owned(),
                            p["service"].as_str().map(str::to_owned),
                            p["clients"].as_u64().unwrap(),
                        )
                    })
                    .collect(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            (
                "192.168.1.50".to_owned(),
                vec![
                    (80, "tcp".to_owned(), Some("http".to_owned()), 2),
                    (443, "tcp".to_owned(), Some("https".to_owned()), 2),
                ]
            ),
            (
                "192.168.1.1".to_owned(),
                vec![(53, "udp".to_owned(), Some("domain".to_owned()), 1)]
            ),
        ],
        "exactly 3 open ports: 22 answered RST"
    );
    let port = &page["items"][0]["ports"][0];
    assert_eq!(port["evidence"], "syn_ack");
    assert!(port["detected"].is_null());
    assert_eq!(page["items"][0]["host"]["category"], "private");
    assert_eq!(page["items"][0]["clients"], 2);

    let stats = env.ok(&format!("{base}/stats")).await;
    assert_eq!(stats["distinct_ports"], 3);
    assert_eq!(stats["open_ports"], 3);
    let top: Vec<(u64, u64)> = stats["top"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["port"].as_u64().unwrap(), p["hosts"].as_u64().unwrap()))
        .collect();
    assert_eq!(top, [(53, 1), (80, 1), (443, 1)]);

    let udp = env.ok(&format!("{base}?port=53")).await;
    assert_eq!(udp["total_estimate"], 1);
    let https = env.ok(&format!("{base}?service=https")).await;
    assert_eq!(https["items"][0]["ports"].as_array().unwrap().len(), 1);
    let text = env.ok(&format!("{base}?q=443")).await;
    assert_eq!(text["total_estimate"], 1);
    let public = env.ok(&format!("{base}?category=public")).await;
    assert_eq!(public["total_estimate"], 0);
    let public_stats = env.ok(&format!("{base}/stats?category=public&n=3")).await;
    assert_eq!(public_stats["top"], serde_json::json!([]));

    for bad in ["port=70000", "category=lan", "cursor=abc"] {
        let (status, _) = env.get(&format!("{base}?{bad}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[tokio::test]
async fn unknown_importing_and_failed_sessions() {
    let env = Env::new();
    let (status, _) = env
        .get("/api/v1/sessions/01J00000000000000000000000/connections")
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let catalog = env.catalog();
    for state in [StoreState::Importing, StoreState::Failed] {
        let info = catalog.create("x", &[], 0).unwrap();
        drop(Session::open(catalog.session_dir(&info.id), OpenMode::ReadWrite).unwrap());
        catalog.set_state(&info.id, state, None).unwrap();
        for route in [
            "connections",
            "connections/stats",
            "connections/top",
            "open-ports",
            "open-ports/stats",
        ] {
            let (status, _) = env
                .get(&format!("/api/v1/sessions/{}/{route}", info.id))
                .await;
            assert_eq!(status, StatusCode::CONFLICT, "{route} {state:?}");
        }
    }
    // A ready session without traffic: empty answers, not errors.
    let info = catalog.create("empty", &[], 0).unwrap();
    drop(Session::open(catalog.session_dir(&info.id), OpenMode::ReadWrite).unwrap());
    catalog
        .set_state(&info.id, StoreState::Ready, None)
        .unwrap();
    let top = env
        .ok(&format!("/api/v1/sessions/{}/connections/top", info.id))
        .await;
    assert_eq!(top["nodes"], serde_json::json!([]));
    let stats = env
        .ok(&format!("/api/v1/sessions/{}/connections/stats", info.id))
        .await;
    assert_eq!(stats["sources"]["total_bytes"], 0);
}
