use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::Scenario;
use netsift_fixtures::scenario::DnsExchange;
use netsift_fixtures::scenarios::hosts;
use netsift_fixtures::servers::{DhcpLease, servers_showcase};
use netsift_fixtures::{Encoding, encode};
use netsift_store::Catalog;
use serde_json::Value;
use tower::ServiceExt;

use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "servers-token";

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
            geoip_path: None,
        };
        let (app, _) = build(config, IngestOptions::default());
        Self {
            _tmp: tmp,
            data,
            captures,
            app,
        }
    }

    fn import(&self, sc: &Scenario) -> String {
        let path = self.captures.join("servers.pcap");
        std::fs::write(&path, encode(sc.packets(), &Encoding::pcap()).unwrap()).unwrap();
        let options = IngestOptions {
            name: Some("servers".to_owned()),
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
}

fn role<'a>(json: &'a Value, name: &str) -> &'a Value {
    json["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["role"] == name)
        .unwrap_or_else(|| panic!("role {name} missing in {json}"))
}

fn kinds(server: &Value) -> Vec<&str> {
    server["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect()
}

/// Acceptance fixture of `docs/specs/servers.md`: a DNS responder and a DHCP server.
fn dns_and_dhcp() -> Scenario {
    let mut sc = Scenario::new();
    sc.dns(
        hosts::workstation(),
        hosts::router(),
        &DnsExchange::a("example.test", [192, 0, 2, 1]),
    );
    let lease = DhcpLease {
        xid: 42,
        client_mac: [2, 0, 0x5e, 0x10, 0, 0x40],
        address: [192, 168, 1, 40].into(),
        hostname: Some("tablet".to_owned()),
        lease_time: 3600,
        router: [192, 168, 1, 1].into(),
        dns: vec![[192, 168, 1, 1].into()],
    };
    sc.dhcp_dora(hosts::router(), &lease);
    sc
}

#[tokio::test]
async fn dns_and_dhcp_cards_are_populated_and_ldap_is_empty() {
    let env = Env::new();
    let id = env.import(&dns_and_dhcp());
    let (status, json) = env.get(&format!("/api/v1/sessions/{id}/servers")).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["analyzed"], true);
    let order: Vec<&str> = json["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["role"].as_str().unwrap())
        .collect();
    assert_eq!(
        order,
        ["dns", "dhcp", "ldap", "ntp", "kerberos", "smb", "http"]
    );

    let dns = role(&json, "dns");
    assert_eq!(dns["total"], 1);
    let server = &dns["servers"][0];
    assert_eq!(server["endpoint"]["ip"], "192.168.1.1");
    assert_eq!(server["endpoint"]["category"], "private");
    assert!(kinds(server).contains(&"dns_response"));
    let response = &server["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "dns_response")
        .unwrap();
    assert_eq!(response["count"], 1);
    assert_eq!(response["clients"], 1);
    assert!(response["first_ts_us"].as_i64().unwrap() > 0);

    let dhcp = role(&json, "dhcp");
    assert_eq!(dhcp["total"], 1);
    let server = &dhcp["servers"][0];
    assert_eq!(server["endpoint"]["ip"], "192.168.1.1");
    assert_eq!(kinds(server), ["dhcp_offer", "dhcp_ack"]);
    assert_eq!(server["evidence"][0]["example"], "192.168.1.40");
    assert_eq!(server["count"], 2);

    let ldap = role(&json, "ldap");
    assert_eq!(ldap["total"], 0);
    assert_eq!(ldap["servers"].as_array().unwrap().len(), 0);

    // The module counter of the overview counts (role, server) pairs.
    let (_, summary) = env.get(&format!("/api/v1/sessions/{id}/summary")).await;
    let module = summary["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == "servers")
        .unwrap();
    assert_eq!(module["count"], 2);
}

#[tokio::test]
async fn every_role_of_the_showcase_has_its_evidence() {
    let env = Env::new();
    let mut sc = Scenario::new();
    servers_showcase(&mut sc);
    let id = env.import(&sc);
    let (status, json) = env.get(&format!("/api/v1/sessions/{id}/servers")).await;
    assert_eq!(status, StatusCode::OK, "{json}");

    let ldap = &role(&json, "ldap")["servers"][0];
    assert_eq!(ldap["endpoint"]["ip"], "192.168.1.5");
    assert_eq!(ldap["endpoint"]["names"][0], "dc.corp.example");
    let mut k = kinds(ldap);
    k.sort_unstable();
    assert_eq!(k, ["dns_srv", "open_port"]);

    let kdc = &role(&json, "kerberos")["servers"][0];
    let mut k = kinds(kdc);
    k.sort_unstable();
    assert_eq!(
        k,
        [
            "dns_srv",
            "kdc_as_rep",
            "kdc_error",
            "kdc_tgs_rep",
            "open_port",
            "open_port"
        ]
    );
    let as_rep = kdc["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "kdc_as_rep")
        .unwrap();
    assert_eq!(as_rep["example"], "CORP.EXAMPLE");

    let ntp = &role(&json, "ntp")["servers"][0];
    assert_eq!(ntp["endpoint"]["ip"], "203.0.113.123");
    // Documentation range (TEST-NET-3): `reserved`, not `public`.
    assert_eq!(ntp["endpoint"]["category"], "reserved");
    let response = ntp["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "ntp_response")
        .unwrap();
    assert_eq!(response["example"], "stratum 2, 192.0.2.1");
}

#[tokio::test]
async fn role_category_and_limit_filters() {
    let env = Env::new();
    let mut sc = Scenario::new();
    servers_showcase(&mut sc);
    let id = env.import(&sc);
    let base = format!("/api/v1/sessions/{id}/servers");

    let (status, json) = env.get(&format!("{base}?role=ntp")).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["roles"].as_array().unwrap().len(), 1);
    assert_eq!(role(&json, "ntp")["total"], 1);

    // One category only: the NTP server (documentation range) stays, the LAN ones go.
    let (_, json) = env.get(&format!("{base}?category=reserved")).await;
    assert_eq!(role(&json, "ntp")["total"], 1);
    assert_eq!(role(&json, "dns")["total"], 0);
    assert_eq!(role(&json, "kerberos")["total"], 0);
    let (_, json) = env.get(&format!("{base}?category=private")).await;
    assert_eq!(role(&json, "ntp")["total"], 0);
    assert_eq!(role(&json, "kerberos")["total"], 1);
    // Every toggle off: nothing.
    let (_, json) = env.get(&format!("{base}?category=")).await;
    assert!(
        json["roles"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["total"] == 0)
    );

    // The limit bounds the listed servers, not the total.
    let (_, json) = env.get(&format!("{base}?role=dns&limit=0")).await;
    let dns = role(&json, "dns");
    assert_eq!(dns["servers"].as_array().unwrap().len(), 1);

    for bad in ["role=wins", "category=lan", "limit=x"] {
        let (status, json) = env.get(&format!("{base}?{bad}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {json}");
    }
    let (status, _) = env
        .get("/api/v1/sessions/00000000000000000000000000/servers")
        .await;
    assert!(status == StatusCode::NOT_FOUND || status == StatusCode::BAD_REQUEST);
}

#[test]
fn grouping_sorts_servers_and_evidence() {
    use netsift_store::connections::EndpointInfo;
    use netsift_store::servers::{EvidenceEntry, RoleEvidence};

    use super::{ServerRole, group};
    let entry = |ip: &str, kind: &str, count: u64| EvidenceEntry {
        role: "dns".to_owned(),
        ip: ip.parse().unwrap(),
        kind: kind.to_owned(),
        count,
        clients: None,
        first_ts: 5_000,
        last_ts: 9_000,
        example: None,
        host: EndpointInfo::default(),
    };
    let found = |entries: Vec<EvidenceEntry>| RoleEvidence {
        entries,
        totals: Vec::new(),
    };
    let roles = group(
        found(vec![
            entry("10.0.0.2", "open_port", 1),
            entry("10.0.0.1", "open_port", 4),
            entry("10.0.0.2", "dns_response", 10),
            entry("10.0.0.3", "unknown_kind", 99),
        ]),
        &[ServerRole::Dns],
        None,
        10,
    );
    let dns = &roles[0];
    assert_eq!(dns.total, 2);
    assert_eq!(dns.servers[0].endpoint.ip, "10.0.0.2");
    assert_eq!(dns.servers[0].count, 11);
    assert_eq!(dns.servers[0].evidence[0].count, 10);
    assert_eq!(
        (dns.servers[0].first_ts_us, dns.servers[0].last_ts_us),
        (5, 9)
    );
    let limited = group(
        found(vec![entry("10.0.0.1", "open_port", 4)]),
        &[ServerRole::Dns],
        None,
        0,
    );
    assert_eq!((limited[0].total, limited[0].servers.len()), (1, 0));
    // A server without stored category is filtered from its address and leaves the total.
    let filtered = group(
        RoleEvidence {
            entries: vec![
                entry("10.0.0.1", "open_port", 4),
                entry("8.8.8.8", "open_port", 1),
            ],
            totals: vec![("dns".to_owned(), 2)],
        },
        &[ServerRole::Dns],
        Some(&["private".to_owned()]),
        10,
    );
    assert_eq!((filtered[0].total, filtered[0].servers.len()), (1, 1));
}
