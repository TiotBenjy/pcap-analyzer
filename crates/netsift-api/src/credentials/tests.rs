use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::credentials::credentials_showcase;
use netsift_fixtures::{Encoding, Scenario, encode};
use netsift_store::Catalog;
use serde_json::Value;
use tower::ServiceExt;

use super::{cell, rfc3339};
use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "creds-token";

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
            // Read-only server: reading and exporting are not mutations.
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

    fn import(&self) -> String {
        let mut sc = Scenario::new();
        credentials_showcase(&mut sc);
        let path = self.captures.join("creds.pcap");
        std::fs::write(&path, encode(sc.packets(), &Encoding::pcap()).unwrap()).unwrap();
        let options = IngestOptions {
            name: Some("creds".to_owned()),
            ..IngestOptions::default()
        };
        let catalog = Catalog::open(&self.data).unwrap();
        ingest(&catalog, &path, &options, &CancelToken::new(), &mut |_| {})
            .unwrap()
            .session
            .to_string()
    }

    async fn raw(&self, uri: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
        let req = Request::get(uri)
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = axum::body::to_bytes(res.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap();
        (status, headers, bytes.to_vec())
    }

    async fn get(&self, uri: &str) -> (StatusCode, Value) {
        let (status, _, body) = self.raw(uri).await;
        (status, serde_json::from_slice(&body).unwrap())
    }
}

const SECRETS: [&str; 9] = [
    "s3cret-fixture",
    "basic-fixture",
    "proxy-fixture",
    "smtp-fixture",
    "login-fixture",
    "pop-fixture",
    "imap-fixture",
    "ldap-fixture",
    "mmartin::CONTOSO",
];

#[tokio::test]
async fn list_stats_and_paths_carry_no_secret() {
    let env = Env::new();
    let id = env.import();
    let base = format!("/api/v1/sessions/{id}/credentials");

    let (status, list) = env.get(&base).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let items = list["items"].as_array().unwrap();
    // FTP, SNMP, Basic, Proxy, HTTP NTLM, SMB NTLM, 3 SMTP, POP3, IMAP, LDAP.
    assert_eq!(items.len(), 12, "{list}");
    assert_eq!(list["total_estimate"], 12);
    let ftp = &items[0];
    assert_eq!(ftp["protocol"], "ftp");
    assert_eq!(ftp["username"], "alice");
    assert_eq!(ftp["secret_state"], "plaintext");
    assert_eq!(ftp["has_secret"], true);
    assert_eq!(ftp["server"]["port"], 21);
    assert_eq!(ftp["server"]["endpoint"]["ip"], "192.168.1.21");
    assert_eq!(ftp["id"].as_str().unwrap().len(), 64);
    assert!(
        ftp["details"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["key"] == "result" && d["value"] == "accepted")
    );

    let (status, stats) = env.get(&format!("{base}/stats")).await;
    assert_eq!(status, StatusCode::OK, "{stats}");
    assert_eq!(stats["analyzed"], true);
    assert_eq!(stats["total"], 12);
    assert_eq!(stats["plaintext"], 9);
    assert_eq!(stats["recoverable"], 3);
    assert_eq!(stats["metadata_only"], 0);
    assert_eq!(stats["handshakes"], 0);
    let modes: Vec<u64> = stats["hashcat_modes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["mode"].as_u64().unwrap())
        .collect();
    assert_eq!(modes, vec![5500, 5600, 16400]);

    let (status, paths) = env.get(&format!("{base}/paths?limit=3")).await;
    assert_eq!(status, StatusCode::OK, "{paths}");
    assert_eq!(paths["paths"].as_array().unwrap().len(), 3);
    assert!(paths["others"].as_u64().unwrap() > 0);

    for body in [list.to_string(), stats.to_string(), paths.to_string()] {
        for secret in SECRETS {
            assert!(!body.contains(secret), "a list route leaked a secret");
        }
        assert!(!body.contains("hashcat_line"));
    }

    // Filters.
    let (_, smtp) = env.get(&format!("{base}?protocol=smtp")).await;
    assert_eq!(smtp["items"].as_array().unwrap().len(), 3);
    let (_, rec) = env.get(&format!("{base}?state=recoverable&limit=1")).await;
    assert_eq!(rec["items"].as_array().unwrap().len(), 1);
    assert_eq!(rec["total_estimate"], 3);
    assert!(rec["next_cursor"].is_string());
    let (status, _) = env.get(&format!("{base}?state=bogus")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn detail_serves_the_secret_on_demand() {
    let env = Env::new();
    let id = env.import();
    let base = format!("/api/v1/sessions/{id}/credentials");
    let (_, list) = env.get(&format!("{base}?protocol=ftp")).await;
    let fp = list["items"][0]["id"].as_str().unwrap().to_owned();
    let (status, d) = env.get(&format!("{base}/{fp}")).await;
    assert_eq!(status, StatusCode::OK, "{d}");
    assert_eq!(d["secret"], "s3cret-fixture");
    assert_eq!(d["info"]["username"], "alice");

    let (_, list) = env.get(&format!("{base}?protocol=smb")).await;
    let fp = list["items"][0]["id"].as_str().unwrap().to_owned();
    let (_, d) = env.get(&format!("{base}/{fp}")).await;
    assert_eq!(d["info"]["hashcat_mode"], 5500);
    assert!(
        d["hashcat_line"]
            .as_str()
            .unwrap()
            .starts_with("svc_backup::CONTOSO:")
    );
    assert!(d["secret"].is_null());

    let (status, _) = env.get(&format!("{base}/{}", "0".repeat(64))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = env.get(&format!("{base}/not-a-fingerprint")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn exports_csv_and_hashcat_as_attachments() {
    let env = Env::new();
    let id = env.import();
    let base = format!("/api/v1/sessions/{id}/credentials");

    let (status, headers, body) = env.raw(&format!("{base}/export?format=csv")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "text/csv; charset=utf-8");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(headers[header::CONTENT_SECURITY_POLICY], "sandbox");
    assert!(
        headers[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .starts_with("attachment; filename=\"credentials-")
    );
    let csv = String::from_utf8(body).unwrap();
    let lines: Vec<&str> = csv.split("\r\n").filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 13, "{csv}");
    assert!(lines[0].starts_with("first_seen,last_seen,protocol"));
    assert!(
        lines[1].contains(",ftp,ftp,") && lines[1].contains("s3cret-fixture"),
        "{}",
        lines[1]
    );
    assert!(lines[1].starts_with("2023-11-14T22:13:20."), "{}", lines[1]);

    // A selection by id.
    let (_, list) = env.get(&format!("{base}?protocol=ldap")).await;
    let fp = list["items"][0]["id"].as_str().unwrap().to_owned();
    let (_, _, body) = env.raw(&format!("{base}/export?format=csv&ids={fp}")).await;
    let csv = String::from_utf8(body).unwrap();
    assert_eq!(csv.lines().count(), 2);
    assert!(csv.contains("ldap-fixture"));

    // hashcat: one mode per file, lines only.
    let (status, headers, body) = env
        .raw(&format!("{base}/export?format=hashcat&mode=5600"))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "text/plain; charset=utf-8");
    let text = String::from_utf8(body).unwrap();
    assert_eq!(text.lines().count(), 1, "{text}");
    assert!(text.starts_with("mmartin::CONTOSO:1122334455667788:"));

    let (status, _, _) = env.raw(&format!("{base}/export?format=hashcat")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = env.raw(&format!("{base}/export?format=xml")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = env.raw(&format!("{base}/export?ids=zz")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_module_is_listed_in_the_summary() {
    let env = Env::new();
    let id = env.import();
    let (status, summary) = env.get(&format!("/api/v1/sessions/{id}/summary")).await;
    assert_eq!(status, StatusCode::OK);
    let module = summary["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == "credentials")
        .cloned()
        .unwrap();
    assert_eq!(module["count"], 12);
}

#[test]
fn csv_cells_are_quoted_and_never_formulas() {
    assert_eq!(cell("plain"), "plain");
    assert_eq!(cell("a,b"), "\"a,b\"");
    assert_eq!(cell("say \"hi\""), "\"say \"\"hi\"\"\"");
    assert_eq!(cell("=HYPERLINK(1)"), "'=HYPERLINK(1)");
    assert_eq!(cell("-1+2"), "'-1+2");
    assert_eq!(cell("@x,y"), "\"'@x,y\"");
}

#[test]
fn timestamps_are_utc_rfc3339() {
    assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000000Z");
    assert_eq!(
        rfc3339(1_700_000_000_123_456_789),
        "2023-11-14T22:13:20.123456Z"
    );
    assert_eq!(
        rfc3339(951_782_400_000_000_000),
        "2000-02-29T00:00:00.000000Z"
    );
    assert_eq!(rfc3339(-1_000), "1969-12-31T23:59:59.999999Z");
}
