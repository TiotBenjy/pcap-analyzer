use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use netsift_engine::{CancelToken, IngestOptions, ingest};
use netsift_fixtures::proto::netbios::{AnnouncementKind, HostAnnouncement};
use netsift_fixtures::scenario::SmbNtlm;
use netsift_fixtures::scenarios::hosts;
use netsift_fixtures::{Encoding, Scenario, encode};
use netsift_store::Catalog;
use serde_json::Value;
use tower::ServiceExt;

use crate::{ApiConfig, DEFAULT_MAX_IMPORTS, build};

const TOKEN: &str = "smb-token";

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

    fn import_smb(&self) -> String {
        let mut sc = Scenario::new();
        // FILESRV01 announces twice (folds to one row, count 2), a legacy host once, a DC as
        // local master, and an NTLMv2 authentication over TCP 445.
        sc.smb_host_announcement(
            hosts::file_server(),
            hosts::broadcast(),
            &HostAnnouncement::default(),
        );
        sc.smb_host_announcement(
            hosts::file_server(),
            hosts::broadcast(),
            &HostAnnouncement::default(),
        );
        sc.smb_host_announcement(
            hosts::file_server(),
            hosts::broadcast(),
            &HostAnnouncement {
                server_name: "LEGACYPC".to_owned(),
                os_major: 5,
                os_minor: 1,
                ..HostAnnouncement::default()
            },
        );
        sc.smb_host_announcement(
            hosts::file_server(),
            hosts::broadcast(),
            &HostAnnouncement {
                kind: AnnouncementKind::LocalMaster,
                server_name: "DC01".to_owned(),
                ..HostAnnouncement::default()
            },
        );
        sc.smb_ntlm(
            hosts::workstation(),
            hosts::file_server(),
            &SmbNtlm::v2("alice", "CORP"),
        );

        let path = self.captures.join("smb.pcap");
        std::fs::write(&path, encode(sc.packets(), &Encoding::pcap()).unwrap()).unwrap();
        let options = IngestOptions {
            name: Some("smb".to_owned()),
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

#[tokio::test]
async fn announces_fold_per_host_with_endpoints_and_roles() {
    let env = Env::new();
    let id = env.import_smb();
    let (status, json) = env
        .get(&format!("/api/v1/sessions/{id}/smb/announces"))
        .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let items = json["items"].as_array().unwrap();
    // FILESRV01, LEGACYPC, DC01: three folded rows.
    assert_eq!(items.len(), 3);

    let host = items
        .iter()
        .find(|a| a["server_name"] == "FILESRV01")
        .unwrap();
    assert_eq!(host["kind"], "host");
    assert_eq!(host["announce_count"], 2);
    assert_eq!(host["os_label"], "Windows 10 / Server 2016+");
    assert_eq!(host["os_version"], "10.0");
    assert_eq!(host["dst_name"], "WORKGROUP<1D>");
    assert!(host["source"]["ip"].as_str().is_some());
    let roles: Vec<&str> = host["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert!(roles.contains(&"server"));
    assert!(roles.contains(&"workstation"));

    let legacy = items
        .iter()
        .find(|a| a["server_name"] == "LEGACYPC")
        .unwrap();
    assert_eq!(legacy["os_label"], "Windows XP");
}

#[tokio::test]
async fn stats_group_host_announcements_by_os() {
    let env = Env::new();
    let id = env.import_smb();
    let (status, json) = env.get(&format!("/api/v1/sessions/{id}/smb/stats")).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(json["announce_count"], 3);
    assert_eq!(json["session_count"], 1);
    assert_eq!(json["auth_count"], 1);
    let os = json["os"].as_array().unwrap();
    // Two distinct host OSes (the local master is not a host announcement).
    assert_eq!(os.len(), 2);
    let labels: Vec<&str> = os.iter().map(|o| o["label"].as_str().unwrap()).collect();
    assert!(labels.contains(&"Windows 10 / Server 2016+"));
    assert!(labels.contains(&"Windows XP"));
}

#[tokio::test]
async fn auth_lists_sessions_without_any_secret() {
    let env = Env::new();
    let id = env.import_smb();
    let (status, json) = env.get(&format!("/api/v1/sessions/{id}/smb/auth")).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    let s = &items[0];
    assert_eq!(s["account"], "alice");
    assert_eq!(s["domain"], "CORP");
    assert_eq!(s["workstation"], "WS01");
    assert_eq!(s["ntlm_phase"], "authenticate");
    assert_eq!(s["protocol"], "smb2");
    assert_eq!(s["dialect"], "SMB 3.1.1");
    assert_eq!(s["signing"], "required");
    assert_eq!(s["server_port"], 445);
    assert!(s["client"]["ip"].as_str().is_some());
    // No secret material is ever exposed by the SMB view.
    let body = json.to_string();
    for forbidden in ["hashcat", "secret", "nt_response", "proof"] {
        assert!(!body.contains(forbidden), "SMB auth leaked `{forbidden}`");
    }
}
