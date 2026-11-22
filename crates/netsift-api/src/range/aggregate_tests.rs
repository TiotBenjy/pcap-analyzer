//! Time range over the aggregated views (P5.2b): Connections, Open Ports, Servers, Network and
//! their module counts, on the spread fixture (`tests.rs` for the environment). Their tables come
//! from a range database built at the first request of a range (`netsift_store::ranges`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::tests::{Env, items, module, total, with_range};

/// Range databases of the server (the temporary directory of a read-only server, else the
/// session directory).
fn range_files(env: &Env) -> Vec<PathBuf> {
    let dir = if env.state.config.read_only {
        env.state
            .range_scratch
            .get()
            .and_then(Option::as_ref)
            .map(|d| d.path().join(&env.id))
    } else {
        Some(
            env.tmp
                .path()
                .join("data/sessions")
                .join(&env.id)
                .join(super::RANGES_DIR),
        )
    };
    let Some(dir) = dir else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map(|e| e.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    files.retain(|f| f.extension().is_some_and(|e| e == "db"));
    files.sort();
    files
}

fn ends(c: &Value) -> (String, String) {
    (
        c["src"]["ip"].as_str().unwrap().to_owned(),
        c["dst"]["ip"].as_str().unwrap().to_owned(),
    )
}

fn by_ends(page: &Value) -> BTreeMap<(String, String), Value> {
    items(page).iter().map(|c| (ends(c), c.clone())).collect()
}

/// Every page of `path` (with `limit=1`), in order.
async fn all_pages(env: &Env, path: &str) -> Vec<Value> {
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut p = format!("{path}&limit=1");
        if let Some(c) = &cursor {
            p.push_str("&cursor=");
            p.push_str(c);
        }
        let page = env.json(&p).await;
        seen.extend(items(&page).iter().cloned());
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => return seen,
        }
    }
}

#[tokio::test]
async fn connections_keep_the_flows_of_the_middle_burst() {
    let env = Env::new();
    let b = |p: &str| env.burst(p, 1);
    let session = by_ends(&env.json("/connections").await);
    let page = env.json(&b("/connections")).await;
    let ranged = by_ends(&page);
    // Every conversation of the burst, with the id of the session conversation.
    assert_eq!(total(&page), ranged.len() as u64);
    assert_eq!(ranged.len(), session.len(), "{ranged:?}");
    for (key, c) in &ranged {
        let s = &session[key];
        assert_eq!(c["id"], s["id"], "{key:?}");
        let (flows, session_flows) = (c["flows"].as_u64().unwrap(), s["flows"].as_u64().unwrap());
        if c["protocols"].as_array().unwrap().contains(&json!("tcp")) && flows == 2 {
            // The SMB session of the burst and the long connection, active in every burst.
            assert_eq!(session_flows, 4, "{key:?}");
        } else {
            assert_eq!(flows * 3, session_flows, "{key:?}: {c} / {s}");
        }
        assert!(c["first_ts_us"].as_i64() >= s["first_ts_us"].as_i64());
    }
    let long = ranged
        .values()
        .find(|c| c["flows"] == 2 && c["protocols"].as_array().unwrap().contains(&json!("tcp")))
        .expect("the conversation of the long connection");
    // Its flows: those active in the range, the long one included.
    let flows = env
        .json(&b(&format!(
            "/connections/{}/flows",
            long["id"].as_str().unwrap()
        )))
        .await;
    assert_eq!(items(&flows).len(), 2);
    assert_eq!(
        items(
            &env.json(&format!(
                "/connections/{}/flows",
                long["id"].as_str().unwrap()
            ))
            .await
        )
        .len(),
        4
    );

    // Statistics, top and module count follow the same conversations.
    let bytes: u64 = ranged
        .values()
        .map(|c| c["bytes_total"].as_u64().unwrap())
        .sum();
    let stats = env.json(&b("/connections/stats")).await;
    assert_eq!(stats["sources"]["total_bytes"].as_u64().unwrap(), bytes);
    assert_eq!(
        stats["destinations"]["total_bytes"].as_u64().unwrap(),
        bytes
    );
    let top = env.json(&b("/connections/top?n=50")).await;
    assert_eq!(top["conversations"].as_u64().unwrap(), total(&page));
    assert_eq!(top["total_bytes"].as_u64().unwrap(), bytes);
    let summary = env.json(&b("/summary")).await;
    assert_eq!(
        module(&summary, "connections"),
        (total(&page), json!("range"))
    );
    // Hosts active in the range: those of the summary figures.
    assert_eq!(
        module(&summary, "hosts"),
        (
            summary["range"]["host_count"].as_u64().unwrap(),
            json!("range")
        )
    );
}

#[tokio::test]
async fn between_two_bursts_only_the_long_connection_is_active() {
    let env = Env::new();
    let (_, last) = env.spread.bursts[1];
    let from = (last + 60_000_000_000).div_euclid(1000);
    let r = |p: &str| with_range(p, from, from + 60_000_000);
    let page = env.json(&r("/connections")).await;
    assert_eq!(total(&page), 1, "{page}");
    assert_eq!(items(&page)[0]["flows"], 1);
    let summary = env.json(&r("/summary")).await;
    assert_eq!(module(&summary, "connections").0, 1);
    assert_eq!(summary["range"]["flow_count"], 1);
    // The open ports seen before and after the gap overlap it, without client in the gap.
    let ports = env.json(&r("/open-ports")).await;
    for host in items(&ports) {
        assert_eq!(host["clients"], 0, "{host}");
        for p in host["ports"].as_array().unwrap() {
            assert_eq!(p["clients"], 0, "{p}");
        }
    }
    let graph = env.json(&r("/network/graph")).await;
    assert_eq!(graph["edges"].as_array().unwrap().len(), 1, "{graph}");
}

#[tokio::test]
async fn open_ports_servers_and_network_follow_the_range() {
    let env = Env::new();
    let b = |p: &str| env.burst(p, 1);
    let summary = env.json(&b("/summary")).await;

    let ports = env.json(&b("/open-ports")).await;
    let port_stats = env.json(&b("/open-ports/stats")).await;
    let open: usize = items(&ports)
        .iter()
        .map(|h| h["ports"].as_array().unwrap().len())
        .sum();
    assert_eq!(port_stats["open_ports"].as_u64().unwrap(), open as u64);
    assert_eq!(module(&summary, "openPorts"), (open as u64, json!("range")));
    assert_eq!(total(&ports), items(&ports).len() as u64);
    // Clients counted on the flows of the burst: a third of those of the session for a port
    // used once per burst.
    let session_ports = env.json("/open-ports").await;
    let clients = |page: &Value| -> BTreeMap<String, u64> {
        items(page)
            .iter()
            .flat_map(|h| {
                h["ports"].as_array().unwrap().iter().map(move |p| {
                    (
                        format!("{} {}", h["host"]["ip"], p["port"]),
                        p["clients"].as_u64().unwrap(),
                    )
                })
            })
            .collect()
    };
    let (ranged_clients, session_clients) = (clients(&ports), clients(&session_ports));
    for (key, n) in &ranged_clients {
        assert!(*n <= session_clients[key], "{key}");
    }
    assert!(ranged_clients.values().any(|n| *n > 0));

    let servers = env.json(&b("/servers")).await;
    assert_eq!(servers["analyzed"], true);
    let roles: u64 = servers["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["total"].as_u64().unwrap())
        .sum();
    assert_eq!(module(&summary, "servers"), (roles, json!("range")));
    assert!(roles > 0);
    // Responses of the burst only: a third of those of the session.
    let count = |s: &Value, role: &str, kind: &str| -> u64 {
        s["roles"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["role"] == role)
            .flat_map(|r| r["servers"].as_array().unwrap())
            .flat_map(|srv| srv["evidence"].as_array().unwrap())
            .filter(|e| e["kind"] == kind)
            .map(|e| e["count"].as_u64().unwrap())
            .sum()
    };
    let session_servers = env.json("/servers").await;
    let ranged_http = count(&servers, "http", "http_response");
    assert!(ranged_http > 0);
    assert_eq!(
        ranged_http * 3,
        count(&session_servers, "http", "http_response")
    );

    let graph = env.json(&b("/network/graph")).await;
    assert_eq!(
        module(&summary, "network"),
        (graph["hosts"].as_u64().unwrap(), json!("range"))
    );
    // A node: its traffic is that of its conversations in the range.
    let node = items(&env.json(&b("/connections")).await)[0]["src"]["ip"]
        .as_str()
        .unwrap()
        .to_owned();
    let detail = env.json(&b(&format!("/network/node/{node}"))).await;
    let sent: u64 = items(&env.json(&b("/connections")).await)
        .iter()
        .map(|c| {
            if c["src"]["ip"] == node.as_str() {
                c["bytes_fwd"].as_u64().unwrap()
            } else if c["dst"]["ip"] == node.as_str() {
                c["bytes_rev"].as_u64().unwrap()
            } else {
                0
            }
        })
        .sum();
    assert_eq!(detail["bytes_sent"].as_u64().unwrap(), sent);
    let session_detail = env.json(&format!("/network/node/{node}")).await;
    assert!(detail["bytes_sent"].as_u64() < session_detail["bytes_sent"].as_u64());
    // A host without traffic in the range is not found under it.
    let (_, last) = env.spread.bursts[2];
    let after = (last + 120_000_000_000).div_euclid(1000);
    let (status, _) = env
        .raw(&with_range(
            "/network/node/203.0.113.80",
            after,
            after + 1_000_000,
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn pages_of_the_aggregated_views_have_no_gap_nor_duplicate() {
    let env = Env::new();
    for route in [
        "/connections?sort=bytes",
        "/connections?sort=first_ts&order=asc",
        "/connections?sort=flows",
        "/open-ports?q=",
    ] {
        let full = env.json(&env.bursts(route, 0, 1)).await;
        let pages = all_pages(&env, &env.bursts(route, 0, 1)).await;
        let key = |v: &Value| {
            v.get("id")
                .cloned()
                .unwrap_or_else(|| v["host"]["ip"].clone())
        };
        let expected: Vec<Value> = items(&full).iter().map(key).collect();
        let seen: Vec<Value> = pages.iter().map(key).collect();
        assert_eq!(seen, expected, "{route}");
        assert!(seen.len() >= 2, "{route}");
    }
}

#[tokio::test]
async fn a_range_is_built_once_and_the_last_four_are_kept() {
    let env = Env::new();
    let b = |p: &str| env.burst(p, 1);
    for route in [
        "/connections",
        "/connections/stats",
        "/open-ports",
        "/servers",
        "/network/graph",
        "/summary",
    ] {
        env.json(&b(route)).await;
    }
    assert_eq!(env.state.ranges.builds(), 1);
    assert_eq!(range_files(&env).len(), 1);
    // Ranges of P5.2a views never build one.
    env.json(&env.burst("/dns/stats", 0)).await;
    assert_eq!(env.state.ranges.builds(), 1);

    // Five ranges: the oldest is evicted, a reused one is not rebuilt.
    let (first, _) = env.spread.bursts[0];
    let start = first.div_euclid(1000);
    for i in 0..4 {
        env.json(&with_range(
            "/connections",
            start,
            start + 1_000_000 * (i + 1),
        ))
        .await;
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(env.state.ranges.builds(), 5);
    assert_eq!(range_files(&env).len(), 4);
    env.json(&with_range("/servers", start, start + 4_000_000))
        .await;
    assert_eq!(env.state.ranges.builds(), 5);
    // The burst range was the least recently used: built again.
    env.json(&b("/connections")).await;
    assert_eq!(env.state.ranges.builds(), 6);
}

#[tokio::test]
async fn concurrent_requests_on_a_new_range_share_one_build() {
    let env = Env::new();
    let paths: Vec<String> = [
        "/connections",
        "/connections/stats",
        "/connections/top",
        "/open-ports",
        "/open-ports/stats",
        "/servers",
        "/network/graph",
        "/summary",
    ]
    .iter()
    .map(|p| env.bursts(p, 0, 1))
    .collect();
    let answers = futures_util::future::join_all(paths.iter().map(|p| env.raw(p))).await;
    for ((status, body), path) in answers.iter().zip(&paths) {
        assert_eq!(
            *status,
            StatusCode::OK,
            "{path}: {}",
            String::from_utf8_lossy(body)
        );
    }
    assert_eq!(env.state.ranges.builds(), 1);
}

#[tokio::test]
async fn a_writable_server_keeps_the_ranges_with_the_session() {
    let env = Env::writable();
    env.json(&env.burst("/connections", 1)).await;
    let files = range_files(&env);
    assert_eq!(files.len(), 1);
    // Nothing in a temporary directory.
    assert!(env.state.range_scratch.get().is_none());
    // Deleted with the session.
    let session_dir: &Path = files[0].parent().unwrap().parent().unwrap();
    assert!(session_dir.is_dir());
    assert_eq!(env.request("DELETE", "").await, StatusCode::NO_CONTENT);
    assert!(!session_dir.exists());
}

#[tokio::test]
async fn the_middle_burst_snapshot_of_the_aggregated_views() {
    let env = Env::new();
    let b = |p: &str| env.burst(p, 1);
    let conversations: Vec<Value> =
        items(&env.json(&b("/connections?sort=first_ts&order=asc")).await)
            .iter()
            .map(|c| {
                json!({
                    "src": c["src"]["ip"], "dst": c["dst"]["ip"], "flows": c["flows"],
                    "bytes": c["bytes_total"], "protocols": c["protocols"],
                })
            })
            .collect();
    let ports: Vec<Value> = items(&env.json(&b("/open-ports")).await)
        .iter()
        .map(|h| {
            json!({
                "host": h["host"]["ip"], "clients": h["clients"],
                "ports": h["ports"].as_array().unwrap().iter()
                    .map(|p| json!([p["port"], p["transport"], p["clients"]]))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    let servers: Vec<Value> = env.json(&b("/servers")).await["roles"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["total"].as_u64() > Some(0))
        .map(|r| {
            json!({
                "role": r["role"],
                "servers": r["servers"].as_array().unwrap().iter().map(|s| json!({
                    "ip": s["endpoint"]["ip"],
                    "evidence": s["evidence"].as_array().unwrap().iter()
                        .map(|e| json!([e["kind"], e["count"], e["clients"]]))
                        .collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let graph = env.json(&b("/network/graph")).await;
    insta::assert_json_snapshot!(
        "middle_burst_aggregates",
        json!({
            "conversations": conversations,
            "open_ports": ports,
            "servers": servers,
            "graph": { "hosts": graph["hosts"], "edges": graph["edges"].as_array().unwrap().len(),
                       "total_bytes": graph["total_bytes"] },
        })
    );
}
