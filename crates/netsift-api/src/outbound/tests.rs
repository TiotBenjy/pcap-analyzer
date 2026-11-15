//! Outbound client against a local plain-HTTP server (`Policy::local_http_for_tests`), never
//! the real network. Production policies are only checked without sending anything.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use tokio::sync::mpsc;

use super::*;

#[derive(Clone)]
enum Reply {
    Body(Vec<u8>),
    Status(StatusCode),
    Redirect(String),
    /// Body streamed from a channel, without `Content-Length`.
    Stream(Arc<Mutex<Option<mpsc::Receiver<Bytes>>>>),
    /// Headers sent after this delay.
    Slow(Duration),
}

#[derive(Default)]
struct Upstream {
    replies: Mutex<HashMap<String, Reply>>,
    /// Method, path and headers of every request received.
    hits: Mutex<Vec<(String, String, HeaderMap)>>,
}

impl Upstream {
    fn reply(&self, name: &str, reply: Reply) {
        self.replies.lock().unwrap().insert(name.to_owned(), reply);
    }

    fn hit_names(&self) -> Vec<String> {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .map(|h| h.1.clone())
            .collect()
    }
}

async fn upstream_file(
    method: axum::http::Method,
    UrlPath(name): UrlPath<String>,
    headers: HeaderMap,
    State(up): State<Arc<Upstream>>,
) -> Response {
    up.hits
        .lock()
        .unwrap()
        .push((method.to_string(), name.clone(), headers));
    let reply = up.replies.lock().unwrap().get(&name).cloned();
    match reply {
        None => StatusCode::NOT_FOUND.into_response(),
        Some(Reply::Body(bytes)) => bytes.into_response(),
        Some(Reply::Status(code)) => code.into_response(),
        Some(Reply::Redirect(to)) => (StatusCode::FOUND, [(header::LOCATION, to)]).into_response(),
        Some(Reply::Stream(rx)) => {
            let rx = rx.lock().unwrap().take().unwrap();
            let stream = futures_util::stream::unfold(rx, |mut rx| async move {
                rx.recv().await.map(|b| (Ok::<_, Infallible>(b), rx))
            });
            Body::from_stream(stream).into_response()
        }
        Some(Reply::Slow(delay)) => {
            tokio::time::sleep(delay).await;
            "late".into_response()
        }
    }
}

struct Env {
    up: Arc<Upstream>,
    addr: SocketAddr,
    tmp: tempfile::TempDir,
}

impl Env {
    async fn new() -> Self {
        let up = Arc::new(Upstream::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/f/{name}", axum::routing::get(upstream_file))
            .with_state(Arc::clone(&up));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            up,
            addr,
            tmp: tempfile::TempDir::new().unwrap(),
        }
    }

    fn url(&self, name: &str) -> String {
        format!("http://{}/f/{name}", self.addr)
    }

    /// Same server, reached through another host name.
    fn other_host_url(&self, name: &str) -> String {
        format!("http://localhost:{}/f/{name}", self.addr.port())
    }

    fn stream(&self, name: &str) -> mpsc::Sender<Bytes> {
        let (tx, rx) = mpsc::channel(4);
        self.up
            .reply(name, Reply::Stream(Arc::new(Mutex::new(Some(rx)))));
        tx
    }

    fn files(&self) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(self.tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

/// Plain HTTP to the local test server.
fn local_policy() -> Policy {
    Policy::new(&["127.0.0.1"]).local_http_for_tests()
}

fn local_client() -> Outbound {
    Outbound::new(local_policy()).unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(&<[u8; 32]>::from(Sha256::digest(bytes)))
}

// ---------------------------------------------------------------------------------------------
// Requests

#[tokio::test]
async fn head_reports_status_and_size_with_a_generic_user_agent() {
    let env = Env::new().await;
    env.up.reply("db.gz", Reply::Body(vec![7; 1_234]));
    let head = local_client().head(&env.url("db.gz")).await.unwrap();
    assert_eq!(head.status, StatusCode::OK);
    assert_eq!(head.content_length, Some(1_234));
    let missing = local_client().head(&env.url("none")).await.unwrap();
    assert_eq!(missing.status, StatusCode::NOT_FOUND);

    let hits = env.up.hits.lock().unwrap();
    let (method, _, headers) = &hits[0];
    assert_eq!(method, "HEAD");
    assert_eq!(headers[header::USER_AGENT], USER_AGENT);
    assert!(USER_AGENT.starts_with("NetSift/"));
    for h in [header::COOKIE, header::AUTHORIZATION, header::REFERER] {
        assert!(!headers.contains_key(&h), "{h} sent");
    }
}

#[tokio::test]
async fn get_json_is_bounded_and_never_echoes_the_body() {
    let env = Env::new().await;
    let client = local_client();
    env.up
        .reply("latest", Reply::Body(br#"{"tag_name":"v1.2.3"}"#.to_vec()));
    let json: Value = client
        .get_json(&env.url("latest"), "application/vnd.github+json", 1_000)
        .await
        .unwrap();
    assert_eq!(json["tag_name"], "v1.2.3");
    // Cloned: a guard kept alive would block the server running on this same thread.
    let accept = env.up.hits.lock().unwrap()[0].2[header::ACCEPT].clone();
    assert_eq!(accept, "application/vnd.github+json");

    // Too large, announced.
    let err = client
        .get_json::<Value>(&env.url("latest"), "application/json", 10)
        .await
        .unwrap_err();
    assert!(matches!(err, OutboundError::TooLarge), "{err}");

    // Not JSON: the error gives a position, never the contents.
    env.up.reply(
        "latest",
        Reply::Body(b"<html>secret-marker</html>".to_vec()),
    );
    let err = client
        .get_json::<Value>(&env.url("latest"), "application/json", 1_000)
        .await
        .unwrap_err();
    assert!(matches!(err, OutboundError::Json { .. }), "{err}");
    assert!(!err.to_string().contains("secret-marker"));
    assert!(!format!("{err:?}").contains("secret-marker"));

    // JSON of another shape: same.
    env.up.reply(
        "latest",
        Reply::Body(br#"{"tag_name":"secret-marker"}"#.to_vec()),
    );
    let err = client
        .get_json::<HashMap<String, u32>>(&env.url("latest"), "application/json", 1_000)
        .await
        .unwrap_err();
    assert!(matches!(err, OutboundError::Json { .. }), "{err}");
    assert!(!format!("{err} {err:?}").contains("secret-marker"));

    // Status other than 2xx.
    env.up
        .reply("latest", Reply::Status(StatusCode::INTERNAL_SERVER_ERROR));
    let err = client
        .get_json::<Value>(&env.url("latest"), "application/json", 1_000)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        OutboundError::Status(StatusCode::INTERNAL_SERVER_ERROR)
    ));
}

#[tokio::test]
async fn get_bytes_stops_as_soon_as_the_bound_is_crossed() {
    let env = Env::new().await;
    let client = local_client();
    let tx = env.stream("big");
    tx.send(Bytes::from(vec![0; 800])).await.unwrap();
    tx.send(Bytes::from(vec![0; 800])).await.unwrap();
    // The sender stays open: the client must not wait for the end of the body.
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        client.get_bytes(&env.url("big"), 1_000, |_, _| {}),
    )
    .await
    .unwrap();
    assert!(matches!(result, Err(OutboundError::TooLarge)));
    drop(tx);

    // Progress: once the status is known, then per part.
    env.up.reply("small", Reply::Body(vec![1; 300]));
    let mut seen = Vec::new();
    let body = client
        .get_bytes(&env.url("small"), 300, |r, t| seen.push((r, t)))
        .await
        .unwrap();
    assert_eq!(body.len(), 300);
    assert_eq!(seen.first(), Some(&(0, Some(300))));
    assert_eq!(seen.last(), Some(&(300, Some(300))));
}

// ---------------------------------------------------------------------------------------------
// Allow list, schemes and redirections

#[tokio::test]
async fn refused_urls_are_never_requested() {
    let env = Env::new().await;
    let client = local_client();
    env.up.reply("x", Reply::Body(b"{}".to_vec()));

    let err = client.head(&env.other_host_url("x")).await.unwrap_err();
    assert!(
        matches!(&err, OutboundError::HostNotAllowed(h) if h == "localhost"),
        "{err}"
    );
    let with_credentials = env.url("x").replace("http://", "http://user:pw@");
    for url in [
        with_credentials.as_str(),
        "not a url",
        "ftp://127.0.0.1/f/x",
    ] {
        let err = client.head(url).await.unwrap_err();
        assert!(matches!(err, OutboundError::UrlRefused), "{url}: {err}");
    }
    assert!(env.up.hits.lock().unwrap().is_empty());
}

#[tokio::test]
async fn production_policies_accept_only_https_on_the_default_port() {
    let policy = Policy::new(&["Download.Example.org"]);
    let check = |url: &str| policy.check(&Url::parse(url).unwrap());
    assert!(check("https://download.example.org/free/x.gz").is_ok());
    assert!(check("https://DOWNLOAD.example.org:443/x").is_ok());
    assert!(matches!(
        check("http://download.example.org/x"),
        Err(Refusal::Url)
    ));
    assert!(matches!(
        check("https://download.example.org:8443/x"),
        Err(Refusal::Url)
    ));
    assert!(matches!(
        check("https://u@download.example.org/x"),
        Err(Refusal::Url)
    ));
    assert!(matches!(
        check("https://example.org/x"),
        Err(Refusal::Host(h)) if h == "example.org"
    ));
    assert!(matches!(
        check("https://download.example.org.evil.test/x"),
        Err(Refusal::Host(_))
    ));
    // The production client builds without any network access.
    Outbound::new(policy).unwrap();
}

#[tokio::test]
async fn redirections_are_checked_against_the_allow_list_and_bounded() {
    let env = Env::new().await;
    let client = local_client();

    // Allowed host: followed.
    env.up.reply("start", Reply::Redirect(env.url("mirror")));
    env.up.reply("mirror", Reply::Body(b"ok".to_vec()));
    let body = client
        .get_bytes(&env.url("start"), 100, |_, _| {})
        .await
        .unwrap();
    assert_eq!(body, b"ok");

    // Another host: refused, never requested.
    env.up
        .reply("start", Reply::Redirect(env.other_host_url("other")));
    env.up.reply("other", Reply::Body(b"no".to_vec()));
    let err = client
        .get_bytes(&env.url("start"), 100, |_, _| {})
        .await
        .unwrap_err();
    assert!(matches!(err, OutboundError::HostNotAllowed(_)), "{err}");
    assert!(!env.up.hit_names().contains(&"other".to_owned()));

    // Downgrade to another scheme: refused.
    env.up.reply(
        "start",
        Reply::Redirect(format!("ftp://127.0.0.1:{}/f/mirror", env.addr.port())),
    );
    let err = client.head(&env.url("start")).await.unwrap_err();
    assert!(
        matches!(err, OutboundError::UrlRefused | OutboundError::Network(_)),
        "{err}"
    );

    // Loop: bounded.
    env.up.hits.lock().unwrap().clear();
    env.up.reply("start", Reply::Redirect(env.url("start")));
    let err = client.head(&env.url("start")).await.unwrap_err();
    assert!(matches!(err, OutboundError::TooManyRedirects), "{err}");
    let followed = env.up.hit_names().iter().filter(|n| *n == "start").count();
    assert_eq!(followed, 1 + MAX_REDIRECTS, "first request + redirections");

    // A lower bound from the caller.
    let strict = Outbound::new(Policy {
        max_redirects: 0,
        ..local_policy()
    })
    .unwrap();
    env.up.reply("start", Reply::Redirect(env.url("mirror")));
    let err = strict.head(&env.url("start")).await.unwrap_err();
    assert!(matches!(err, OutboundError::TooManyRedirects), "{err}");
}

// ---------------------------------------------------------------------------------------------
// Timeouts

#[tokio::test]
async fn slow_servers_time_out() {
    let env = Env::new().await;
    let quick = Outbound::new(Policy {
        read_timeout: Duration::from_millis(200),
        ..local_policy()
    })
    .unwrap();

    // Headers late.
    env.up.reply("slow", Reply::Slow(Duration::from_secs(5)));
    let err = quick.head(&env.url("slow")).await.unwrap_err();
    assert!(matches!(err, OutboundError::Timeout), "{err}");

    // Body stalled after a first part.
    let tx = env.stream("stall");
    tx.send(Bytes::from_static(b"part")).await.unwrap();
    let err = quick
        .get_bytes(&env.url("stall"), 1_000, |_, _| {})
        .await
        .unwrap_err();
    assert!(matches!(err, OutboundError::Timeout), "{err}");

    // Total duration.
    let bounded = Outbound::new(Policy {
        total_timeout: Duration::from_millis(300),
        ..local_policy()
    })
    .unwrap();
    let err = bounded.head(&env.url("slow")).await.unwrap_err();
    assert!(matches!(err, OutboundError::Timeout), "{err}");
    drop(tx);
}

// ---------------------------------------------------------------------------------------------
// Downloads to a file

#[tokio::test]
async fn downloads_are_hashed_and_renamed_once_complete() {
    let env = Env::new().await;
    let body: Vec<u8> = (0..50_000_u32)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    env.up.reply("asset", Reply::Body(body.clone()));
    let dest = env.tmp.path().join("NetSift.AppImage");
    std::fs::write(&dest, b"previous").unwrap();

    let expected = sha256_hex(&body).to_ascii_uppercase();
    let mut last = (0, None);
    let done = local_client()
        .download_to(
            &env.url("asset"),
            &dest,
            100_000,
            Some(&expected),
            |r, t| {
                last = (r, t);
            },
        )
        .await
        .unwrap();
    assert_eq!(done.bytes, 50_000);
    assert_eq!(done.sha256, sha256_hex(&body));
    assert_eq!(last, (50_000, Some(50_000)));
    assert_eq!(std::fs::read(&dest).unwrap(), body);
    assert_eq!(env.files(), ["NetSift.AppImage"]);

    // Without an expected checksum: the computed one is returned.
    let other = env.tmp.path().join("copy.bin");
    let done = local_client()
        .download_to(&env.url("asset"), &other, 100_000, None, |_, _| {})
        .await
        .unwrap();
    assert_eq!(done.sha256, sha256_hex(&body));
}

#[tokio::test]
async fn failed_downloads_leave_no_part_file_and_keep_the_destination() {
    let env = Env::new().await;
    let client = local_client();
    let dest = env.tmp.path().join("asset.bin");
    std::fs::write(&dest, b"previous").unwrap();
    env.up.reply("asset", Reply::Body(vec![9; 2_000]));

    // Checksum mismatch.
    let wrong = sha256_hex(b"something else");
    let err = client
        .download_to(&env.url("asset"), &dest, 10_000, Some(&wrong), |_, _| {})
        .await
        .unwrap_err();
    assert!(matches!(err, OutboundError::ChecksumMismatch), "{err}");

    // Invalid expected checksum: nothing requested.
    let hits = env.up.hits.lock().unwrap().len();
    let err = client
        .download_to(&env.url("asset"), &dest, 10_000, Some("abc"), |_, _| {})
        .await
        .unwrap_err();
    assert!(matches!(err, OutboundError::InvalidChecksum), "{err}");
    assert_eq!(env.up.hits.lock().unwrap().len(), hits);

    // Announced size above the bound, status error, refused host.
    let err = client
        .download_to(&env.url("asset"), &dest, 1_000, None, |_, _| {})
        .await
        .unwrap_err();
    assert!(matches!(err, OutboundError::TooLarge), "{err}");
    let err = client
        .download_to(&env.url("missing"), &dest, 1_000, None, |_, _| {})
        .await
        .unwrap_err();
    assert!(matches!(err, OutboundError::Status(StatusCode::NOT_FOUND)));
    let err = client
        .download_to(&env.other_host_url("asset"), &dest, 1_000, None, |_, _| {})
        .await
        .unwrap_err();
    assert!(matches!(err, OutboundError::HostNotAllowed(_)));

    // Streamed body crossing the bound after part of it was written.
    let tx = env.stream("stream");
    tx.send(Bytes::from(vec![0; 800])).await.unwrap();
    tx.send(Bytes::from(vec![0; 800])).await.unwrap();
    let err = client
        .download_to(&env.url("stream"), &dest, 1_000, None, |_, _| {})
        .await
        .unwrap_err();
    assert!(matches!(err, OutboundError::TooLarge), "{err}");
    drop(tx);

    // Destination without a file name.
    let err = client
        .download_to(&env.url("asset"), Path::new("/"), 10_000, None, |_, _| {})
        .await
        .unwrap_err();
    assert!(matches!(err, OutboundError::Io(_)), "{err}");

    assert_eq!(std::fs::read(&dest).unwrap(), b"previous");
    assert_eq!(env.files(), ["asset.bin"]);
}

#[tokio::test]
async fn a_cancelled_download_removes_its_part_file() {
    let env = Env::new().await;
    let tx = env.stream("stream");
    tx.send(Bytes::from(vec![1; 100])).await.unwrap();
    let dest = env.tmp.path().join("asset.bin");
    let part = env.tmp.path().join("asset.bin.part");
    let client = local_client();
    let url = env.url("stream");
    let target = dest.clone();
    let task = tokio::spawn(async move {
        client
            .download_to(&url, &target, 10_000, None, |_, _| {})
            .await
    });
    // Wait for the first part to be on disk, then drop the download.
    tokio::time::timeout(Duration::from_secs(10), async {
        while std::fs::metadata(&part).map_or(0, |m| m.len()) < 100 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(!part.exists());
    assert!(!dest.exists());
    drop(tx);
}

#[test]
fn sha256_digests_parse_in_either_case() {
    let lower = sha256_hex(b"abc");
    assert_eq!(
        lower,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let bytes = parse_sha256(&lower).unwrap();
    assert_eq!(to_hex(&bytes), lower);
    assert_eq!(parse_sha256(&lower.to_ascii_uppercase()), Some(bytes));
    assert_eq!(parse_sha256(&lower[1..]), None);
    assert_eq!(parse_sha256(&format!("{}g", &lower[1..])), None);
    assert_eq!(parse_sha256(&format!("{lower}00")), None);
    assert_eq!(parse_sha256(""), None);
}
