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
    // Trailing dot: another name for the resolver, refused.
    assert!(matches!(
        check("https://download.example.org./x"),
        Err(Refusal::Host(h)) if h == "download.example.org."
    ));
    // IP literals, even when listed.
    let ips = Policy::new(&["93.184.216.34", "[2001:db8::1]", "2001:db8::1"]);
    for url in [
        "https://93.184.216.34/x",
        "https://[2001:db8::1]/x",
        "https://0x5db8d822/x",
    ] {
        assert!(
            matches!(ips.check(&Url::parse(url).unwrap()), Err(Refusal::Url)),
            "{url}"
        );
    }
    // The production client builds without any network access.
    Outbound::new(policy.with_connect_timeout(Duration::from_secs(5))).unwrap();
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
}

// ---------------------------------------------------------------------------------------------
// Timeouts

#[tokio::test]
async fn slow_servers_time_out() {
    let env = Env::new().await;
    let quick =
        Outbound::new(local_policy().with_read_timeout(Duration::from_millis(200))).unwrap();

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
    let bounded =
        Outbound::new(local_policy().with_total_timeout(Duration::from_millis(300))).unwrap();
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
        while part_files(env.tmp.path())
            .iter()
            .all(|p| std::fs::metadata(p).map_or(0, |m| m.len()) < 100)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(part_files(env.tmp.path()), Vec::<PathBuf>::new());
    assert!(!dest.exists());
    drop(tx);
}

/// Temporary download files in `dir`.
fn part_files(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "part"))
        .collect()
}

#[tokio::test]
async fn temporary_files_are_unique_and_never_reuse_an_existing_one() {
    let env = Env::new().await;
    env.up.reply("asset", Reply::Body(b"new".to_vec()));
    let dest = env.tmp.path().join("asset.bin");
    // Files a previous run or another program left there, including a link.
    let stale = env.tmp.path().join("asset.bin.part");
    std::fs::write(&stale, b"stale").unwrap();
    let victim = env.tmp.path().join("victim.txt");
    std::fs::write(&victim, b"victim").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&victim, env.tmp.path().join("link.part")).unwrap();

    // Refused URL, then 404: nothing touched.
    let client = local_client();
    let err = client
        .download_to(&env.other_host_url("asset"), &dest, 100, None, |_, _| {})
        .await
        .unwrap_err();
    assert!(matches!(err, OutboundError::HostNotAllowed(_)));
    let err = client
        .download_to(&env.url("missing"), &dest, 100, None, |_, _| {})
        .await
        .unwrap_err();
    assert!(matches!(err, OutboundError::Status(StatusCode::NOT_FOUND)));
    assert_eq!(std::fs::read(&stale).unwrap(), b"stale");

    // A successful download uses a name of its own.
    client
        .download_to(&env.url("asset"), &dest, 100, None, |_, _| {})
        .await
        .unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"new");
    assert_eq!(std::fs::read(&stale).unwrap(), b"stale");
    assert_eq!(std::fs::read(&victim).unwrap(), b"victim");
    let a = part_path(&dest).unwrap();
    let b = part_path(&dest).unwrap();
    assert_ne!(a, b);
    let name = a.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        name.starts_with(&format!("asset.bin.{}-", std::process::id())),
        "{name}"
    );

    // Exclusive creation: an existing path (file or link) is refused, and left alone.
    assert!(PartFile::create(stale.clone()).await.is_err());
    assert_eq!(std::fs::read(&stale).unwrap(), b"stale");
    #[cfg(unix)]
    {
        assert!(
            PartFile::create(env.tmp.path().join("link.part"))
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"victim");
    }
}

/// Index `n` of a temporary name `<name>.<pid>-<n>.part`.
fn part_index(path: &Path) -> u64 {
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    let (_, tail) = name.rsplit_once('-').unwrap();
    tail.strip_suffix(".part").unwrap().parse().unwrap()
}

/// `<dest>.<pid>-<n>.part`, as left by a crashed run of this PID.
fn stale_part(dest: &Path, n: u64) -> PathBuf {
    let mut name = dest.file_name().unwrap().to_os_string();
    name.push(format!(".{}-{n}.part", std::process::id()));
    dest.with_file_name(name)
}

// The counter of temporary names is per process: nextest runs each test in its own process, so
// the next names are known here.
#[tokio::test]
async fn temporary_names_left_by_a_crashed_run_with_the_same_pid_are_skipped() {
    let env = Env::new().await;
    env.up.reply("asset", Reply::Body(b"new".to_vec()));
    let dest = env.tmp.path().join("asset.bin");
    let client = local_client();

    // The next three names are taken (PID reuse after a crash): the fourth one is used.
    let next = part_index(&part_path(&dest).unwrap()) + 1;
    let stale: Vec<_> = (next..next + 3).map(|n| stale_part(&dest, n)).collect();
    for path in &stale {
        std::fs::write(path, b"stale").unwrap();
    }
    client
        .download_to(&env.url("asset"), &dest, 100, None, |_, _| {})
        .await
        .unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"new");
    assert_eq!(
        part_index(&part_path(&dest).unwrap()),
        next + 4,
        "three names skipped"
    );
    for path in &stale {
        assert_eq!(std::fs::read(path).unwrap(), b"stale");
    }

    // Bounded: past PART_ATTEMPTS taken names in a row, the download fails, touching nothing.
    std::fs::remove_file(&dest).unwrap();
    let next = part_index(&part_path(&dest).unwrap()) + 1;
    let n = u64::try_from(PART_ATTEMPTS).unwrap();
    let taken: Vec<_> = (next..next + n).map(|n| stale_part(&dest, n)).collect();
    for path in &taken {
        std::fs::write(path, b"stale").unwrap();
    }
    let err = client
        .download_to(&env.url("asset"), &dest, 100, None, |_, _| {})
        .await
        .unwrap_err();
    assert!(
        matches!(&err, OutboundError::Io(e) if e.kind() == std::io::ErrorKind::AlreadyExists),
        "{err}"
    );
    assert!(!dest.exists());
    for path in stale.iter().chain(&taken) {
        assert_eq!(std::fs::read(path).unwrap(), b"stale");
    }
    assert_eq!(part_files(env.tmp.path()).len(), stale.len() + taken.len());
}

#[tokio::test]
async fn concurrent_downloads_to_one_target_never_mix() {
    let env = Env::new().await;
    let dest = env.tmp.path().join("NetSift.AppImage");
    let (a, b) = (vec![b'a'; 3_000], vec![b'b'; 3_000]);
    let (sum_a, sum_b) = (sha256_hex(&a), sha256_hex(&b));
    let tx_a = env.stream("a");
    let tx_b = env.stream("b");
    let start = |name: &str, sum: String| {
        let (client, url, target) = (local_client(), env.url(name), dest.clone());
        tokio::spawn(async move {
            client
                .download_to(&url, &target, 10_000, Some(&sum), |_, _| {})
                .await
        })
    };
    let task_a = start("a", sum_a.clone());
    let task_b = start("b", sum_b.clone());
    // Interleaved parts: both downloads are writing at the same time.
    for i in 0..3 {
        let range = i * 1_000..(i + 1) * 1_000;
        tx_a.send(Bytes::copy_from_slice(&a[range.clone()]))
            .await
            .unwrap();
        tx_b.send(Bytes::copy_from_slice(&b[range])).await.unwrap();
        tokio::task::yield_now().await;
    }
    drop((tx_a, tx_b));
    let done_a = task_a.await.unwrap().unwrap();
    let done_b = task_b.await.unwrap().unwrap();
    assert_eq!(done_a.sha256, sum_a);
    assert_eq!(done_b.sha256, sum_b);
    let result = std::fs::read(&dest).unwrap();
    assert!(result == a || result == b, "mixed file");
    assert_eq!(part_files(env.tmp.path()), Vec::<PathBuf>::new());
}

#[tokio::test]
async fn network_errors_never_carry_the_url() {
    // A port nothing listens on (bound, then closed).
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let signed = format!("http://127.0.0.1:{closed}/asset?sig=secret-marker&jwt=secret-marker");
    let client = local_client();
    let err = client.get_bytes(&signed, 100, |_, _| {}).await.unwrap_err();
    assert!(matches!(err, OutboundError::Network(_)), "{err}");
    assert!(!format!("{err} {err:?}").contains("secret-marker"));

    // Same after a redirection to a signed storage URL.
    let env = Env::new().await;
    env.up.reply("asset", Reply::Redirect(signed));
    let dest = env.tmp.path().join("asset.bin");
    let err = client
        .download_to(&env.url("asset"), &dest, 100, None, |_, _| {})
        .await
        .unwrap_err();
    assert!(matches!(err, OutboundError::Network(_)), "{err}");
    assert!(!format!("{err} {err:?}").contains("secret-marker"));
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

#[test]
fn failures_map_to_feature_problems_without_details() {
    let problem = OutboundError::Timeout.into_problem("update-check-failed", "Update check failed");
    assert_eq!(problem.status(), 504);
    let (kind, detail) = problem.problem();
    assert_eq!(kind, "urn:netsift:problem:update-check-failed");
    assert_eq!(detail, None);
    assert_eq!(problem.title(), "Update check failed");
    let problem = OutboundError::Json { line: 1, column: 2 }.into_problem("k", "t");
    assert_eq!(problem.status(), 502);
    let problem = OutboundError::Io(std::io::Error::other("disk")).into_problem("k", "t");
    assert_eq!(problem.status(), 500);
    assert_eq!(
        OutboundError::ChecksumMismatch
            .into_problem("k", "t")
            .status(),
        502
    );
}
