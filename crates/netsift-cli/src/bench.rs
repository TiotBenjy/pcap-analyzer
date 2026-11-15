//! `netsift bench` (feature `bench`): measurements of `docs/PERFORMANCE.md`.
//!
//! - `bench ingest`: imports a capture like `netsift ingest`, sampling the CPU time of every
//!   thread of the process (`/proc/self/task/*/stat`) and reading the peak resident memory
//!   (`VmHWM` of `/proc/self/status`) at the end. Linux only.
//! - `bench queries`: calls every view endpoint of the API in-process (the axum router, no
//!   socket) on a session, with representative filters and sorts, and prints the median, p95
//!   and maximum time of each.
//!
//! `./x.sh bench` (`scripts/ct/bench.sh`) generates the data set and runs both.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use clap::{Args, Subcommand};
use netsift_engine::{CancelToken, IngestOptions, Phase, Progress, ingest};
use netsift_store::Catalog;
use tower::ServiceExt as _;

#[derive(Debug, Subcommand)]
pub enum BenchCommand {
    /// Import a capture and report throughput, CPU per thread and peak memory.
    Ingest(IngestArgs),
    /// Time the view endpoints of the API on a session.
    Queries(QueriesArgs),
    /// Time SQL statements on a session (read-only) and print their query plans.
    Sql(SqlArgs),
}

#[derive(Debug, Args)]
pub struct SqlArgs {
    /// Data directory holding the session.
    #[arg(long)]
    pub data_dir: PathBuf,
    /// Session id (default: the most recent session).
    #[arg(long)]
    pub session: Option<String>,
    /// Timed runs per statement.
    #[arg(long, default_value_t = 5)]
    pub repeat: usize,
    /// Pragmas run first (`mmap_size=268435456`...).
    #[arg(long = "pragma")]
    pub pragmas: Vec<String>,
    /// Statements (no parameters).
    pub sql: Vec<String>,
}

#[derive(Debug, Args)]
pub struct IngestArgs {
    /// Capture file or folder of chunks.
    pub input: PathBuf,
    /// Data directory (created if needed).
    #[arg(long)]
    pub out: PathBuf,
    /// Number of flow shards (default: cores - 2).
    #[arg(long)]
    pub shards: Option<usize>,
    #[arg(long, default_value = "bench")]
    pub name: String,
}

#[derive(Debug, Args)]
pub struct QueriesArgs {
    /// Data directory holding the session.
    #[arg(long)]
    pub data_dir: PathBuf,
    /// Session id (default: the most recent session).
    #[arg(long)]
    pub session: Option<String>,
    /// Timed calls per endpoint (after one untimed call).
    #[arg(long, default_value_t = 9)]
    pub repeat: usize,
    /// Only the cases whose name contains this text.
    #[arg(long)]
    pub only: Option<String>,
}

pub fn run(command: &BenchCommand, out: &mut dyn Write) -> Result<()> {
    match command {
        BenchCommand::Ingest(args) => bench_ingest(args, out),
        BenchCommand::Queries(args) => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            runtime.block_on(bench_queries(args, out))
        }
        BenchCommand::Sql(args) => bench_sql(args, out),
    }
}

fn session_dir(data_dir: &Path, session: Option<&str>) -> Result<PathBuf> {
    let sessions = data_dir.join("sessions");
    if let Some(id) = session {
        return Ok(sessions.join(id));
    }
    // ULIDs sort by creation time: the last one is the most recent.
    let mut ids: Vec<PathBuf> = std::fs::read_dir(&sessions)
        .with_context(|| format!("cannot list {}", sessions.display()))?
        .flatten()
        .map(|e| e.path())
        .collect();
    ids.sort();
    ids.pop().context("no session in the data directory")
}

fn bench_sql(args: &SqlArgs, out: &mut dyn Write) -> Result<()> {
    let dir = session_dir(&args.data_dir, args.session.as_deref())?;
    let session = netsift_store::Session::open(&dir, netsift_store::OpenMode::ReadOnly)?;
    let conn = session.conn();
    for pragma in &args.pragmas {
        conn.execute_batch(&format!("PRAGMA {pragma}"))?;
    }
    for sql in &args.sql {
        let mut times = Vec::new();
        let mut rows = 0usize;
        for _ in 0..=args.repeat.max(1) {
            let t = Instant::now();
            let mut stmt = conn.prepare(sql)?;
            let mut q = stmt.query([])?;
            rows = 0;
            while q.next()?.is_some() {
                rows += 1;
            }
            times.push(t.elapsed());
        }
        times.remove(0);
        times.sort();
        writeln!(
            out,
            "{} ms (median of {}, {rows} rows): {sql}",
            ms(percentile(&times, 0.5)),
            times.len()
        )?;
        let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
        let plan = stmt.query_map([], |r| r.get::<_, String>(3))?;
        for line in plan {
            writeln!(out, "    {}", line?)?;
        }
    }
    Ok(())
}

// --- ingest -------------------------------------------------------------------------------

/// CPU ticks per thread, keyed by thread id: (name, ticks).
type Ticks = BTreeMap<u32, (String, u64)>;

/// Linux `USER_HZ`: clock ticks per second of `/proc/<pid>/stat` (100 on every mainstream
/// architecture; `sysconf` would need `unsafe` code).
const TICKS_PER_SEC: u64 = 100;

fn sample_threads(into: &mut Ticks) {
    let Ok(entries) = std::fs::read_dir("/proc/self/task") else {
        return;
    };
    for entry in entries.flatten() {
        let Some(tid) = entry.file_name().to_str().and_then(|s| s.parse().ok()) else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // `pid (comm) state ...`: the name may hold spaces, the fields follow the last ')'.
        let (Some(open), Some(close)) = (stat.find('('), stat.rfind(')')) else {
            continue;
        };
        let name = stat.get(open + 1..close).unwrap_or_default().to_owned();
        let fields: Vec<&str> = stat
            .get(close + 2..)
            .unwrap_or_default()
            .split(' ')
            .collect();
        // utime and stime are fields 14 and 15 of the line, 12 and 13 after the state.
        let ticks = fields
            .get(11)
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
            + fields
                .get(12)
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
        let slot = into.entry(tid).or_insert((name, 0));
        slot.1 = slot.1.max(ticks);
    }
}

/// Thread group of a thread name: shards are summed together.
fn group(name: &str) -> String {
    let trimmed = name.trim_end_matches(|c: char| c.is_ascii_digit());
    if trimmed.ends_with('-') && trimmed.len() < name.len() {
        format!("{trimmed}*")
    } else {
        name.to_owned()
    }
}

/// `VmHWM` (peak resident set) of this process, in KiB.
pub fn peak_rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))?
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()
}

fn dir_size(path: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .map(|e| match e.metadata() {
            Ok(m) if m.is_dir() => dir_size(&e.path()),
            Ok(m) => m.len(),
            Err(_) => 0,
        })
        .sum()
}

#[allow(clippy::cast_precision_loss, clippy::too_many_lines)]
fn bench_ingest(args: &IngestArgs, out: &mut dyn Write) -> Result<()> {
    std::fs::create_dir_all(&args.out)
        .with_context(|| format!("cannot create {}", args.out.display()))?;
    let catalog = Catalog::open(&args.out)?;
    let options = IngestOptions {
        name: Some(args.name.clone()),
        shards: args.shards,
        ..IngestOptions::default()
    };

    let stop = Arc::new(AtomicBool::new(false));
    let sampler = {
        let stop = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("bench-sampler".into())
            .spawn(move || {
                let mut ticks = Ticks::new();
                while !stop.load(Ordering::Relaxed) {
                    sample_threads(&mut ticks);
                    std::thread::sleep(Duration::from_millis(50));
                }
                sample_threads(&mut ticks);
                ticks
            })?
    };
    let start = Instant::now();
    let mut reading_done: Option<Duration> = None;
    let report = ingest(
        &catalog,
        &args.input,
        &options,
        &CancelToken::new(),
        &mut |p: &Progress| {
            if p.phase != Phase::Reading && reading_done.is_none() {
                reading_done = Some(start.elapsed());
            }
        },
    );
    let total = start.elapsed();
    stop.store(true, Ordering::Relaxed);
    let ticks = sampler
        .join()
        .map_err(|_| anyhow::anyhow!("sampler panicked"))?;
    let report = report?;

    let mut cpu: BTreeMap<String, u64> = BTreeMap::new();
    for (name, t) in ticks.values() {
        *cpu.entry(group(name)).or_insert(0) += t;
    }
    let mb = report.bytes_read as f64 / 1e6;
    let secs = total.as_secs_f64();
    let reading = reading_done.unwrap_or(total);
    let session_dir = args.out.join("sessions").join(report.session.to_string());
    writeln!(out, "| Mesure | Valeur |")?;
    writeln!(out, "|---|---|")?;
    let rows = [
        ("session", report.session.to_string()),
        ("shards", report.shards.to_string()),
        (
            "fichiers lus",
            format!("{} ({mb:.0} Mo)", report.chunks_read),
        ),
        ("paquets", report.packets.to_string()),
        ("flux", report.flows.to_string()),
        ("hôtes", report.hosts.to_string()),
        ("durée totale", format!("{secs:.1} s")),
        ("débit (total)", format!("{:.1} Mo/s", mb / secs.max(1e-9))),
        (
            "lecture + analyse",
            format!(
                "{:.1} s ({:.1} Mo/s)",
                reading.as_secs_f64(),
                mb / reading.as_secs_f64().max(1e-9)
            ),
        ),
        (
            "fin d'import",
            format!("{:.1} s", (total.saturating_sub(reading)).as_secs_f64()),
        ),
        (
            "étapes de fin d'import",
            report
                .writer
                .finalize
                .timings
                .iter()
                .map(|(id, d)| format!("{id} {:.1} s", d.as_secs_f64()))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        (
            "pic mémoire (VmHWM)",
            peak_rss_kib().map_or_else(|| "?".to_owned(), |k| format!("{} Mio", k / 1024)),
        ),
        (
            "taille de la session",
            format!("{:.0} Mo", dir_size(&session_dir) as f64 / 1e6),
        ),
        ("lignes écrites", report.writer.total_rows().to_string()),
    ];
    for (k, v) in rows {
        writeln!(out, "| {k} | {v} |")?;
    }
    writeln!(out)?;
    writeln!(out, "| Thread | CPU (s) | Occupation |")?;
    writeln!(out, "|---|---|---|")?;
    for (name, t) in &cpu {
        let s = *t as f64 / TICKS_PER_SEC as f64;
        if s >= 0.05 {
            writeln!(
                out,
                "| {name} | {s:.1} | {:.0} % |",
                100.0 * s / secs.max(1e-9)
            )?;
        }
    }
    let rows_by_kind: Vec<String> = report
        .writer
        .rows
        .iter()
        .map(|(k, n)| format!("{k} {n}"))
        .collect();
    writeln!(out, "\nlignes par type : {}", rows_by_kind.join(", "))?;
    let mut by_time: Vec<(&str, Duration)> = report
        .writer
        .insert_time
        .iter()
        .map(|(k, d)| (*k, *d))
        .collect();
    by_time.sort_by_key(|(_, d)| std::cmp::Reverse(*d));
    let times: Vec<String> = by_time
        .iter()
        .map(|(k, d)| format!("{k} {:.1} s", d.as_secs_f64()))
        .collect();
    writeln!(
        out,
        "temps d'insertion par type : {} ; commits {:.1} s ({} transactions)",
        times.join(", "),
        report.writer.commit_time.as_secs_f64(),
        report.writer.batches
    )?;
    Ok(())
}

// --- queries ------------------------------------------------------------------------------

const TOKEN: &str = "bench-token-0123456789abcdef";

/// One timed endpoint: `path` is relative to `/api/v1/sessions/{id}`; `{name}` placeholders
/// are filled from [`PLACEHOLDERS`].
struct Case {
    view: &'static str,
    path: &'static str,
}

const fn case(view: &'static str, path: &'static str) -> Case {
    Case { view, path }
}

/// Placeholders: name, list endpoint, JSON pointer of the value in its response.
const PLACEHOLDERS: &[(&str, &str, &str)] = &[
    ("conn_cursor", "/connections?limit=50", "/next_cursor"),
    ("dns_cursor", "/dns/messages?limit=50", "/next_cursor"),
    ("http_cursor", "/http/transactions?limit=50", "/next_cursor"),
    ("tls_cursor", "/tls/sessions?limit=50", "/next_cursor"),
    ("http_tid", "/http/transactions?limit=1", "/items/0/id"),
    ("tls_flow", "/tls/sessions?limit=1", "/items/0/id"),
    (
        "cert",
        "/tls/certificates?limit=1",
        "/items/0/certificate/sha256",
    ),
    ("cred", "/credentials?limit=1", "/items/0/id"),
    ("host", "/connections?limit=1", "/items/0/src/ip"),
    ("server", "/connections?limit=1", "/items/0/dst/ip"),
];

#[rustfmt::skip]
const CASES: &[Case] = &[
    case("session", ""),
    case("session", "/anomalies?limit=100"),
    case("session", "/chunks?limit=100"),
    case("overview", "/summary"),
    case("overview", "/timeseries?points=500"),
    case("overview", "/timeseries?points=2000&metric=packets"),
    case("overview", "/timeseries?points=500&protocols=dns%2Ctls"),
    case("connections", "/connections?limit=50"),
    case("connections", "/connections?limit=50&cursor={conn_cursor}"),
    case("connections", "/connections?limit=50&sort=packets"),
    case("connections", "/connections?limit=50&sort=first_ts&order=asc"),
    case("connections", "/connections?limit=50&from={host}"),
    case("connections", "/connections?limit=50&to={server}"),
    case("connections", "/connections?limit=50&protocol=dns"),
    case("connections", "/connections?limit=50&category=public"),
    case("connections", "/connections/stats"),
    case("connections", "/connections/top?n=20"),
    case("connections", "/connections/top?n=20&exclude_dns=true"),
    case("open-ports", "/open-ports?limit=50"),
    case("open-ports", "/open-ports?limit=50&port=443"),
    case("open-ports", "/open-ports?limit=50&q=ssh"),
    case("open-ports", "/open-ports?limit=50&category=public"),
    case("open-ports", "/open-ports/stats"),
    case("open-ports", "/open-ports/stats?category=public"),
    case("dns", "/dns/stats"),
    case("dns", "/dns/servers"),
    case("dns", "/dns/pairs?limit=50"),
    case("dns", "/dns/messages?limit=50"),
    case("dns", "/dns/messages?limit=50&cursor={dns_cursor}"),
    case("dns", "/dns/messages?limit=50&q=cdn1"),
    case("dns", "/dns/messages?limit=50&q=ab"),
    case("dns", "/dns/messages?limit=50&errors=true"),
    case("dns", "/dns/messages?limit=50&protocols=nbns"),
    case("http", "/http/stats"),
    case("http", "/http/transactions?limit=50"),
    case("http", "/http/transactions?limit=50&cursor={http_cursor}"),
    case("http", "/http/transactions?limit=50&sort=size"),
    case("http", "/http/transactions?limit=50&status=404"),
    case("http", "/http/transactions?limit=50&method=POST"),
    case("http", "/http/transactions?limit=50&q=news"),
    case("http", "/http/transactions/{http_tid}"),
    case("http-headers", "/http/headers/stats"),
    case("http-headers", "/http/headers?limit=50"),
    case("http-headers", "/http/headers?limit=50&name=user-agent"),
    case("http-headers", "/http/headers?limit=50&q=curl"),
    case("tls", "/tls/stats"),
    case("tls", "/tls/sessions?limit=50"),
    case("tls", "/tls/sessions?limit=50&cursor={tls_cursor}"),
    case("tls", "/tls/sessions?limit=50&version=772"),
    case("tls", "/tls/sessions?limit=50&q=video"),
    case("tls", "/tls/sessions?limit=50&weak=true"),
    case("tls", "/tls/sessions?limit=50&cert_issues=true"),
    case("tls", "/tls/sessions/{tls_flow}"),
    case("tls", "/tls/certificates?limit=50"),
    case("tls", "/tls/certificates?limit=50&problems=true"),
    case("tls", "/tls/certificates/{cert}"),
    case("smb", "/smb/stats"),
    case("smb", "/smb/announces"),
    case("smb", "/smb/auth"),
    case("credentials", "/credentials?limit=50"),
    case("credentials", "/credentials?limit=50&protocol=ftp"),
    case("credentials", "/credentials/stats"),
    case("credentials", "/credentials/paths"),
    case("credentials", "/credentials/{cred}"),
    case("pictures", "/objects/stats"),
    case("pictures", "/objects?limit=50"),
    case("pictures", "/objects?limit=50&kind=all"),
    case("pictures", "/objects?limit=50&sort=size&order=desc"),
    case("pictures", "/objects?limit=50&q=img"),
    case("servers", "/servers"),
    case("servers", "/servers?role=dns"),
    case("network", "/network/graph"),
    case("network", "/network/graph?mode=countries"),
    case("network", "/network/graph?protocols=https"),
    case("network", "/network/graph?include_orphans=true"),
    case("network", "/network/node/{host}"),
];

struct Api {
    app: axum::Router,
    base: String,
}

impl Api {
    async fn get(&self, path: &str) -> Result<(StatusCode, Vec<u8>)> {
        let request = Request::get(format!("{}{path}", self.base))
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(Body::empty())?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        Ok((status, body.to_vec()))
    }
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let index = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted.get(index).copied().unwrap_or_default()
}

fn ms(d: Duration) -> String {
    format!("{:.1}", d.as_secs_f64() * 1e3)
}

#[allow(clippy::too_many_lines)] // Setup, placeholders, then one row per case.
async fn bench_queries(args: &QueriesArgs, out: &mut dyn Write) -> Result<()> {
    let config = netsift_api::ApiConfig {
        token: TOKEN.to_owned(),
        data_dir: args.data_dir.clone(),
        captures_roots: Vec::new(),
        read_only: false,
        cors_origins: Vec::new(),
        allow_any_path: false,
        max_imports: 1,
        geoip_fallback_path: None,
    };
    let mut api = Api {
        app: netsift_api::router(config),
        base: "/api/v1".to_owned(),
    };
    // First opening of the session (list, then details): migrations and pending end-of-import
    // steps of an older session run here (ADR-013, ADR-014).
    let t = Instant::now();
    let session = if let Some(s) = &args.session {
        s.clone()
    } else {
        let (status, body) = api.get("/sessions").await?;
        if !status.is_success() {
            bail!("GET /sessions: {status}");
        }
        let list: serde_json::Value = serde_json::from_slice(&body)?;
        list.pointer("/items/0/id")
            .and_then(serde_json::Value::as_str)
            .context("no session in the data directory")?
            .to_owned()
    };
    api.base = format!("/api/v1/sessions/{session}");
    let (status, _) = api.get("").await?;
    writeln!(
        out,
        "session {session}: first opening {} ms ({status})\n",
        ms(t.elapsed())
    )?;

    let mut values: BTreeMap<&str, String> = BTreeMap::new();
    for (name, list, pointer) in PLACEHOLDERS {
        let (_, body) = api.get(list).await?;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let value = match json.pointer(pointer) {
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            Some(serde_json::Value::Number(n)) => Some(n.to_string()),
            _ => None,
        };
        if let Some(v) = value {
            values.insert(name, encode(&v));
        }
    }

    writeln!(
        out,
        "| Vue | Requête | Médiane (ms) | p95 (ms) | Max (ms) | Statut | Taille |"
    )?;
    writeln!(out, "|---|---|---|---|---|---|---|")?;
    let mut slow = Vec::new();
    for c in CASES {
        if args
            .only
            .as_ref()
            .is_some_and(|o| !c.path.contains(o.as_str()) && c.view != o)
        {
            continue;
        }
        let Some(path) = fill(c.path, &values) else {
            writeln!(
                out,
                "| {} | `{}` | - | - | - | sans donnée | - |",
                c.view, c.path
            )?;
            continue;
        };
        let (status, body) = api.get(&path).await?;
        let mut times = Vec::with_capacity(args.repeat);
        for _ in 0..args.repeat.max(1) {
            let t = Instant::now();
            api.get(&path).await?;
            times.push(t.elapsed());
        }
        times.sort();
        let median = percentile(&times, 0.5);
        let p95 = percentile(&times, 0.95);
        let max = times.last().copied().unwrap_or_default();
        let flag = if median >= Duration::from_millis(300) {
            slow.push(c.path);
            " **lent**"
        } else {
            ""
        };
        writeln!(
            out,
            "| {} | `{}` | {}{flag} | {} | {} | {} | {} o |",
            c.view,
            c.path,
            ms(median),
            ms(p95),
            ms(max),
            status.as_u16(),
            body.len()
        )?;
    }
    writeln!(out, "\n{} requêtes au-dessus de 300 ms", slow.len())?;
    Ok(())
}

/// Percent-encodes a query value (cursors are base64-like, addresses may hold ':').
fn encode(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Replaces the `{name}` placeholders; `None` if one has no value.
fn fill(path: &str, values: &BTreeMap<&str, String>) -> Option<String> {
    let mut out = String::new();
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        let close = rest.get(open..)?.find('}')? + open;
        out.push_str(rest.get(..open)?);
        out.push_str(values.get(rest.get(open + 1..close)?)?);
        rest = rest.get(close + 1..)?;
    }
    out.push_str(rest);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_and_groups() {
        let mut values = BTreeMap::new();
        values.insert("a", "1".to_owned());
        assert_eq!(fill("/x/{a}?b={a}", &values).as_deref(), Some("/x/1?b=1"));
        assert_eq!(fill("/x/{missing}", &values), None);
        assert_eq!(group("netsift-shard-12"), "netsift-shard-*");
        assert_eq!(group("netsift-reader"), "netsift-reader");
        assert_eq!(encode("a b:c"), "a%20b%3Ac");
        assert!(peak_rss_kib().is_some());
        let mut ticks = Ticks::new();
        sample_threads(&mut ticks);
        assert!(!ticks.is_empty());
    }

    #[test]
    fn every_placeholder_is_declared() {
        let names: Vec<&str> = PLACEHOLDERS.iter().map(|p| p.0).collect();
        for c in CASES {
            let mut rest = c.path;
            while let Some(open) = rest.find('{') {
                let close = rest[open..].find('}').unwrap() + open;
                assert!(names.contains(&&rest[open + 1..close]), "{}", c.path);
                rest = &rest[close + 1..];
            }
        }
    }
}
