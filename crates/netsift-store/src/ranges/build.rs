//! Build of a range database (see the parent module): the tables of the aggregated views derived
//! from the records of one time range, by the code of the end-of-import steps.
//!
//! The build connection opens the new file as `main` and attaches the session read-only: the
//! copied tables (same DDL as the session, read from its `sqlite_master`) shadow the session ones,
//! so the steps `connections`, `ports` and `network` run unchanged on the rows of the range.
//!
//! Rules of the range (spec « Sémantique par route ») :
//! - flows **active** in the range (span overlapping it, two branches as `range::count_active_flows`)
//!   give the conversations (grouped per client and server, each flow counted in full, the id of the
//!   session conversation kept), the traffic per host, and the flows and clients of the open ports
//!   (`fold.rs`);
//! - hosts and open ports whose span overlaps the range are copied as they are (session values);
//! - server evidence: every branch of `server_evidence_source` filtered by its timestamp (point
//!   records) or by overlap (folded rows), then the roles and ranks of the step `servers`.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use rusqlite::{Connection, ErrorCode, OpenFlags};

use super::{ATTACHED, POLL, attach};
use crate::error::{Result, StoreError};
use crate::range::TimeRange;
use crate::session::PAGE_SIZE;

/// Tables copied from the session schema, in creation order. `meta` is copied too: the readers
/// check the end-of-import steps there.
const COPIED: &[&str] = &[
    "meta",
    "hosts",
    "conversations",
    "host_traffic",
    "conversation_categories",
    "open_ports",
    "open_port_hosts",
    "server_evidence",
    "server_roles",
    "server_ranks",
    "network_hosts",
    "network_ends",
    "network_edges",
    "network_country_edges",
    "network_expand",
    "network_host_counts",
    "network_protocols",
];

/// Tables filled by a plain copy or a grouping: indexed once filled (faster than row by row).
const COPIED_ROWS: &[&str] = &["hosts", "conversations", "open_ports"];

/// Steps whose tables the range database holds: marked done in its copy of `meta`.
const STEPS: &[&str] = &["connections", "ports", "servers", "network"];

/// Tables of the range database only.
const OWN_TABLES: &str = "
CREATE TABLE range_meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) WITHOUT ROWID;
-- Flows and distinct clients of each open port, over the active flows (Open Ports, Servers).
CREATE TABLE open_port_clients (
    ip        TEXT NOT NULL,
    transport INTEGER NOT NULL,
    port      INTEGER NOT NULL,
    flows     INTEGER NOT NULL,
    clients   INTEGER NOT NULL,
    PRIMARY KEY (ip, transport, port)
) WITHOUT ROWID;
-- Distinct clients of all the open ports of a host.
CREATE TABLE open_port_host_clients (
    ip      TEXT PRIMARY KEY NOT NULL,
    clients INTEGER NOT NULL
) WITHOUT ROWID;
";

/// Copies of the folded rows whose span overlaps the range (same columns, no generated one).
/// `wide`: the range covers a large part of the session, the table is read in storage order
/// (`+`: no index) rather than through the start-time index row by row.
fn overlap_copy(table: &str, wide: bool) -> String {
    let plus = if wide { "+" } else { "" };
    format!(
        "INSERT INTO main.{table} SELECT * FROM {ATTACHED}.{table} \
         WHERE {plus}first_ts < ?99 AND {plus}last_ts >= ?98"
    )
}

/// `server_evidence_source` (migration 0801) over the range: point records by their timestamp,
/// folded rows by overlap; open ports from the range database (with the flows of the range).
/// A test compares it with the session table over a range covering the session.
fn server_evidence_sql() -> String {
    let s = ATTACHED;
    format!(
        "INSERT INTO main.server_evidence (role, ip, kind, count, clients, first_ts, last_ts, example)
WITH srv AS (
    SELECT owner, lower(substr(v, length(rtrim(v, replace(v, ' ', ''))) + 1)) AS target, ts
    FROM (SELECT lower(json_extract(a.value, '$.n')) AS owner, json_extract(a.value, '$.v') AS v,
                 m.ts + coalesce(m.latency_ns, 0) AS ts
          FROM {s}.dns_messages m, json_each(m.answers) a
          WHERE m.qtype = 'SRV' AND m.has_response = 1 AND m.ts >= ?98 AND m.ts < ?99
            AND json_extract(a.value, '$.t') = 'SRV')
    WHERE owner LIKE '\\_ldap.\\_tcp.%' ESCAPE '\\' OR owner LIKE '\\_gc.\\_tcp.%' ESCAPE '\\'
       OR owner LIKE '\\_kerberos.\\_tcp.%' ESCAPE '\\' OR owner LIKE '\\_kerberos.\\_udp.%' ESCAPE '\\'
),
named AS (
    SELECT h.ip, lower(n.value) AS name
    FROM main.hosts h, json_each(h.names) n
    WHERE h.names <> '[]' AND lower(n.value) IN (SELECT target FROM srv)
)
SELECT 'dns', coalesce(responder_ip, server_ip), 'dns_response', count(*),
       count(DISTINCT client_ip), min(ts + coalesce(latency_ns, 0)),
       max(ts + coalesce(latency_ns, 0)), NULL
FROM {s}.dns_messages
WHERE proto = 'dns' AND has_response = 1 AND +ts >= ?98 AND +ts < ?99
GROUP BY coalesce(responder_ip, server_ip)
UNION ALL
SELECT CASE o.port WHEN 53 THEN 'dns' WHEN 67 THEN 'dhcp' WHEN 88 THEN 'kerberos'
                   WHEN 123 THEN 'ntp' WHEN 139 THEN 'smb' WHEN 445 THEN 'smb' ELSE 'ldap' END,
       o.ip, 'open_port', coalesce(c.flows, 0), coalesce(c.clients, 0), o.first_ts, o.last_ts,
       o.port || '/' || CASE o.transport WHEN 6 THEN 'tcp' WHEN 17 THEN 'udp'
                                         ELSE o.transport END
FROM main.open_ports o
LEFT JOIN main.open_port_clients c ON c.ip = o.ip AND c.transport = o.transport AND c.port = o.port
WHERE o.port IN (53, 67, 88, 123, 139, 389, 445, 636, 3268, 3269)
UNION ALL
SELECT 'dhcp', d.server_ip, 'dhcp_' || d.msg_type, count(*), count(DISTINCT d.client_mac),
       min(d.ts), max(d.ts),
       (SELECT x.yiaddr FROM {s}.dhcp_messages x
        WHERE x.op = 2 AND x.msg_type = d.msg_type AND x.server_ip = d.server_ip
          AND x.ts >= ?98 AND x.ts < ?99
        ORDER BY x.ts DESC, x.yiaddr DESC LIMIT 1)
FROM {s}.dhcp_messages d
WHERE d.op = 2 AND d.msg_type IN ('offer', 'ack', 'nak') AND d.ts >= ?98 AND d.ts < ?99
  AND NOT (d.src_ip IS d.giaddr AND EXISTS (
      SELECT 1 FROM {s}.dhcp_messages x
      WHERE x.xid = d.xid AND x.client_mac IS d.client_mac AND x.op = 2
        AND x.msg_type = d.msg_type AND x.src_ip IS NOT d.giaddr
        AND x.ts >= ?98 AND x.ts < ?99))
GROUP BY d.server_ip, d.msg_type
UNION ALL
SELECT CASE WHEN s.owner LIKE '\\_kerberos.%' ESCAPE '\\' THEN 'kerberos' ELSE 'ldap' END,
       n.ip, 'dns_srv', count(*), NULL, min(s.ts), max(s.ts), min(s.owner)
FROM srv s JOIN named n ON n.name = s.target
GROUP BY 1, n.ip
UNION ALL
SELECT 'ntp', t.server_ip, 'ntp_response', sum(t.responses), count(*), min(t.first_ts),
       max(t.last_ts),
       (SELECT 'stratum ' || x.stratum || coalesce(nullif(', ' || x.reference, ', '), '')
        FROM {s}.ntp_responses x
        WHERE x.server_ip = t.server_ip AND x.first_ts < ?99 AND x.last_ts >= ?98
        ORDER BY x.last_ts DESC, x.stratum DESC, x.reference DESC LIMIT 1)
FROM {s}.ntp_responses t
WHERE t.first_ts < ?99 AND t.last_ts >= ?98
GROUP BY t.server_ip
UNION ALL
SELECT 'kerberos', k.server_ip, 'kdc_' || k.kind, sum(k.replies), count(*), min(k.first_ts),
       max(k.last_ts),
       (SELECT x.realm FROM {s}.kerberos_replies x
        WHERE x.server_ip = k.server_ip AND x.kind = k.kind AND x.realm IS NOT NULL
          AND x.first_ts < ?99 AND x.last_ts >= ?98
        ORDER BY x.last_ts DESC, x.realm DESC LIMIT 1)
FROM {s}.kerberos_replies k
WHERE k.first_ts < ?99 AND k.last_ts >= ?98
GROUP BY k.server_ip, k.kind
UNION ALL
SELECT 'smb', server_ip, 'smb_session', count(*), count(DISTINCT client_ip), min(first_ts),
       max(last_ts), max(dialect)
FROM {s}.smb_sessions
WHERE first_ts < ?99 AND last_ts >= ?98
GROUP BY server_ip
UNION ALL
SELECT 'smb', src_ip, CASE WHEN server_type & 24 <> 0 THEN 'browser_dc' ELSE 'browser_server' END,
       sum(announce_count), NULL, min(first_ts), max(last_ts), min(server_name)
FROM {s}.smb_announces
WHERE server_type & 26 <> 0 AND first_ts < ?99 AND last_ts >= ?98
GROUP BY src_ip, 3
UNION ALL
SELECT 'http', server_ip, 'http_response', count(*), count(DISTINCT client_ip), min(resp_ts),
       max(resp_ts), NULL
FROM {s}.http_transactions
WHERE resp_ts IS NOT NULL AND +resp_ts >= ?98 AND +resp_ts < ?99
GROUP BY server_ip"
    )
}

/// Roles: the servers of the evidence (same sources and conditions as `server_roles_source`).
const SERVER_ROLES_SQL: &str = "INSERT INTO main.server_roles (role, ip) \
    SELECT DISTINCT role, ip FROM main.server_evidence";

/// Builds the range database of `range` into `target` (a new file). Stops with
/// [`StoreError::Cancelled`] as soon as `abandoned` returns true (polled by a watcher thread
/// that interrupts the running statement).
pub(super) fn build(
    session_db: &Path,
    target: &Path,
    range: TimeRange,
    abandoned: &(dyn Fn() -> bool + Sync),
) -> Result<()> {
    let conn = open_target(target, session_db)?;
    let handle = conn.get_interrupt_handle();
    let done = AtomicBool::new(false);
    let result = std::thread::scope(|scope| {
        let watcher = scope.spawn(|| {
            while !done.load(Ordering::Relaxed) {
                if abandoned() {
                    handle.interrupt();
                    return;
                }
                std::thread::park_timeout(POLL);
            }
        });
        let result = steps(&conn, range, abandoned);
        done.store(true, Ordering::Relaxed);
        watcher.thread().unpark();
        result
    });
    match result {
        Err(e) if abandoned() || is_interrupt(&e) => Err(StoreError::Cancelled),
        other => other,
    }
}

fn is_interrupt(e: &StoreError) -> bool {
    matches!(e, StoreError::Sqlite(s) if s.sqlite_error_code() == Some(ErrorCode::OperationInterrupted))
}

/// The new file, written without journal (a failed build is deleted), the session attached.
fn open_target(target: &Path, session_db: &Path) -> Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_URI;
    let conn = Connection::open_with_flags(target, flags)?;
    conn.busy_timeout(crate::session::BUSY_TIMEOUT)?;
    conn.pragma_update(None, "page_size", PAGE_SIZE)?;
    conn.pragma_update(None, "journal_mode", "OFF")?;
    conn.pragma_update(None, "synchronous", "OFF")?;
    // Negative = KiB: 128 MiB of page cache (the conversations of a wide range and their indexes
    // stay in memory while written); larger sorts spill to temporary files.
    conn.pragma_update(None, "cache_size", -131_072)?;
    attach(&conn, session_db)?;
    // The session is read once, mostly in storage order: through a memory map rather than read
    // calls into a small page cache (file-backed pages, released under memory pressure).
    conn.pragma_update(Some(ATTACHED), "mmap_size", 1_i64 << 30)?;
    Ok(conn)
}

/// Runs `sql`, binding the range to `?98` / `?99` when it names them.
fn exec(conn: &Connection, sql: &str, range: TimeRange) -> Result<()> {
    let mut stmt = conn.prepare(sql)?;
    if stmt.parameter_count() >= 99 {
        stmt.raw_bind_parameter(98, range.from_ns())?;
        stmt.raw_bind_parameter(99, range.to_ns())?;
    }
    stmt.raw_execute()?;
    Ok(())
}

/// DDL of `kind` objects (`table` or `index`) of the session: the table itself, or the indexes of
/// table `name` (automatic ones come with their table).
fn session_ddl(conn: &Connection, kind: &str, name: &str) -> Result<Vec<String>> {
    let column = if kind == "table" { "name" } else { "tbl_name" };
    let mut stmt = conn.prepare(&format!(
        "SELECT sql FROM {ATTACHED}.sqlite_master \
         WHERE type = ?1 AND {column} = ?2 AND sql IS NOT NULL ORDER BY name"
    ))?;
    let rows = stmt.query_map([kind, name], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

fn create_indexes(conn: &Connection, table: &str) -> Result<()> {
    for sql in session_ddl(conn, "index", table)? {
        conn.execute_batch(&sql)?;
    }
    Ok(())
}

fn steps(conn: &Connection, range: TimeRange, abandoned: &dyn Fn() -> bool) -> Result<()> {
    let started = std::time::Instant::now();
    let mut marks: Vec<(&str, u128)> = Vec::new();
    let mut check = |step: &'static str| {
        marks.push((step, started.elapsed().as_millis()));
        if abandoned() {
            Err(StoreError::Cancelled)
        } else {
            Ok(())
        }
    };
    conn.execute_batch("BEGIN")?;
    for table in COPIED {
        let ddl = session_ddl(conn, "table", table)?;
        if ddl.is_empty() {
            return Err(StoreError::RangeBuild(format!(
                "the session has no table {table}"
            )));
        }
        for sql in ddl {
            conn.execute_batch(&sql)?;
        }
    }
    conn.execute_batch(OWN_TABLES)?;
    // Indexes of the tables filled by the steps below, which read them while filling (the
    // network step reads `network_hosts` by index); the copied tables get theirs once filled.
    for table in COPIED.iter().filter(|t| !COPIED_ROWS.contains(t)) {
        create_indexes(conn, table)?;
    }

    copy_meta(conn)?;
    // Flows active in the range against all: the plan of the reads (wide: tables in storage order).
    let active = crate::range::count_active_flows(conn, range)?;
    let flows: u64 =
        conn.query_row(&format!("SELECT count(*) FROM {ATTACHED}.flows"), [], |r| {
            r.get(0)
        })?;
    let wide = active.saturating_mul(20) >= flows;
    exec(conn, &overlap_copy("hosts", wide), range)?;
    create_indexes(conn, "hosts")?;
    check("hosts")?;

    exec(conn, &overlap_copy("open_ports", true), range)?;
    create_indexes(conn, "open_ports")?;
    crate::ports::finalize(conn)?;
    check("open_ports")?;

    super::fold::fold_flows(conn, range, active, wide, abandoned)?;
    create_indexes(conn, "conversations")?;
    check("conversations")?;

    exec(conn, &server_evidence_sql(), range)?;
    exec(conn, SERVER_ROLES_SQL, range)?;
    crate::servers::rank_servers(conn)?;
    check("servers")?;

    crate::network::finalize(conn)?;
    check("network")?;

    let mut meta = conn.prepare("INSERT INTO main.range_meta (key, value) VALUES (?1, ?2)")?;
    for (key, value) in [
        ("from_ns", range.from_ns().to_string()),
        ("to_ns", range.to_ns().to_string()),
        ("build_version", super::BUILD_VERSION.to_string()),
    ] {
        meta.execute([key, value.as_str()])?;
    }
    drop(meta);
    conn.execute_batch("COMMIT")?;
    tracing::debug!(
        ?marks,
        active,
        wide,
        "range database steps (ms since the start)"
    );
    Ok(())
}

/// `meta` of the session, with the steps whose tables the range database holds marked done in
/// their current version (the readers then read these tables, never their fallbacks).
fn copy_meta(conn: &Connection) -> Result<()> {
    conn.execute_batch(&format!(
        "INSERT INTO main.meta SELECT * FROM {ATTACHED}.meta"
    ))?;
    let mut markers: Vec<String> = crate::finalize::finalizers_done(conn)?
        .into_iter()
        .filter(|m| !STEPS.iter().any(|s| m.split(':').next() == Some(*s)))
        .collect();
    markers.extend(
        crate::finalize::SESSION_FINALIZERS
            .iter()
            .filter(|f| STEPS.contains(&f.id))
            .map(|f| format!("{}:{}", f.id, f.version)),
    );
    conn.execute(
        "INSERT INTO main.meta (key, value) VALUES (?1, ?2) \
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        [crate::finalize::MARKER_KEY, &markers.join(",")],
    )?;
    Ok(())
}
