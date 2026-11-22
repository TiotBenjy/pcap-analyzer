//! DNS tables (`0100_dns.sql`): transaction rows written by the `dns` analyzer, end-of-import
//! processing ([`finalize`]) and the read queries of the DNS view.
//!
//! # End of import
//!
//! Shards cannot pair a query sent to a group address (NBNS broadcast, LLMNR multicast) with
//! a response handled by another shard. Such queries arrive with `pending = 1`; [`finalize`]
//! pairs each one, in time order, with the earliest response-only row of the same
//! (client endpoint, transaction id, protocol, transport) within the response window of the
//! analyzer (`meta` [`PAIR_WINDOW_META_KEY`], default [`PAIR_WINDOW_NS`]), then:
//! - builds `dns_pairs` (one row per protocol, client and server, deterministic ids) and sets
//!   `dns_messages.pair_id`;
//! - rebuilds the `dns_fts` search index;
//! - adds the names resolved by the answers (A, AAAA, NB) to `hosts.names`, for the hosts
//!   already present only (a resolved address that never shows up in the traffic is not a host
//!   of the capture).
//!
//! The result does not depend on the arrival order of the rows.

use std::net::IpAddr;

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, ToSql, params};
use serde_json::json;

use crate::connections::EndpointInfo;
use crate::error::Result;
use crate::query::{Conditions, Keyset, Page, PageRequest, keyset_page};
use crate::range::{PointSql, TimeRange, query_ranged, query_row_ranged};
use crate::records::{MAX_HOST_NAMES, conversion};

/// Response window of the end-of-import pairing (same as the analyzer's default).
pub const PAIR_WINDOW_NS: i64 = 5_000_000_000;
/// Names listed per pair (`dns_pairs.top_names`).
pub const TOP_NAMES: usize = 5;
/// Entries of each statistics list (the rest is summed into `other`).
pub const STATS_TOP: usize = 10;

/// One answer record of a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswerRow {
    pub name: String,
    pub rtype: String,
    pub value: String,
    pub ttl: u32,
}

/// One transaction (see `netsift-analyze`, `dns.rs`, for the meaning of each field).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRow {
    pub ts: i64,
    pub flow_id: Option<i64>,
    pub transport: u8,
    /// `dns`, `mdns`, `llmnr` or `nbns`.
    pub proto: String,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub responder_ip: Option<IpAddr>,
    pub txid: u16,
    pub opcode: String,
    pub qname: String,
    pub qtype: String,
    pub nb_suffix: Option<u8>,
    pub flags: u16,
    pub rcode: Option<String>,
    pub latency_ns: Option<i64>,
    pub answers: Vec<DnsAnswerRow>,
    pub has_query: bool,
    pub has_response: bool,
    pub pending: bool,
}

fn answers_json(answers: &[DnsAnswerRow]) -> Result<String> {
    let v: Vec<_> = answers
        .iter()
        .map(|a| json!({ "n": a.name, "t": a.rtype, "v": a.value, "ttl": a.ttl }))
        .collect();
    Ok(serde_json::to_string(&v)?)
}

/// Owner names and values of the answers, space separated, without repetition (search text).
pub(crate) fn answers_text(answers: &[DnsAnswerRow]) -> String {
    let mut words: Vec<&str> = Vec::new();
    for a in answers {
        for w in [a.name.as_str(), a.value.as_str()] {
            if !w.is_empty() && !words.contains(&w) {
                words.push(w);
            }
        }
    }
    words.join(" ")
}

fn parse_answers(text: &str) -> serde_json::Result<Vec<DnsAnswerRow>> {
    let raw: Vec<serde_json::Value> = serde_json::from_str(text)?;
    Ok(raw
        .iter()
        .map(|a| DnsAnswerRow {
            name: a["n"].as_str().unwrap_or_default().to_owned(),
            rtype: a["t"].as_str().unwrap_or_default().to_owned(),
            value: a["v"].as_str().unwrap_or_default().to_owned(),
            ttl: a["ttl"]
                .as_u64()
                .and_then(|t| u32::try_from(t).ok())
                .unwrap_or(0),
        })
        .collect())
}

impl DnsRow {
    pub(crate) fn insert(&self, conn: &Connection) -> Result<()> {
        conn.prepare_cached(
            "INSERT INTO dns_messages (ts, flow_id, transport, proto, client_ip, client_port, \
             server_ip, server_port, responder_ip, txid, opcode, qname, qtype, nb_suffix, flags, \
             rcode, latency_ns, answers, answers_text, has_query, has_response, pending) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
             ?18, ?19, ?20, ?21, ?22)",
        )?
        .execute(params![
            self.ts,
            self.flow_id,
            self.transport,
            self.proto,
            self.client_ip.to_string(),
            self.client_port,
            self.server_ip.to_string(),
            self.server_port,
            self.responder_ip.map(|ip| ip.to_string()),
            self.txid,
            self.opcode,
            self.qname,
            self.qtype,
            self.nb_suffix,
            self.flags,
            self.rcode,
            self.latency_ns,
            answers_json(&self.answers)?,
            answers_text(&self.answers),
            self.has_query,
            self.has_response,
            self.pending,
        ])?;
        Ok(())
    }
}

// --- End of import --------------------------------------------------------------------------

/// `meta` key of the response window used by the analyzer (ns), written by the engine.
pub const PAIR_WINDOW_META_KEY: &str = "dns.pair_window_ns";

/// End-of-import processing of the DNS tables (see the module documentation), registered in
/// [`crate::finalize::SESSION_FINALIZERS`]: runs inside the transaction of the caller.
/// Idempotent.
pub(crate) fn finalize(conn: &Connection) -> Result<()> {
    let window = crate::query::get_meta(conn, PAIR_WINDOW_META_KEY)?
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|w| *w >= 0)
        .unwrap_or(PAIR_WINDOW_NS);
    pair_pending(conn, window)?;
    build_pairs(conn)?;
    conn.execute("INSERT INTO dns_fts (dns_fts) VALUES ('rebuild')", [])?;
    feed_host_names(conn)?;
    Ok(())
}

struct PendingQuery {
    id: i64,
    ts: i64,
    proto: String,
    transport: i64,
    client_ip: String,
    client_port: i64,
    txid: i64,
}

/// Group queries read per batch by [`pair_pending`].
const PENDING_BATCH: i64 = 10_000;

fn pair_pending(conn: &Connection, window: i64) -> Result<()> {
    let mut next_batch = conn.prepare_cached(
        "SELECT id, ts, proto, transport, client_ip, client_port, txid \
         FROM dns_messages WHERE pending = 1 \
         ORDER BY ts, client_ip, client_port, txid, proto, transport, qname, server_ip, id \
         LIMIT ?1",
    )?;
    let mut find = conn.prepare_cached(
        "SELECT id FROM dns_messages \
         WHERE client_ip = ?1 AND client_port = ?2 AND txid = ?3 AND proto = ?4 \
         AND transport = ?5 AND ts BETWEEN ?6 AND ?7 AND has_query = 0 \
         ORDER BY ts, server_ip, qname, id LIMIT 1",
    )?;
    let mut merge = conn.prepare_cached(
        "UPDATE dns_messages SET \
         responder_ip = CASE WHEN r.server_ip <> dns_messages.server_ip THEN r.server_ip END, \
         flags = r.flags, rcode = r.rcode, latency_ns = max(r.ts - dns_messages.ts, 0), \
         answers_text = CASE WHEN r.answers <> '[]' OR dns_messages.answers = '[]' \
                   THEN r.answers_text ELSE dns_messages.answers_text END, \
         answers = CASE WHEN r.answers <> '[]' OR dns_messages.answers = '[]' \
                   THEN r.answers ELSE dns_messages.answers END, \
         has_response = 1, pending = 0 \
         FROM (SELECT server_ip, flags, rcode, ts, answers, answers_text FROM dns_messages \
               WHERE id = ?2) AS r \
         WHERE dns_messages.id = ?1",
    )?;
    let mut delete = conn.prepare_cached("DELETE FROM dns_messages WHERE id = ?1")?;
    let mut settle = conn.prepare_cached("UPDATE dns_messages SET pending = 0 WHERE id = ?1")?;
    // Every query of a batch leaves the pending set, so the next batch starts after it.
    loop {
        let batch: Vec<PendingQuery> = next_batch
            .query_map([PENDING_BATCH], |r| {
                Ok(PendingQuery {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    proto: r.get(2)?,
                    transport: r.get(3)?,
                    client_ip: r.get(4)?,
                    client_port: r.get(5)?,
                    txid: r.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        if batch.is_empty() {
            return Ok(());
        }
        for q in batch {
            pair_one(&q, window, &mut find, &mut merge, &mut delete, &mut settle)?;
        }
    }
}

fn pair_one(
    q: &PendingQuery,
    window: i64,
    find: &mut rusqlite::CachedStatement<'_>,
    merge: &mut rusqlite::CachedStatement<'_>,
    delete: &mut rusqlite::CachedStatement<'_>,
    settle: &mut rusqlite::CachedStatement<'_>,
) -> Result<()> {
    let found = find
        .query_row(
            params![
                q.client_ip,
                q.client_port,
                q.txid,
                q.proto,
                q.transport,
                q.ts,
                q.ts.saturating_add(window)
            ],
            |r| r.get::<_, i64>(0),
        )
        .optional()?;
    match found {
        Some(response) => {
            merge.execute(params![q.id, response])?;
            delete.execute([response])?;
        }
        // Unpaired: keeps its outcome (`timeout`, or none when no response is expected).
        None => {
            settle.execute([q.id])?;
        }
    }
    Ok(())
}

fn build_pairs(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "DELETE FROM dns_pairs;
         INSERT INTO dns_pairs (id, proto, client_ip, server_ip, messages, errors, names, \
                                first_ts, last_ts)
         SELECT row_number() OVER (ORDER BY proto, client_ip, server_ip), proto, client_ip,
                server_ip, count(*), sum(is_error), count(DISTINCT nullif(qname, '')),
                min(ts), max(ts)
         FROM dns_messages GROUP BY proto, client_ip, server_ip;
         UPDATE dns_messages SET pair_id = (
             SELECT p.id FROM dns_pairs p WHERE p.proto = dns_messages.proto
             AND p.client_ip = dns_messages.client_ip AND p.server_ip = dns_messages.server_ip);",
    )?;
    conn.execute(
        "UPDATE dns_pairs SET top_names = (
             SELECT json_group_array(qname ORDER BY n DESC, qname) FROM (
                 SELECT qname, count(*) AS n FROM dns_messages m
                 WHERE m.pair_id = dns_pairs.id AND qname <> ''
                 GROUP BY qname ORDER BY n DESC, qname LIMIT ?1))",
        [i64::try_from(TOP_NAMES).unwrap_or(5)],
    )?;
    Ok(())
}

fn feed_host_names(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "DROP TABLE IF EXISTS temp.dns_resolved;
         CREATE TEMP TABLE dns_resolved (ip TEXT NOT NULL, name TEXT NOT NULL,
                                         PRIMARY KEY (ip, name)) WITHOUT ROWID;
         INSERT OR IGNORE INTO temp.dns_resolved (ip, name)
         SELECT json_extract(a.value, '$.v'), json_extract(a.value, '$.n')
         FROM dns_messages m, json_each(m.answers) a
         WHERE json_extract(a.value, '$.t') IN ('A', 'AAAA', 'NB')
         UNION
         SELECT json_extract(a.value, '$.v'), m.qname
         FROM dns_messages m, json_each(m.answers) a
         WHERE m.qtype IN ('A', 'AAAA') AND json_extract(a.value, '$.t') IN ('A', 'AAAA');
         DELETE FROM temp.dns_resolved
         WHERE ip IS NULL OR name IS NULL OR name = '' OR length(CAST(name AS BLOB)) > 255
            OR ip NOT IN (SELECT ip FROM hosts);",
    )?;
    // Names from other sources are kept; resolved names fill the room left, smallest first.
    let rows: Vec<(String, String, String)> = conn
        .prepare(
            "SELECT r.ip, h.names, json_group_array(r.name ORDER BY r.name) \
             FROM temp.dns_resolved r JOIN hosts h ON h.ip = r.ip GROUP BY r.ip",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut update = conn.prepare("UPDATE hosts SET names = ?2 WHERE ip = ?1")?;
    for (ip, existing, resolved) in rows {
        let mut names: Vec<String> = serde_json::from_str(&existing)?;
        let resolved: Vec<String> = serde_json::from_str(&resolved)?;
        let before = names.len();
        for name in resolved {
            if names.len() >= MAX_HOST_NAMES {
                break;
            }
            if !names.contains(&name) {
                names.push(name);
            }
        }
        if names.len() != before {
            names.sort_unstable();
            update.execute(params![ip, serde_json::to_string(&names)?])?;
        }
    }
    drop(update);
    conn.execute_batch("DROP TABLE temp.dns_resolved")?;
    Ok(())
}

// --- Read queries ---------------------------------------------------------------------------

/// Count of one category of the statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bucket {
    /// `None`: no value (no response expected, unknown country...).
    pub key: Option<String>,
    pub count: u64,
}

/// Countries of the servers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CountryBucket {
    /// ISO 3166-1 alpha-2 code, `None` for local, group and unknown addresses.
    pub country: Option<String>,
    pub servers: u64,
    pub messages: u64,
}

/// Figures of the DNS view charts and filter counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsStats {
    pub total: u64,
    pub errors: u64,
    pub answered: u64,
    /// Per protocol, every protocol present.
    pub protocols: Vec<Bucket>,
    /// Errors per protocol (filter counters with "errors only").
    pub protocol_errors: Vec<Bucket>,
    /// Top [`STATS_TOP`] outcomes, the rest in `rcode_other`.
    pub rcodes: Vec<Bucket>,
    pub rcode_other: u64,
    /// Top [`STATS_TOP`] query types, the rest in `qtype_other`.
    pub qtypes: Vec<Bucket>,
    pub qtype_other: u64,
    /// Top [`STATS_TOP`] known countries, by messages; local and unknown in `country_unknown`.
    pub countries: Vec<CountryBucket>,
    pub country_unknown: CountryBucket,
    /// Median and 95th percentile of the response time (ns), over answered transactions.
    pub latency_p50_ns: Option<i64>,
    pub latency_p95_ns: Option<i64>,
}

fn u(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn buckets(conn: &Connection, sql: &str, range: Option<TimeRange>) -> Result<Vec<Bucket>> {
    query_ranged(conn, sql, &[], range, |r| {
        Ok(Bucket {
            key: r.get(0)?,
            count: u(r.get(1)?),
        })
    })
}

/// Keeps the `n` largest buckets (already sorted) and sums the rest.
fn top(mut all: Vec<Bucket>, n: usize) -> (Vec<Bucket>, u64) {
    let rest = all.split_off(n.min(all.len()));
    (all, rest.iter().map(|b| b.count).sum())
}

/// Pairs with their messages within the range (`rn`, bound to `?98` and `?99`).
const RANGE_PAIR_COUNTS: &str = "(SELECT p.*, \
    (SELECT count(*) FROM dns_messages m WHERE m.pair_id = p.id AND m.ts >= ?98 \
     AND m.ts < ?99) AS rn FROM dns_pairs p)";

/// `(total, errors, answered, messages per protocol, errors per protocol)`.
type ProtocolCounts = (i64, i64, i64, Vec<Bucket>, Vec<Bucket>);

/// Totals, answered transactions and the messages and errors per protocol, from one pass over
/// the covering index `(proto, is_error, has_query, has_response, ts)` (three passes before
/// P5.2). `w`: the range condition of the plan (` WHERE ...`, or nothing).
fn protocol_counts(conn: &Connection, w: &str, range: Option<TimeRange>) -> Result<ProtocolCounts> {
    let groups: Vec<(String, bool, bool, i64)> = query_ranged(
        conn,
        &format!(
            "SELECT proto, is_error, has_query AND has_response, count(*) FROM dns_messages{w} \
             GROUP BY proto, is_error, has_query, has_response"
        ),
        &[],
        range,
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    let (mut total, mut errors, mut answered) = (0_i64, 0_i64, 0_i64);
    let mut per_proto: std::collections::BTreeMap<String, (i64, i64)> =
        std::collections::BTreeMap::default();
    for (proto, is_error, both, n) in groups {
        total += n;
        let entry = per_proto.entry(proto).or_default();
        entry.0 += n;
        if is_error {
            errors += n;
            entry.1 += n;
        }
        if both {
            answered += n;
        }
    }
    let ranked = |pick: fn(&(i64, i64)) -> i64| -> Vec<Bucket> {
        let mut out: Vec<Bucket> = per_proto
            .iter()
            .filter(|(_, c)| pick(c) > 0)
            .map(|(p, c)| Bucket {
                key: Some(p.clone()),
                count: u(pick(c)),
            })
            .collect();
        // Most first, then by name (the order of the former `ORDER BY 2 DESC, 1`).
        out.sort_by(|x, y| y.count.cmp(&x.count).then_with(|| x.key.cmp(&y.key)));
        out
    };
    let protocols = ranked(|c| c.0);
    let protocol_errors = ranked(|c| c.1);
    Ok((total, errors, answered, protocols, protocol_errors))
}

/// Statistics of the session, or of the messages within `range` (ADR-030).
pub fn stats(conn: &Connection, range: Option<TimeRange>) -> Result<DnsStats> {
    let plan = PointSql::new(conn, "dns_messages", "ts", range)?;
    let w = plan.where_();
    let a = plan.and();
    let (total, errors, answered, protocols, protocol_errors) = protocol_counts(conn, &w, range)?;
    let (rcodes, rcode_other) = top(
        buckets(
            conn,
            &format!(
                "SELECT rcode, count(*) FROM dns_messages{w} GROUP BY rcode ORDER BY 2 DESC, 1"
            ),
            range,
        )?,
        STATS_TOP,
    );
    let (qtypes, qtype_other) = top(
        buckets(
            conn,
            &format!(
                "SELECT qtype, count(*) FROM dns_messages WHERE qtype <> '' AND has_query = 1{a} \
                 GROUP BY qtype ORDER BY 2 DESC, 1"
            ),
            range,
        )?,
        STATS_TOP,
    );
    let countries_sql = if range.is_some() {
        format!(
            "SELECT h.country, count(DISTINCT p.server_ip), sum(p.rn) \
             FROM {RANGE_PAIR_COUNTS} p LEFT JOIN hosts h ON h.ip = p.server_ip \
             WHERE p.rn > 0 GROUP BY h.country ORDER BY 3 DESC, 1"
        )
    } else {
        "SELECT h.country, count(DISTINCT p.server_ip), sum(p.messages) \
         FROM dns_pairs p LEFT JOIN hosts h ON h.ip = p.server_ip \
         GROUP BY h.country ORDER BY 3 DESC, 1"
            .to_owned()
    };
    let mut countries: Vec<CountryBucket> = query_ranged(conn, &countries_sql, &[], range, |r| {
        Ok(CountryBucket {
            country: r.get(0)?,
            servers: u(r.get(1)?),
            messages: u(r.get(2)?),
        })
    })?;
    let unknown_pos = countries.iter().position(|c| c.country.is_none());
    let country_unknown = unknown_pos.map_or_else(CountryBucket::default, |i| countries.remove(i));
    countries.truncate(STATS_TOP);
    let (latency_p50_ns, latency_p95_ns) = latency_percentiles(conn, answered, plan)?;
    Ok(DnsStats {
        total: u(total),
        errors: u(errors),
        answered: u(answered),
        protocols,
        protocol_errors,
        rcodes,
        rcode_other,
        qtypes,
        qtype_other,
        countries,
        country_unknown,
        latency_p50_ns,
        latency_p95_ns,
    })
}

fn latency_percentiles(
    conn: &Connection,
    answered: i64,
    plan: PointSql,
) -> Result<(Option<i64>, Option<i64>)> {
    if answered <= 0 {
        return Ok((None, None));
    }
    let range = plan.range();
    let a = plan.and();
    let n: i64 = query_row_ranged(
        conn,
        &format!("SELECT count(*) FROM dns_messages WHERE latency_ns IS NOT NULL{a}"),
        &[],
        range,
        |r| r.get(0),
    )?;
    if n == 0 {
        return Ok((None, None));
    }
    // Both percentiles from one walk of the latency index, stopped at the 95th (two `OFFSET`
    // walks before P5.2).
    let at = |percent: i64| n.saturating_sub(1).saturating_mul(percent) / 100;
    let (i50, i95) = (at(50), at(95));
    let (mut row, mut p50, mut p95) = (0_i64, None, None);
    // Rows are read one by one (nothing kept but the two values).
    query_ranged(
        conn,
        &format!(
            "SELECT latency_ns FROM dns_messages WHERE latency_ns IS NOT NULL{a} \
             ORDER BY latency_ns LIMIT ?1"
        ),
        &[&(i95 + 1)],
        range,
        |r| {
            if row == i50 {
                p50 = Some(r.get::<_, i64>(0)?);
            }
            if row == i95 {
                p95 = Some(r.get::<_, i64>(0)?);
            }
            row += 1;
            Ok(())
        },
    )?;
    Ok((p50, p95))
}

/// Filters of the pair and message lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsFilter {
    /// Protocols shown (`dns`, `mdns`, `llmnr`, `nbns`); unknown labels match nothing.
    pub protocols: Vec<String>,
    /// Only transactions with an error (pairs with at least one).
    pub errors_only: bool,
    /// Substring of a name, an address or an answer (case-insensitive).
    pub search: Option<String>,
    /// Only the messages within this time range (pairs and servers regrouped over them).
    pub range: Option<TimeRange>,
}

impl Default for DnsFilter {
    fn default() -> Self {
        Self {
            protocols: ["dns", "mdns", "llmnr", "nbns"].map(str::to_owned).to_vec(),
            errors_only: false,
            search: None,
            range: None,
        }
    }
}

/// How the search text is matched.
enum Search {
    None,
    /// Trigram full-text index (3 characters or more).
    Fts(String),
    /// Short text: plain `LIKE` on the indexed columns.
    Like(String),
}

impl DnsFilter {
    fn protocol_list(&self) -> String {
        let mut s = String::from(",");
        for p in &self.protocols {
            s.push_str(p);
            s.push(',');
        }
        s
    }

    /// Without the search index (`fts_ready` false: step `dns` not run, ADR-023), every search
    /// uses `LIKE`.
    fn search(&self, fts_ready: bool) -> Search {
        let Some(q) = self
            .search
            .as_deref()
            .map(str::trim)
            .filter(|q| !q.is_empty())
        else {
            return Search::None;
        };
        if fts_ready && q.chars().count() >= 3 {
            // A quoted FTS5 string: any character is literal inside.
            Search::Fts(format!("\"{}\"", q.replace('"', "\"\"")))
        } else {
            let escaped = q
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            Search::Like(format!("%{escaped}%"))
        }
    }
}

/// Message-level search condition on `dns_messages` aliased `m`, one `?` parameter.
macro_rules! fts_cond {
    () => {
        "m.id IN (SELECT rowid FROM dns_fts WHERE dns_fts MATCH ?)"
    };
}
macro_rules! like_cond {
    () => {
        "(m.qname LIKE ? ESCAPE '\\' OR m.client_ip LIKE ? ESCAPE '\\' \
          OR m.server_ip LIKE ? ESCAPE '\\' OR m.answers_text LIKE ? ESCAPE '\\')"
    };
}

/// Protocols stored in `dns_messages` (its `CHECK` constraint): selecting them all filters
/// nothing.
const ALL_PROTOCOLS: [&str; 4] = ["dns", "mdns", "llmnr", "nbns"];

impl DnsFilter {
    /// False when every stored protocol is selected (no condition needed).
    fn filters_protocols(&self) -> bool {
        !ALL_PROTOCOLS
            .iter()
            .all(|p| self.protocols.iter().any(|q| q == p))
    }
}

/// Adds the search condition on `dns_messages m`.
fn push_search(c: &mut Conditions, search: &Search) {
    match search {
        Search::None => {}
        Search::Fts(q) => c.push(fts_cond!(), [Value::Text(q.clone())]),
        Search::Like(q) => c.push(like_cond!(), [0, 1, 2, 3].map(|_| Value::Text(q.clone()))),
    }
}

/// The active filters of the message list only (P4.2): with every protocol and no other
/// filter, the count reads the table without evaluating anything per row.
fn message_conditions(filter: &DnsFilter, pair: Option<i64>, fts_ready: bool) -> Conditions {
    let mut c = Conditions::new();
    if let Some(p) = pair {
        c.push("m.pair_id = ?", [Value::Integer(p)]);
    }
    if filter.filters_protocols() {
        c.push(
            "instr(?, ',' || m.proto || ',') > 0",
            [Value::Text(filter.protocol_list())],
        );
    }
    if filter.errors_only {
        c.push("m.is_error = 1", []);
    }
    if let Some(r) = filter.range {
        r.push_point(&mut c, "m.ts");
    }
    push_search(&mut c, &filter.search(fts_ready));
    c
}

/// Same for the pair list: the search applies to the messages of a pair.
fn pair_conditions(filter: &DnsFilter, fts_ready: bool) -> Conditions {
    let mut c = Conditions::new();
    // Under a range, `p` is [`RANGE_PAIRS`]: its counts are those of the range.
    if filter.range.is_some() {
        c.push("p.rn > 0", []);
    }
    if filter.filters_protocols() {
        c.push(
            "instr(?, ',' || p.proto || ',') > 0",
            [Value::Text(filter.protocol_list())],
        );
    }
    if filter.errors_only {
        c.push(
            if filter.range.is_some() {
                "p.re > 0"
            } else {
                "p.errors > 0"
            },
            [],
        );
    }
    let mut search = Conditions::new();
    push_search(&mut search, &filter.search(fts_ready));
    if let Some(r) = filter.range
        && !search.is_empty()
    {
        r.push_point(&mut search, "m.ts");
    }
    c.push_group(
        "p.id IN (SELECT m.pair_id FROM dns_messages m WHERE ",
        search,
        ")",
    );
    c
}

/// Pair of the grouped table, with what `hosts` knows of both ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPairRow {
    pub id: i64,
    pub proto: String,
    pub client_ip: IpAddr,
    pub server_ip: IpAddr,
    pub messages: u64,
    pub errors: u64,
    pub names: u64,
    pub top_names: Vec<String>,
    pub first_ts: i64,
    pub last_ts: i64,
    pub client: EndpointInfo,
    pub server: EndpointInfo,
}

fn ip_at(r: &rusqlite::Row<'_>, col: usize) -> rusqlite::Result<IpAddr> {
    let text: String = r.get(col)?;
    text.parse().map_err(|e| conversion(col, e))
}

fn json_strings(text: Option<String>, col: usize) -> rusqlite::Result<Vec<String>> {
    match text {
        None => Ok(Vec::new()),
        Some(t) => serde_json::from_str(&t).map_err(|e| conversion(col, e)),
    }
}

const PAIR_FROM: &str = "dns_pairs p LEFT JOIN hosts hc ON hc.ip = p.client_ip \
    LEFT JOIN hosts hs ON hs.ip = p.server_ip";
const PAIR_SELECT: &str = "p.id, p.proto, p.client_ip, p.server_ip, p.messages, p.errors, \
    p.names, p.top_names, p.first_ts, p.last_ts, hc.country, hc.category, hc.names, \
    hs.country, hs.category, hs.names";

fn pair_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<DnsPairRow> {
    Ok(DnsPairRow {
        id: r.get(0)?,
        proto: r.get(1)?,
        client_ip: ip_at(r, 2)?,
        server_ip: ip_at(r, 3)?,
        messages: u(r.get(4)?),
        errors: u(r.get(5)?),
        names: u(r.get(6)?),
        top_names: json_strings(r.get(7)?, 7)?,
        first_ts: r.get(8)?,
        last_ts: r.get(9)?,
        client: EndpointInfo {
            country: r.get(10)?,
            category: r.get(11)?,
            names: json_strings(r.get(12)?, 12)?,
        },
        server: EndpointInfo {
            country: r.get(13)?,
            category: r.get(14)?,
            names: json_strings(r.get(15)?, 15)?,
        },
    })
}

/// Pairs with their messages (`rn`) and errors (`re`) within the range, bound to (from, to,
/// from, to), by a probe of the covering index `(pair_id, ts, ...)` of each pair: 29 ms for the
/// 2 988 pairs of the bench over six days, where grouping the messages took 1.6 s.
const RANGE_PAIRS: &str = "(SELECT p.*, \
    (SELECT count(*) FROM dns_messages m WHERE m.pair_id = p.id AND m.ts >= ? \
     AND m.ts < ?) AS rn, \
    (SELECT count(*) FROM dns_messages m WHERE m.pair_id = p.id AND m.ts >= ? \
     AND m.ts < ? AND m.is_error = 1) AS re \
    FROM dns_pairs p)";

fn range_values(r: TimeRange) -> [Value; 4] {
    let [a, b] = r.values();
    [a.clone(), b.clone(), a, b]
}

/// One page of pairs, most messages first, and the number of pairs matching the filter.
/// Under a range, a pair is listed with the messages, errors, names and times of the range.
pub fn pairs_page(
    conn: &Connection,
    filter: &DnsFilter,
    request: &PageRequest,
) -> Result<(Page<DnsPairRow>, u64)> {
    let cond = pair_conditions(filter, crate::finalize::step_done(conn, "dns")?);
    let where_sql = cond.sql();
    let Some(range) = filter.range else {
        let query = Keyset {
            from: PAIR_FROM,
            select: PAIR_SELECT,
            sort: "p.messages",
            tiebreak: "p.id",
            descending: true,
            filter: where_sql.as_deref(),
        };
        let refs = cond.params();
        let page = keyset_page(conn, &query, &refs, request, pair_row)?;
        let total = count(conn, "dns_pairs p", where_sql.as_deref(), &refs)?;
        return Ok((page, total));
    };
    let from = format!(
        "{RANGE_PAIRS} p LEFT JOIN hosts hc ON hc.ip = p.client_ip \
         LEFT JOIN hosts hs ON hs.ip = p.server_ip"
    );
    let query = Keyset {
        from: &from,
        select: RANGE_PAIR_SELECT,
        sort: "p.rn",
        tiebreak: "p.id",
        descending: true,
        filter: where_sql.as_deref(),
    };
    let bounds = range_values(range);
    let mut refs: Vec<&dyn ToSql> = bounds.iter().map(|v| v as &dyn ToSql).collect();
    refs.extend(cond.params());
    let mut page = keyset_page(conn, &query, &refs, request, pair_row)?;
    for row in &mut page.items {
        fill_range_pair(conn, row, range)?;
    }
    let total = count(
        conn,
        &format!("{RANGE_PAIRS} p"),
        where_sql.as_deref(),
        &refs,
    )?;
    Ok((page, total))
}

/// Columns of [`PAIR_SELECT`] with the counts of the range; names, top names and times are
/// filled by [`fill_range_pair`] for the rows of the page only.
const RANGE_PAIR_SELECT: &str = "p.id, p.proto, p.client_ip, p.server_ip, p.rn, p.re, \
    p.names, p.top_names, p.first_ts, p.last_ts, hc.country, hc.category, hc.names, \
    hs.country, hs.category, hs.names";

/// Distinct names, the [`TOP_NAMES`] most frequent ones and the first and last message
/// time of a pair within `range` (index `(pair_id, ts, is_error, qname)`).
fn fill_range_pair(conn: &Connection, row: &mut DnsPairRow, range: TimeRange) -> Result<()> {
    let (names, first, last): (i64, Option<i64>, Option<i64>) = conn
        .prepare_cached(
            "SELECT count(DISTINCT nullif(qname, '')), min(ts), max(ts) FROM dns_messages \
             WHERE pair_id = ?1 AND ts >= ?2 AND ts < ?3",
        )?
        .query_row(params![row.id, range.from_ns(), range.to_ns()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
    row.names = u(names);
    row.first_ts = first.unwrap_or(row.first_ts);
    row.last_ts = last.unwrap_or(row.last_ts);
    row.top_names = conn
        .prepare_cached(
            "SELECT qname FROM dns_messages WHERE pair_id = ?1 AND ts >= ?2 AND ts < ?3 \
             AND qname <> '' GROUP BY qname ORDER BY count(*) DESC, qname LIMIT ?4",
        )?
        .query_map(
            params![
                row.id,
                range.from_ns(),
                range.to_ns(),
                i64::try_from(TOP_NAMES).unwrap_or(5)
            ],
            |r| r.get(0),
        )?
        .collect::<rusqlite::Result<_>>()?;
    Ok(())
}

fn count(conn: &Connection, from: &str, cond: Option<&str>, params: &[&dyn ToSql]) -> Result<u64> {
    let sql = match cond {
        Some(cond) => format!("SELECT count(*) FROM {from} WHERE {cond}"),
        None => format!("SELECT count(*) FROM {from}"),
    };
    let n: i64 = conn.query_row(&sql, params, |r| r.get(0))?;
    Ok(u(n))
}

/// A transaction as listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessageRow {
    pub id: i64,
    pub pair_id: Option<i64>,
    pub ts: i64,
    pub flow_id: Option<i64>,
    pub transport: u8,
    pub proto: String,
    pub client_ip: String,
    pub client_port: u16,
    pub server_ip: String,
    pub server_port: u16,
    pub responder_ip: Option<String>,
    pub txid: u16,
    pub opcode: String,
    pub qname: String,
    pub qtype: String,
    pub nb_suffix: Option<u8>,
    pub flags: u16,
    pub rcode: Option<String>,
    pub latency_ns: Option<i64>,
    pub answers: Vec<DnsAnswerRow>,
    pub has_query: bool,
    pub has_response: bool,
}

const MESSAGE_SELECT: &str = "m.id, m.pair_id, m.ts, m.flow_id, m.transport, m.proto, \
    m.client_ip, m.client_port, m.server_ip, m.server_port, m.responder_ip, m.txid, m.opcode, \
    m.qname, m.qtype, m.nb_suffix, m.flags, m.rcode, m.latency_ns, m.answers, m.has_query, \
    m.has_response";

fn message_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<DnsMessageRow> {
    let answers: String = r.get(19)?;
    Ok(DnsMessageRow {
        id: r.get(0)?,
        pair_id: r.get(1)?,
        ts: r.get(2)?,
        flow_id: r.get(3)?,
        transport: r.get(4)?,
        proto: r.get(5)?,
        client_ip: r.get(6)?,
        client_port: r.get(7)?,
        server_ip: r.get(8)?,
        server_port: r.get(9)?,
        responder_ip: r.get(10)?,
        txid: r.get(11)?,
        opcode: r.get(12)?,
        qname: r.get(13)?,
        qtype: r.get(14)?,
        nb_suffix: r.get(15)?,
        flags: r.get(16)?,
        rcode: r.get(17)?,
        latency_ns: r.get(18)?,
        answers: parse_answers(&answers).map_err(|e| conversion(19, e))?,
        has_query: r.get(20)?,
        has_response: r.get(21)?,
    })
}

/// One page of transactions in time order (of one pair when `pair` is set), and the number
/// of transactions matching the filter.
pub fn messages_page(
    conn: &Connection,
    pair: Option<i64>,
    filter: &DnsFilter,
    request: &PageRequest,
) -> Result<(Page<DnsMessageRow>, u64)> {
    let cond = message_conditions(filter, pair, crate::finalize::step_done(conn, "dns")?);
    let where_sql = cond.sql();
    let query = Keyset {
        from: "dns_messages m",
        select: MESSAGE_SELECT,
        sort: "m.ts",
        tiebreak: "m.id",
        descending: false,
        filter: where_sql.as_deref(),
    };
    let refs = cond.params();
    let page = keyset_page(conn, &query, &refs, request, message_row)?;
    let total = count(conn, "dns_messages m", where_sql.as_deref(), &refs)?;
    Ok((page, total))
}

/// A server (destination of queries) with its geolocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServerRow {
    pub ip: IpAddr,
    pub messages: u64,
    pub errors: u64,
    pub clients: u64,
    /// Protocols seen, sorted.
    pub protocols: Vec<String>,
    pub host: EndpointInfo,
}

/// One page of servers, most messages first (of the messages within `range` when set).
pub fn servers_page(
    conn: &Connection,
    request: &PageRequest,
    range: Option<TimeRange>,
) -> Result<(Page<DnsServerRow>, u64)> {
    let from = match range {
        None => "(SELECT server_ip, sum(messages) AS messages, sum(errors) AS errors, \
               count(DISTINCT client_ip) AS clients, \
               (SELECT json_group_array(proto ORDER BY proto) FROM \
                 (SELECT DISTINCT proto FROM dns_pairs q WHERE q.server_ip = p.server_ip)) \
                 AS protocols \
               FROM dns_pairs p GROUP BY server_ip) s LEFT JOIN hosts h ON h.ip = s.server_ip"
            .to_owned(),
        Some(_) => format!(
            "(SELECT server_ip, sum(rn) AS messages, sum(re) AS errors, \
               count(DISTINCT client_ip) AS clients, \
               json_group_array(DISTINCT proto) AS protocols \
               FROM {RANGE_PAIRS} p WHERE p.rn > 0 GROUP BY server_ip) s \
             LEFT JOIN hosts h ON h.ip = s.server_ip"
        ),
    };
    let query = Keyset {
        from: &from,
        select: "s.server_ip, s.messages, s.errors, s.clients, s.protocols, h.country, \
                 h.category, h.names",
        sort: "s.messages",
        tiebreak: "s.server_ip",
        descending: true,
        filter: None,
    };
    let bounds = range.map(range_values);
    let refs: Vec<&dyn ToSql> = bounds.iter().flatten().map(|v| v as &dyn ToSql).collect();
    let page = keyset_page(conn, &query, &refs, request, |r| {
        let mut protocols = json_strings(r.get(4)?, 4)?;
        protocols.sort();
        Ok(DnsServerRow {
            ip: ip_at(r, 0)?,
            messages: u(r.get(1)?),
            errors: u(r.get(2)?),
            clients: u(r.get(3)?),
            protocols,
            host: EndpointInfo {
                country: r.get(5)?,
                category: r.get(6)?,
                names: json_strings(r.get(7)?, 7)?,
            },
        })
    })?;
    let total_sql = match range {
        None => "SELECT count(DISTINCT server_ip) FROM dns_pairs".to_owned(),
        Some(_) => format!("SELECT count(DISTINCT server_ip) FROM {RANGE_PAIRS} p WHERE p.rn > 0"),
    };
    let total: i64 = conn.query_row(&total_sql, refs.as_slice(), |r| r.get(0))?;
    Ok((page, u(total)))
}

#[cfg(test)]
mod tests;
