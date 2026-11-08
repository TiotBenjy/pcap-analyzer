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
use crate::query::{Keyset, Page, PageRequest, keyset_page};
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

fn buckets(conn: &Connection, sql: &str) -> Result<Vec<Bucket>> {
    Ok(conn
        .prepare(sql)?
        .query_map([], |r| {
            Ok(Bucket {
                key: r.get(0)?,
                count: u(r.get(1)?),
            })
        })?
        .collect::<rusqlite::Result<_>>()?)
}

/// Keeps the `n` largest buckets (already sorted) and sums the rest.
fn top(mut all: Vec<Bucket>, n: usize) -> (Vec<Bucket>, u64) {
    let rest = all.split_off(n.min(all.len()));
    (all, rest.iter().map(|b| b.count).sum())
}

/// Statistics of the whole session.
pub fn stats(conn: &Connection) -> Result<DnsStats> {
    let (total, errors, answered): (i64, i64, i64) = conn.query_row(
        "SELECT count(*), coalesce(sum(is_error), 0), \
         coalesce(sum(has_response AND has_query), 0) FROM dns_messages",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let protocols = buckets(
        conn,
        "SELECT proto, count(*) FROM dns_messages GROUP BY proto ORDER BY 2 DESC, 1",
    )?;
    let protocol_errors = buckets(
        conn,
        "SELECT proto, count(*) FROM dns_messages WHERE is_error = 1 GROUP BY proto \
         ORDER BY 2 DESC, 1",
    )?;
    let (rcodes, rcode_other) = top(
        buckets(
            conn,
            "SELECT rcode, count(*) FROM dns_messages GROUP BY rcode ORDER BY 2 DESC, 1",
        )?,
        STATS_TOP,
    );
    let (qtypes, qtype_other) = top(
        buckets(
            conn,
            "SELECT qtype, count(*) FROM dns_messages WHERE qtype <> '' AND has_query = 1 \
             GROUP BY qtype ORDER BY 2 DESC, 1",
        )?,
        STATS_TOP,
    );
    let mut countries: Vec<CountryBucket> = conn
        .prepare(
            "SELECT h.country, count(DISTINCT p.server_ip), sum(p.messages) \
             FROM dns_pairs p LEFT JOIN hosts h ON h.ip = p.server_ip \
             GROUP BY h.country ORDER BY 3 DESC, 1",
        )?
        .query_map([], |r| {
            Ok(CountryBucket {
                country: r.get(0)?,
                servers: u(r.get(1)?),
                messages: u(r.get(2)?),
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    let unknown_pos = countries.iter().position(|c| c.country.is_none());
    let country_unknown = unknown_pos.map_or_else(CountryBucket::default, |i| countries.remove(i));
    countries.truncate(STATS_TOP);
    let (latency_p50_ns, latency_p95_ns) = latency_percentiles(conn, answered)?;
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

fn latency_percentiles(conn: &Connection, answered: i64) -> Result<(Option<i64>, Option<i64>)> {
    if answered <= 0 {
        return Ok((None, None));
    }
    let n: i64 = conn.query_row(
        "SELECT count(*) FROM dns_messages WHERE latency_ns IS NOT NULL",
        [],
        |r| r.get(0),
    )?;
    if n == 0 {
        return Ok((None, None));
    }
    let mut stmt = conn.prepare(
        "SELECT latency_ns FROM dns_messages WHERE latency_ns IS NOT NULL \
         ORDER BY latency_ns LIMIT 1 OFFSET ?1",
    )?;
    let mut at = |percent: i64| -> Result<Option<i64>> {
        let offset = n.saturating_sub(1).saturating_mul(percent) / 100;
        Ok(stmt.query_row([offset], |r| r.get(0)).optional()?)
    };
    let p50 = at(50)?;
    let p95 = at(95)?;
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
}

impl Default for DnsFilter {
    fn default() -> Self {
        Self {
            protocols: ["dns", "mdns", "llmnr", "nbns"].map(str::to_owned).to_vec(),
            errors_only: false,
            search: None,
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

    fn search(&self) -> Search {
        let Some(q) = self
            .search
            .as_deref()
            .map(str::trim)
            .filter(|q| !q.is_empty())
        else {
            return Search::None;
        };
        if q.chars().count() >= 3 {
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

/// Builds the positional parameters: filters first, in the order of the SQL text.
fn filter_params(filter: &DnsFilter, pair: Option<i64>) -> (Vec<Value>, Search) {
    let mut params = Vec::new();
    if let Some(p) = pair {
        params.push(Value::Integer(p));
    }
    params.push(Value::Text(filter.protocol_list()));
    params.push(Value::Integer(i64::from(filter.errors_only)));
    let search = filter.search();
    match &search {
        Search::None => {}
        Search::Fts(q) => params.push(Value::Text(q.clone())),
        Search::Like(q) => {
            for _ in 0..4 {
                params.push(Value::Text(q.clone()));
            }
        }
    }
    (params, search)
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

macro_rules! pair_filter {
    ($search:expr) => {
        concat!(
            "instr(?, ',' || p.proto || ',') > 0 AND (? = 0 OR p.errors > 0)",
            $search
        )
    };
}
const PAIR_FILTER: &str = pair_filter!("");
const PAIR_FILTER_FTS: &str = pair_filter!(concat!(
    " AND p.id IN (SELECT m.pair_id FROM dns_messages m WHERE ",
    fts_cond!(),
    ")"
));
const PAIR_FILTER_LIKE: &str = pair_filter!(concat!(
    " AND p.id IN (SELECT m.pair_id FROM dns_messages m WHERE ",
    like_cond!(),
    ")"
));

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

/// One page of pairs, most messages first, and the number of pairs matching the filter.
pub fn pairs_page(
    conn: &Connection,
    filter: &DnsFilter,
    request: &PageRequest,
) -> Result<(Page<DnsPairRow>, u64)> {
    let (params, search) = filter_params(filter, None);
    let cond: &'static str = match search {
        Search::None => PAIR_FILTER,
        Search::Fts(_) => PAIR_FILTER_FTS,
        Search::Like(_) => PAIR_FILTER_LIKE,
    };
    let query = Keyset {
        from: PAIR_FROM,
        select: PAIR_SELECT,
        sort: "p.messages",
        tiebreak: "p.id",
        descending: true,
        filter: Some(cond),
    };
    let refs: Vec<&dyn ToSql> = params.iter().map(|v| v as &dyn ToSql).collect();
    let page = keyset_page(conn, &query, &refs, request, pair_row)?;
    let total = count(conn, "dns_pairs p", cond, &refs)?;
    Ok((page, total))
}

fn count(conn: &Connection, from: &str, cond: &str, params: &[&dyn ToSql]) -> Result<u64> {
    let n: i64 = conn.query_row(
        &format!("SELECT count(*) FROM {from} WHERE {cond}"),
        params,
        |r| r.get(0),
    )?;
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

macro_rules! message_filter {
    ($pair:expr, $search:expr) => {
        concat!(
            $pair,
            "instr(?, ',' || m.proto || ',') > 0 AND (? = 0 OR m.is_error = 1)",
            $search
        )
    };
}
const MSG_ALL: &str = message_filter!("", "");
const MSG_ALL_FTS: &str = message_filter!("", concat!(" AND ", fts_cond!()));
const MSG_ALL_LIKE: &str = message_filter!("", concat!(" AND ", like_cond!()));
const MSG_PAIR: &str = message_filter!("m.pair_id = ? AND ", "");
const MSG_PAIR_FTS: &str = message_filter!("m.pair_id = ? AND ", concat!(" AND ", fts_cond!()));
const MSG_PAIR_LIKE: &str = message_filter!("m.pair_id = ? AND ", concat!(" AND ", like_cond!()));

/// One page of transactions in time order (of one pair when `pair` is set), and the number
/// of transactions matching the filter.
pub fn messages_page(
    conn: &Connection,
    pair: Option<i64>,
    filter: &DnsFilter,
    request: &PageRequest,
) -> Result<(Page<DnsMessageRow>, u64)> {
    let (params, search) = filter_params(filter, pair);
    let cond: &'static str = match (pair.is_some(), search) {
        (false, Search::None) => MSG_ALL,
        (false, Search::Fts(_)) => MSG_ALL_FTS,
        (false, Search::Like(_)) => MSG_ALL_LIKE,
        (true, Search::None) => MSG_PAIR,
        (true, Search::Fts(_)) => MSG_PAIR_FTS,
        (true, Search::Like(_)) => MSG_PAIR_LIKE,
    };
    let query = Keyset {
        from: "dns_messages m",
        select: MESSAGE_SELECT,
        sort: "m.ts",
        tiebreak: "m.id",
        descending: false,
        filter: Some(cond),
    };
    let refs: Vec<&dyn ToSql> = params.iter().map(|v| v as &dyn ToSql).collect();
    let page = keyset_page(conn, &query, &refs, request, message_row)?;
    let total = count(conn, "dns_messages m", cond, &refs)?;
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

/// One page of servers, most messages first.
pub fn servers_page(conn: &Connection, request: &PageRequest) -> Result<(Page<DnsServerRow>, u64)> {
    let query = Keyset {
        from: "(SELECT server_ip, sum(messages) AS messages, sum(errors) AS errors, \
               count(DISTINCT client_ip) AS clients, \
               (SELECT json_group_array(proto ORDER BY proto) FROM \
                 (SELECT DISTINCT proto FROM dns_pairs q WHERE q.server_ip = p.server_ip)) \
                 AS protocols \
               FROM dns_pairs p GROUP BY server_ip) s LEFT JOIN hosts h ON h.ip = s.server_ip",
        select: "s.server_ip, s.messages, s.errors, s.clients, s.protocols, h.country, \
                 h.category, h.names",
        sort: "s.messages",
        tiebreak: "s.server_ip",
        descending: true,
        filter: None,
    };
    let page = keyset_page(conn, &query, &[], request, |r| {
        Ok(DnsServerRow {
            ip: ip_at(r, 0)?,
            messages: u(r.get(1)?),
            errors: u(r.get(2)?),
            clients: u(r.get(3)?),
            protocols: json_strings(r.get(4)?, 4)?,
            host: EndpointInfo {
                country: r.get(5)?,
                category: r.get(6)?,
                names: json_strings(r.get(7)?, 7)?,
            },
        })
    })?;
    let total: i64 =
        conn.query_row("SELECT count(DISTINCT server_ip) FROM dns_pairs", [], |r| {
            r.get(0)
        })?;
    Ok((page, u(total)))
}

#[cfg(test)]
mod tests;
