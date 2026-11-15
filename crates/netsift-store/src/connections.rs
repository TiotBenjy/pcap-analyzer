//! Tables `conversations` and `host_traffic` (migration `0400_flows.sql`): rows written by the
//! `connections` analyzer and the read queries of the Connections view.
//!
//! Merge rules (commutative, see `records.rs`): every counter is **added** (saturating at
//! `i64::MAX`), `first_ts` = min, `last_ts` = max, `protocols` = sorted union (at most
//! [`MAX_PROTOCOLS`] labels).

use std::net::IpAddr;
use std::sync::LazyLock;

use rusqlite::types::Value;
use rusqlite::{Connection, params};

use crate::error::Result;
use crate::query::{Conditions, Keyset, Page, PageRequest, keyset_page};
use crate::records::{conversion, sat};

/// Maximum number of protocol labels kept per conversation.
pub const MAX_PROTOCOLS: usize = 32;
/// Largest top N of [`top_conversations`].
pub const MAX_TOP: u32 = 200;

/// Additive delta of one conversation (client `src_ip` -> server `dst_ip`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationRow {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub first_ts: i64,
    pub last_ts: i64,
    pub bytes_fwd: u64,
    pub bytes_rev: u64,
    pub packets_fwd: u64,
    pub packets_rev: u64,
    pub flows: u64,
    pub dns_bytes_fwd: u64,
    pub dns_bytes_rev: u64,
    pub dns_flows: u64,
    /// Protocol labels (`dns`, `tls`, `tcp`...).
    pub protocols: Vec<String>,
}

/// Upsert of [`ConversationRow`]. On i64 overflow SQLite switches to REAL: `min()` brings the
/// sums back to the integer bound.
static CONVERSATION_UPSERT: LazyLock<String> = LazyLock::new(|| {
    let add = |col: &str| format!("{col} = min({col} + excluded.{col}, 9223372036854775807)");
    let sums = [
        "bytes_fwd",
        "bytes_rev",
        "packets_fwd",
        "packets_rev",
        "flows",
        "dns_bytes_fwd",
        "dns_bytes_rev",
        "dns_flows",
    ]
    .map(add)
    .join(", ");
    format!(
        "INSERT INTO conversations (src_ip, dst_ip, first_ts, last_ts, bytes_fwd, bytes_rev, \
         packets_fwd, packets_rev, flows, dns_bytes_fwd, dns_bytes_rev, dns_flows, protocols) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13) \
         ON CONFLICT (src_ip, dst_ip) DO UPDATE SET \
         first_ts = min(first_ts, excluded.first_ts), last_ts = max(last_ts, excluded.last_ts), \
         {sums}, \
         protocols = CASE WHEN excluded.protocols = '[]' THEN conversations.protocols \
         ELSE (SELECT json_group_array(value ORDER BY value) FROM (\
         SELECT value FROM json_each(conversations.protocols) UNION \
         SELECT value FROM json_each(excluded.protocols) ORDER BY 1 LIMIT {MAX_PROTOCOLS})) END"
    )
});

impl ConversationRow {
    pub(crate) fn insert(&self, conn: &Connection) -> Result<()> {
        let mut protocols: Vec<&str> = self.protocols.iter().map(String::as_str).collect();
        protocols.sort_unstable();
        protocols.dedup();
        protocols.truncate(MAX_PROTOCOLS);
        let protocols = serde_json::to_string(&protocols)?;
        conn.prepare_cached(&CONVERSATION_UPSERT)?.execute(params![
            self.src_ip.to_string(),
            self.dst_ip.to_string(),
            self.first_ts,
            self.last_ts,
            sat(self.bytes_fwd),
            sat(self.bytes_rev),
            sat(self.packets_fwd),
            sat(self.packets_rev),
            sat(self.flows),
            sat(self.dns_bytes_fwd),
            sat(self.dns_bytes_rev),
            sat(self.dns_flows),
            protocols,
        ])?;
        Ok(())
    }
}

/// Additive delta of the traffic of one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTrafficRow {
    pub ip: IpAddr,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
}

impl HostTrafficRow {
    pub(crate) fn insert(&self, conn: &Connection) -> Result<()> {
        conn.prepare_cached(
            "INSERT INTO host_traffic (ip, bytes_sent, bytes_received, packets_sent, \
             packets_received) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT (ip) DO UPDATE SET \
             bytes_sent = min(bytes_sent + excluded.bytes_sent, 9223372036854775807), \
             bytes_received = min(bytes_received + excluded.bytes_received, 9223372036854775807), \
             packets_sent = min(packets_sent + excluded.packets_sent, 9223372036854775807), \
             packets_received = min(packets_received + excluded.packets_received, 9223372036854775807)",
        )?
        .execute(params![
            self.ip.to_string(),
            sat(self.bytes_sent),
            sat(self.bytes_received),
            sat(self.packets_sent),
            sat(self.packets_received),
        ])?;
        Ok(())
    }
}

/// What the `hosts` table knows about an endpoint (absent when the host was never seen).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EndpointInfo {
    pub names: Vec<String>,
    pub category: Option<String>,
    pub country: Option<String>,
}

/// A stored conversation with what is known about both ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationEntry {
    pub id: i64,
    pub row: ConversationRow,
    pub src: EndpointInfo,
    pub dst: EndpointInfo,
}

/// Sort keys of the conversations table (whitelist).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationSort {
    Bytes,
    Packets,
    Flows,
    FirstTs,
    LastTs,
}

impl ConversationSort {
    fn expr(self) -> &'static str {
        match self {
            Self::Bytes => "c.bytes_total",
            Self::Packets => "c.packets_total",
            Self::Flows => "c.flows",
            Self::FirstTs => "c.first_ts",
            Self::LastTs => "c.last_ts",
        }
    }
}

/// Filters of the conversations table; `None` = no filter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConversationFilter {
    /// Substring of the client IP or of one of its names (case-insensitive).
    pub from: Option<String>,
    /// Same for the server.
    pub to: Option<String>,
    /// Protocol label carried by at least one flow of the conversation.
    pub protocol: Option<String>,
    /// Address categories: at least one end must be in one of them.
    pub categories: Option<Vec<String>>,
}

const CONVERSATION_FROM: &str = "conversations c \
    LEFT JOIN hosts hs ON hs.ip = c.src_ip LEFT JOIN hosts hd ON hd.ip = c.dst_ip";

const CONVERSATION_SELECT: &str = "c.id, c.src_ip, c.dst_ip, c.first_ts, c.last_ts, \
    c.bytes_fwd, c.bytes_rev, c.packets_fwd, c.packets_rev, c.flows, c.dns_bytes_fwd, \
    c.dns_bytes_rev, c.dns_flows, c.protocols, hs.names, hs.category, hs.country, hd.names, \
    hd.category, hd.country";

/// How the category filter finds its conversations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CategoryPlan {
    /// Hosts of the categories listed once, each conversation checked against the lists while
    /// scanning in sort order (`+`: no index). The only plan before the step `connections`.
    Lists,
    /// Each conversation checked by a primary key search in `hosts`, scanning in sort order: a
    /// page stops after a few rows when the categories match many conversations (P4.8).
    Probe,
    /// Conversations of the hosts of the categories found by index, then sorted: when the
    /// categories match few conversations (P4.8).
    Lookup,
}

/// The active filters of [`ConversationFilter`], on `c` (`conversations`) only: they are
/// evaluated before the joins with `hosts`, and the count needs no join at all (P4.2). Host
/// names and categories are looked up in `hosts` once per query, by sub-query.
fn conditions(filter: &ConversationFilter) -> Result<Conditions> {
    conditions_with(filter, CategoryPlan::Lists)
}

fn conditions_with(filter: &ConversationFilter, plan: CategoryPlan) -> Result<Conditions> {
    let mut c = Conditions::new();
    if let Some(from) = text_filter(filter.from.as_ref()) {
        c.push(
            "instr(c.src_ip, ?) > 0 \
             OR c.src_ip IN (SELECT ip FROM hosts WHERE instr(lower(names), ?) > 0)",
            [Value::Text(from.clone()), Value::Text(from)],
        );
    }
    if let Some(to) = text_filter(filter.to.as_ref()) {
        c.push(
            "instr(c.dst_ip, ?) > 0 \
             OR c.dst_ip IN (SELECT ip FROM hosts WHERE instr(lower(names), ?) > 0)",
            [Value::Text(to.clone()), Value::Text(to)],
        );
    }
    if let Some(protocol) = &filter.protocol {
        c.push(
            "EXISTS (SELECT 1 FROM json_each(c.protocols) WHERE value = ?)",
            [Value::Text(protocol.clone())],
        );
    }
    if let Some(categories) = json_list(filter.categories.as_deref())? {
        let sql = match plan {
            // `+`: no index for these terms. A category matches a large part of the hosts;
            // looking up their conversations one by one in two indexes (multi-index OR) took 2 s
            // for the first page, against a scan in sort order that stops at the page size.
            CategoryPlan::Lists => {
                "+c.src_ip IN (SELECT ip FROM hosts WHERE category IN (SELECT value FROM json_each(?))) \
                 OR +c.dst_ip IN (SELECT ip FROM hosts WHERE category IN (SELECT value FROM json_each(?)))"
            }
            CategoryPlan::Probe => {
                "EXISTS (SELECT 1 FROM hosts h WHERE h.ip = c.src_ip \
                         AND h.category IN (SELECT value FROM json_each(?))) \
                 OR EXISTS (SELECT 1 FROM hosts h WHERE h.ip = c.dst_ip \
                            AND h.category IN (SELECT value FROM json_each(?)))"
            }
            CategoryPlan::Lookup => {
                "c.src_ip IN (SELECT ip FROM hosts WHERE category IN (SELECT value FROM json_each(?))) \
                 OR c.dst_ip IN (SELECT ip FROM hosts WHERE category IN (SELECT value FROM json_each(?)))"
            }
        };
        c.push(
            sql,
            [Value::Text(categories.clone()), Value::Text(categories)],
        );
    }
    Ok(c)
}

/// End-of-import step `connections` ([`crate::finalize::SESSION_FINALIZERS`]): counts the
/// conversations per pair of categories of their ends into `conversation_categories`, in the
/// transaction of the caller. One pass over `conversations` in storage order, ends found by
/// primary key; the counts are kept in memory (one entry per pair of categories). Idempotent.
pub(crate) fn finalize(conn: &Connection) -> Result<()> {
    let mut counts: std::collections::BTreeMap<(String, String), i64> =
        std::collections::BTreeMap::new();
    {
        let mut stmt = conn.prepare(
            "SELECT coalesce(hs.category, ''), coalesce(hd.category, '') FROM conversations c \
             LEFT JOIN hosts hs ON hs.ip = c.src_ip LEFT JOIN hosts hd ON hd.ip = c.dst_ip",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            *counts.entry((r.get(0)?, r.get(1)?)).or_insert(0) += 1;
        }
    }
    conn.execute("DELETE FROM conversation_categories", [])?;
    let mut insert = conn.prepare(
        "INSERT INTO conversation_categories (src_category, dst_category, conversations) \
         VALUES (?1, ?2, ?3)",
    )?;
    for ((src, dst), n) in counts {
        insert.execute(params![src, dst, n])?;
    }
    Ok(())
}

/// Conversations with an end in one of `categories`, and all conversations, from the counts of
/// the step `connections`; `None` while it has not run.
fn category_counts(conn: &Connection, categories: &str) -> Result<Option<(u64, u64)>> {
    if !crate::finalize::step_done(conn, "connections")? {
        return Ok(None);
    }
    let (matched, total): (i64, i64) = conn.query_row(
        "SELECT coalesce(sum(conversations) FILTER (WHERE src_category IN \
                    (SELECT value FROM json_each(?1)) OR dst_category IN \
                    (SELECT value FROM json_each(?1))), 0), \
                coalesce(sum(conversations), 0) \
         FROM conversation_categories",
        [categories],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(Some((
        u64::try_from(matched).unwrap_or(0),
        u64::try_from(total).unwrap_or(0),
    )))
}

/// Plan of the category filter for a page of `limit` rows: a scan in sort order reads about
/// `limit * total / matched` conversations before filling the page, a lookup reads the `matched`
/// ones (then sorts them); the cheaper one wins, from the counts of the step `connections`.
fn category_plan(
    conn: &Connection,
    filter: &ConversationFilter,
    limit: u32,
) -> Result<CategoryPlan> {
    let Some(categories) = json_list(filter.categories.as_deref())? else {
        return Ok(CategoryPlan::Lists);
    };
    Ok(match category_counts(conn, &categories)? {
        None => CategoryPlan::Lists,
        Some((matched, total)) => {
            if u128::from(matched) * u128::from(matched)
                >= u128::from(limit).saturating_add(1) * u128::from(total)
            {
                CategoryPlan::Probe
            } else {
                CategoryPlan::Lookup
            }
        }
    })
}

fn json_list(values: Option<&[String]>) -> Result<Option<String>> {
    Ok(values.map(serde_json::to_string).transpose()?)
}

fn text_filter(v: Option<&String>) -> Option<String> {
    v.map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty())
}

fn json_strings(raw: Option<String>, col: usize) -> rusqlite::Result<Vec<String>> {
    match raw {
        None => Ok(Vec::new()),
        Some(raw) => serde_json::from_str(&raw).map_err(|e| conversion(col, e)),
    }
}

fn ip(raw: &str, col: usize) -> rusqlite::Result<IpAddr> {
    raw.parse().map_err(|e| conversion(col, e))
}

fn conversation_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<ConversationEntry> {
    let src: String = r.get(1)?;
    let dst: String = r.get(2)?;
    Ok(ConversationEntry {
        id: r.get(0)?,
        row: ConversationRow {
            src_ip: ip(&src, 1)?,
            dst_ip: ip(&dst, 2)?,
            first_ts: r.get(3)?,
            last_ts: r.get(4)?,
            bytes_fwd: r.get(5)?,
            bytes_rev: r.get(6)?,
            packets_fwd: r.get(7)?,
            packets_rev: r.get(8)?,
            flows: r.get(9)?,
            dns_bytes_fwd: r.get(10)?,
            dns_bytes_rev: r.get(11)?,
            dns_flows: r.get(12)?,
            protocols: json_strings(r.get(13)?, 13)?,
        },
        src: EndpointInfo {
            names: json_strings(r.get(14)?, 14)?,
            category: r.get(15)?,
            country: r.get(16)?,
        },
        dst: EndpointInfo {
            names: json_strings(r.get(17)?, 17)?,
            category: r.get(18)?,
            country: r.get(19)?,
        },
    })
}

/// One page of conversations, sorted by `sort` then id.
pub fn conversations_page(
    conn: &Connection,
    filter: &ConversationFilter,
    sort: ConversationSort,
    descending: bool,
    request: &PageRequest,
) -> Result<Page<ConversationEntry>> {
    let plan = category_plan(conn, filter, request.effective_limit())?;
    page_with(conn, filter, sort, descending, request, plan)
}

fn page_with(
    conn: &Connection,
    filter: &ConversationFilter,
    sort: ConversationSort,
    descending: bool,
    request: &PageRequest,
    plan: CategoryPlan,
) -> Result<Page<ConversationEntry>> {
    let conditions = conditions_with(filter, plan)?;
    let where_sql = conditions.sql();
    let query = Keyset {
        from: CONVERSATION_FROM,
        select: CONVERSATION_SELECT,
        sort: sort.expr(),
        tiebreak: "c.id",
        descending,
        filter: where_sql.as_deref(),
    };
    keyset_page(
        conn,
        &query,
        &conditions.params(),
        request,
        conversation_entry,
    )
}

/// Client and server of the conversation with this id, if any.
pub fn conversation_ends(conn: &Connection, id: i64) -> Result<Option<(IpAddr, IpAddr)>> {
    use rusqlite::OptionalExtension as _;
    let ends: Option<(String, String)> = conn
        .query_row(
            "SELECT src_ip, dst_ip FROM conversations WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match ends {
        None => Ok(None),
        Some((src, dst)) => Ok(Some((ip(&src, 0)?, ip(&dst, 1)?))),
    }
}

/// Number of conversations matching `filter`. A category filter alone is answered from the
/// counts of the step `connections` (P4.8).
pub fn count_conversations(conn: &Connection, filter: &ConversationFilter) -> Result<u64> {
    let only_categories = ConversationFilter {
        categories: filter.categories.clone(),
        ..ConversationFilter::default()
    };
    if *filter == only_categories
        && let Some(categories) = json_list(filter.categories.as_deref())?
        && let Some((matched, _)) = category_counts(conn, &categories)?
    {
        return Ok(matched);
    }
    count_at_read_time(conn, filter)
}

fn count_at_read_time(conn: &Connection, filter: &ConversationFilter) -> Result<u64> {
    let conditions = conditions(filter)?;
    let sql = match conditions.sql() {
        Some(w) => format!("SELECT count(*) FROM conversations c WHERE {w}"),
        None => "SELECT count(*) FROM conversations c".to_owned(),
    };
    let n: i64 = conn.query_row(&sql, conditions.params().as_slice(), |r| r.get(0))?;
    Ok(u64::try_from(n).unwrap_or(0))
}

/// The `n` conversations with the most bytes (at most [`MAX_TOP`]), without DNS flows when
/// `exclude_dns` (their DNS bytes are then subtracted, and conversations left empty skipped).
pub fn top_conversations(
    conn: &Connection,
    n: u32,
    exclude_dns: bool,
) -> Result<Vec<ConversationEntry>> {
    let order = if exclude_dns {
        "(c.bytes_fwd + c.bytes_rev - c.dns_bytes_fwd - c.dns_bytes_rev)"
    } else {
        "c.bytes_total"
    };
    let sql = format!(
        "SELECT {CONVERSATION_SELECT} FROM {CONVERSATION_FROM} WHERE {order} > 0 \
         ORDER BY {order} DESC, c.id DESC LIMIT ?1"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([i64::from(n.min(MAX_TOP))], conversation_entry)?;
    let mut out = Vec::new();
    for row in rows {
        let mut entry = row?;
        if exclude_dns {
            let r = &mut entry.row;
            r.bytes_fwd = r.bytes_fwd.saturating_sub(r.dns_bytes_fwd);
            r.bytes_rev = r.bytes_rev.saturating_sub(r.dns_bytes_rev);
            r.flows = r.flows.saturating_sub(r.dns_flows);
            r.protocols.retain(|p| p != "dns");
        }
        out.push(entry);
    }
    Ok(out)
}

/// Direction of the traffic of a host, for [`country_traffic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficSide {
    /// Bytes sent by the host (sources of downloads).
    Sent,
    /// Bytes received by the host (destinations).
    Received,
}

/// Traffic of the hosts of one country.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountryTraffic {
    /// ISO 3166-1 alpha-2 code; `None` for hosts without country.
    pub country: Option<String>,
    /// For hosts without country: true when the address is public (country unknown), false
    /// for private, local and reserved addresses (never geolocated).
    pub public: bool,
    pub bytes: u64,
    pub hosts: u64,
}

/// Bytes sent (or received) per country of the host (`total()`: no integer overflow error,
/// saturated at `i64::MAX`), largest first (bounded by the number
/// of countries, plus the two groups of hosts without country).
pub fn country_traffic(conn: &Connection, side: TrafficSide) -> Result<Vec<CountryTraffic>> {
    let col = match side {
        TrafficSide::Sent => "t.bytes_sent",
        TrafficSide::Received => "t.bytes_received",
    };
    let sql = format!(
        "SELECT h.country, coalesce(h.category, '') = 'public' AS public, \
         CAST(min(total({col}), 9223372036854775807.0) AS INTEGER), count(*) \
         FROM host_traffic t LEFT JOIN hosts h ON h.ip = t.ip WHERE {col} > 0 \
         GROUP BY h.country, public"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |r| {
        let country: Option<String> = r.get(0)?;
        let public: bool = r.get(1)?;
        Ok(CountryTraffic {
            // A country is only ever set on public addresses.
            public: public || country.is_some(),
            country,
            bytes: r.get(2)?,
            hosts: r.get(3)?,
        })
    })?;
    fold_countries(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Bytes sent and received per country of the host, as two calls of [`country_traffic`] but in
/// one pass over `host_traffic` (P4.8: the Connections statistics read both).
pub fn country_traffic_both(
    conn: &Connection,
) -> Result<(Vec<CountryTraffic>, Vec<CountryTraffic>)> {
    let mut stmt = conn.prepare(
        "SELECT h.country, coalesce(h.category, '') = 'public' AS public, \
         CAST(min(total(t.bytes_sent), 9223372036854775807.0) AS INTEGER), \
         count(*) FILTER (WHERE t.bytes_sent > 0), \
         CAST(min(total(t.bytes_received), 9223372036854775807.0) AS INTEGER), \
         count(*) FILTER (WHERE t.bytes_received > 0) \
         FROM host_traffic t LEFT JOIN hosts h ON h.ip = t.ip \
         WHERE t.bytes_sent > 0 OR t.bytes_received > 0 \
         GROUP BY h.country, public",
    )?;
    let mut sent = Vec::new();
    let mut received = Vec::new();
    let mut rows = stmt.query([])?;
    while let Some(r) = rows.next()? {
        let country: Option<String> = r.get(0)?;
        // A country is only ever set on public addresses.
        let public = r.get::<_, bool>(1)? || country.is_some();
        for (side, bytes, hosts) in [(&mut sent, 2, 3), (&mut received, 4, 5)] {
            let hosts: u64 = r.get(hosts)?;
            if hosts > 0 {
                side.push(CountryTraffic {
                    country: country.clone(),
                    public,
                    bytes: r.get(bytes)?,
                    hosts,
                });
            }
        }
    }
    Ok((fold_countries(sent)?, fold_countries(received)?))
}

/// Groups of hosts with a country merged by country, largest first.
fn fold_countries(rows: Vec<CountryTraffic>) -> Result<Vec<CountryTraffic>> {
    let mut out: Vec<CountryTraffic> = Vec::new();
    for row in rows {
        // Hosts with a country are grouped by country whatever their category.
        match out
            .iter_mut()
            .find(|c| c.country.is_some() && c.country == row.country)
        {
            Some(known) => {
                known.bytes = known.bytes.saturating_add(row.bytes);
                known.hosts = known.hosts.saturating_add(row.hosts);
            }
            None => out.push(row),
        }
    }
    out.sort_by(|a, b| {
        b.bytes
            .cmp(&a.bytes)
            .then_with(|| a.country.cmp(&b.country))
            .then(a.public.cmp(&b.public))
    });
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests;
