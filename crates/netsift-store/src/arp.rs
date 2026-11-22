//! Rows and read queries of the ARP analyzer (`arp_messages`, `arp_bindings`,
//! `docs/specs/arp.md`).
//!
//! Time range (ADR-030): messages are point records (`ts`); bindings are folded rows (their span
//! overlaps the range, their counters stay those of the session).

use std::collections::BTreeMap;
use std::net::IpAddr;

use rusqlite::types::Value;
use rusqlite::{Connection, ToSql, params};

use crate::connections::EndpointInfo;
use crate::error::Result;
use crate::query::{Conditions, Keyset, Page, PageRequest, keyset_page};
use crate::range::{PointSql, TimeRange, and_overlap, query_ranged, query_row_ranged};
use crate::records::{conversion, format_mac};

/// Message types, in display order (`arp_messages.kind`).
pub const KINDS: [&str; 5] = ["request", "reply", "gratuitous", "probe", "other"];

fn count(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn ip(raw: &str, col: usize) -> rusqlite::Result<IpAddr> {
    raw.parse().map_err(|e| conversion(col, e))
}

fn opt_ip(raw: Option<String>, col: usize) -> rusqlite::Result<Option<IpAddr>> {
    raw.map(|r| ip(&r, col)).transpose()
}

fn endpoint(r: &rusqlite::Row<'_>, first: usize) -> rusqlite::Result<EndpointInfo> {
    let names: Option<String> = r.get(first)?;
    Ok(EndpointInfo {
        names: match names {
            None => Vec::new(),
            Some(raw) => serde_json::from_str(&raw).map_err(|e| conversion(first, e))?,
        },
        category: r.get(first + 1)?,
        country: r.get(first + 2)?,
    })
}

/// One ARP packet emitted by the analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpRow {
    pub ts: i64,
    pub frame: u64,
    pub operation: u16,
    /// One of [`KINDS`].
    pub kind: &'static str,
    pub sender_mac: Option<[u8; 6]>,
    pub sender_ip: Option<IpAddr>,
    pub target_mac: Option<[u8; 6]>,
    pub target_ip: Option<IpAddr>,
    pub unsolicited: bool,
    /// Counted in `arp_bindings` (sender IP and MAC both set).
    pub binds: bool,
}

impl ArpRow {
    /// Inserts the message, and folds it into its binding when it announces one (commutative).
    pub(crate) fn insert(&self, conn: &Connection) -> Result<()> {
        let sender_mac = self.sender_mac.map(format_mac);
        let sender_ip = self.sender_ip.map(|i| i.to_string());
        let binding = match (&sender_ip, &sender_mac) {
            (Some(ip), Some(mac)) if self.binds => Some((ip, mac)),
            _ => None,
        };
        conn.prepare_cached(
            "INSERT INTO arp_messages (ts, frame, operation, kind, sender_mac, sender_ip, \
             target_mac, target_ip, unsolicited, binds) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )?
        .execute(params![
            self.ts,
            i64::try_from(self.frame).unwrap_or(i64::MAX),
            self.operation,
            self.kind,
            sender_mac,
            sender_ip,
            self.target_mac.map(format_mac),
            self.target_ip.map(|i| i.to_string()),
            self.unsolicited,
            binding.is_some(),
        ])?;
        if let Some((ip, mac)) = binding {
            conn.prepare_cached(
                "INSERT INTO arp_bindings (ip, mac, first_ts, last_ts, messages, requests, \
                 replies, gratuitous, unsolicited) VALUES (?1, ?2, ?3, ?3, 1, ?4, ?5, ?6, ?7) \
                 ON CONFLICT (ip, mac) DO UPDATE SET \
                 first_ts = min(arp_bindings.first_ts, excluded.first_ts), \
                 last_ts = max(arp_bindings.last_ts, excluded.last_ts), \
                 messages = arp_bindings.messages + 1, \
                 requests = arp_bindings.requests + excluded.requests, \
                 replies = arp_bindings.replies + excluded.replies, \
                 gratuitous = arp_bindings.gratuitous + excluded.gratuitous, \
                 unsolicited = arp_bindings.unsolicited + excluded.unsolicited",
            )?
            .execute(params![
                ip,
                mac,
                self.ts,
                self.kind == "request",
                self.kind == "reply",
                self.kind == "gratuitous",
                self.unsolicited,
            ])?;
        }
        Ok(())
    }
}

// --- messages ---------------------------------------------------------------------------------

/// Filters of the message list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageFilters {
    /// Types kept (any of [`KINDS`]); all when empty.
    pub kinds: Vec<String>,
    /// Sender or target address.
    pub ip: Option<IpAddr>,
    /// Sender MAC address (lower-case colon text).
    pub mac: Option<String>,
    /// Unsolicited replies only.
    pub unsolicited: bool,
}

impl MessageFilters {
    fn conditions(&self, range: Option<TimeRange>) -> Conditions {
        let mut c = Conditions::new();
        if !self.kinds.is_empty() {
            let marks = vec!["?"; self.kinds.len()].join(", ");
            c.push_owned(
                format!("m.kind IN ({marks})"),
                self.kinds.iter().map(|k| Value::Text(k.clone())),
            );
        }
        if let Some(ip) = self.ip {
            let text = ip.to_string();
            c.push(
                "m.sender_ip = ? OR m.target_ip = ?",
                [Value::Text(text.clone()), Value::Text(text)],
            );
        }
        if let Some(mac) = &self.mac {
            c.push("m.sender_mac = ?", [Value::Text(mac.clone())]);
        }
        if self.unsolicited {
            c.push("m.unsolicited = 1", []);
        }
        if let Some(r) = range {
            r.push_point(&mut c, "m.ts");
        }
        c
    }
}

/// One message with what the session knows about both addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpMessageEntry {
    pub id: i64,
    pub ts: i64,
    pub operation: u16,
    pub kind: String,
    pub sender_mac: Option<String>,
    pub sender_ip: Option<IpAddr>,
    pub target_mac: Option<String>,
    pub target_ip: Option<IpAddr>,
    pub unsolicited: bool,
    pub sender: EndpointInfo,
    pub target: EndpointInfo,
}

const MESSAGE_FROM: &str = "arp_messages m \
    LEFT JOIN hosts hs ON hs.ip = m.sender_ip LEFT JOIN hosts ht ON ht.ip = m.target_ip";
const MESSAGE_SELECT: &str = "m.id, m.ts, m.operation, m.kind, m.sender_mac, m.sender_ip, \
    m.target_mac, m.target_ip, m.unsolicited, hs.names, hs.category, hs.country, ht.names, \
    ht.category, ht.country";

fn message_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<ArpMessageEntry> {
    Ok(ArpMessageEntry {
        id: r.get(0)?,
        ts: r.get(1)?,
        operation: r.get(2)?,
        kind: r.get(3)?,
        sender_mac: r.get(4)?,
        sender_ip: opt_ip(r.get(5)?, 5)?,
        target_mac: r.get(6)?,
        target_ip: opt_ip(r.get(7)?, 7)?,
        unsolicited: r.get(8)?,
        sender: endpoint(r, 9)?,
        target: endpoint(r, 12)?,
    })
}

/// One page of messages in time order.
pub fn messages_page(
    conn: &Connection,
    filters: &MessageFilters,
    request: &PageRequest,
    range: Option<TimeRange>,
) -> Result<Page<ArpMessageEntry>> {
    let c = filters.conditions(range);
    let where_sql = c.sql();
    let query = Keyset {
        from: MESSAGE_FROM,
        select: MESSAGE_SELECT,
        sort: "m.ts",
        tiebreak: "m.id",
        descending: false,
        filter: where_sql.as_deref(),
    };
    keyset_page(conn, &query, &c.params(), request, message_entry)
}

/// Number of messages matching `filters` (within `range` when set).
pub fn count_messages(
    conn: &Connection,
    filters: &MessageFilters,
    range: Option<TimeRange>,
) -> Result<u64> {
    let c = filters.conditions(range);
    let where_sql = c.sql().map(|w| format!(" WHERE {w}")).unwrap_or_default();
    let n: i64 = conn.query_row(
        &format!("SELECT count(*) FROM arp_messages m{where_sql}"),
        c.params().as_slice(),
        |r| r.get(0),
    )?;
    Ok(count(n))
}

/// Messages per type, plus unsolicited replies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KindCounts {
    /// Count per type of [`KINDS`] (absent types: 0).
    pub kinds: BTreeMap<String, u64>,
    pub unsolicited: u64,
}

impl KindCounts {
    pub fn get(&self, kind: &str) -> u64 {
        self.kinds.get(kind).copied().unwrap_or(0)
    }

    pub fn total(&self) -> u64 {
        self.kinds.values().sum()
    }
}

/// Messages per type within `range` (covering index `(kind, unsolicited, ts)`).
pub fn kind_counts(conn: &Connection, range: Option<TimeRange>) -> Result<KindCounts> {
    let point = PointSql::new(conn, "arp_messages", "ts", range)?;
    let rows = query_ranged(
        conn,
        &format!(
            "SELECT kind, unsolicited, count(*) FROM arp_messages{} GROUP BY kind, unsolicited",
            point.where_()
        ),
        &[],
        point.range(),
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, bool>(1)?,
                count(r.get(2)?),
            ))
        },
    )?;
    let mut out = KindCounts::default();
    for (kind, unsolicited, n) in rows {
        *out.kinds.entry(kind).or_default() += n;
        if unsolicited {
            out.unsolicited += n;
        }
    }
    Ok(out)
}

/// Time of the first and last message within `range`.
pub fn period(conn: &Connection, range: Option<TimeRange>) -> Result<Option<(i64, i64)>> {
    let w = range.map_or("", |_| " WHERE ts >= ?98 AND ts < ?99");
    let (first, last): (Option<i64>, Option<i64>) = query_row_ranged(
        conn,
        &format!(
            "SELECT (SELECT min(ts) FROM arp_messages{w}), (SELECT max(ts) FROM arp_messages{w})"
        ),
        &[],
        range,
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(first.zip(last))
}

/// One sender of binding messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderEntry {
    pub ip: IpAddr,
    pub mac: String,
    pub messages: u64,
    pub info: EndpointInfo,
}

/// The `limit` most active (IP, MAC) senders of binding messages: from the bindings without
/// range, from the messages of the range otherwise (covering index `(binds, sender_ip,
/// sender_mac, ts)`).
pub fn top_senders(
    conn: &Connection,
    limit: u32,
    range: Option<TimeRange>,
) -> Result<Vec<SenderEntry>> {
    let inner = if range.is_some() {
        let point = PointSql::new(conn, "arp_messages", "ts", range)?;
        format!(
            "SELECT sender_ip AS ip, sender_mac AS mac, count(*) AS n FROM arp_messages \
             WHERE binds = 1{} GROUP BY sender_ip, sender_mac \
             ORDER BY n DESC, ip, mac LIMIT ?1",
            point.and()
        )
    } else {
        "SELECT ip, mac, messages AS n FROM arp_bindings ORDER BY n DESC, ip, mac LIMIT ?1"
            .to_owned()
    };
    query_ranged(
        conn,
        &format!(
            "SELECT s.ip, s.mac, s.n, h.names, h.category, h.country FROM ({inner}) s \
             LEFT JOIN hosts h ON h.ip = s.ip ORDER BY s.n DESC, s.ip, s.mac"
        ),
        &[&limit],
        range,
        |r| {
            let raw: String = r.get(0)?;
            Ok(SenderEntry {
                ip: ip(&raw, 0)?,
                mac: r.get(1)?,
                messages: count(r.get(2)?),
                info: endpoint(r, 3)?,
            })
        },
    )
}

// --- bindings ---------------------------------------------------------------------------------

/// Filters of the binding table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BindingFilters {
    /// Substring of the IP or of the MAC address.
    pub q: Option<String>,
    /// Only the addresses claimed by several MAC addresses.
    pub conflicts: bool,
}

/// `%q%` with LIKE wildcards escaped, lower case (MAC addresses are stored in lower case).
fn like_pattern(q: Option<&str>) -> Option<String> {
    let q = q.map(str::trim).filter(|q| !q.is_empty())?;
    let mut out = String::with_capacity(q.len() + 2);
    out.push('%');
    for c in q.to_ascii_lowercase().chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    Some(out)
}

/// `EXISTS` another MAC for the IP of `b` (overlapping the range when set).
fn other_mac(range: Option<TimeRange>) -> &'static str {
    match range {
        None => "EXISTS (SELECT 1 FROM arp_bindings o WHERE o.ip = b.ip AND o.mac <> b.mac)",
        Some(_) => {
            "EXISTS (SELECT 1 FROM arp_bindings o WHERE o.ip = b.ip AND o.mac <> b.mac \
             AND o.first_ts < ? AND o.last_ts >= ?)"
        }
    }
}

fn overlap_values(range: Option<TimeRange>) -> Vec<Value> {
    range.map_or_else(Vec::new, |r| {
        vec![Value::Integer(r.to_ns()), Value::Integer(r.from_ns())]
    })
}

impl BindingFilters {
    fn conditions(&self, range: Option<TimeRange>) -> Conditions {
        let mut c = Conditions::new();
        if let Some(p) = like_pattern(self.q.as_deref()) {
            c.push(
                "b.ip LIKE ? ESCAPE '\\' OR b.mac LIKE ? ESCAPE '\\'",
                [Value::Text(p.clone()), Value::Text(p)],
            );
        }
        if self.conflicts {
            c.push(other_mac(range), overlap_values(range));
        }
        if let Some(r) = range {
            r.push_overlap(&mut c, "b.first_ts", "b.last_ts");
        }
        c
    }
}

/// One (IP, MAC) binding with what the session knows about the IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpBindingEntry {
    pub ip: IpAddr,
    pub mac: String,
    pub first_ts: i64,
    pub last_ts: i64,
    pub messages: u64,
    pub requests: u64,
    pub replies: u64,
    pub gratuitous: u64,
    pub unsolicited: u64,
    /// Another MAC address claims the same IP (overlapping the range when set).
    pub conflict: bool,
    pub info: EndpointInfo,
}

const BINDING_FROM: &str = "arp_bindings b LEFT JOIN hosts h ON h.ip = b.ip";

fn binding_select(range: Option<TimeRange>) -> &'static str {
    match range {
        None => {
            "b.ip, b.mac, b.first_ts, b.last_ts, b.messages, b.requests, b.replies, \
             b.gratuitous, b.unsolicited, EXISTS (SELECT 1 FROM arp_bindings o WHERE \
             o.ip = b.ip AND o.mac <> b.mac), h.names, h.category, h.country"
        }
        Some(_) => {
            "b.ip, b.mac, b.first_ts, b.last_ts, b.messages, b.requests, b.replies, \
             b.gratuitous, b.unsolicited, EXISTS (SELECT 1 FROM arp_bindings o WHERE \
             o.ip = b.ip AND o.mac <> b.mac AND o.first_ts < ? AND o.last_ts >= ?), \
             h.names, h.category, h.country"
        }
    }
}

fn binding_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<ArpBindingEntry> {
    let raw: String = r.get(0)?;
    Ok(ArpBindingEntry {
        ip: ip(&raw, 0)?,
        mac: r.get(1)?,
        first_ts: r.get(2)?,
        last_ts: r.get(3)?,
        messages: count(r.get(4)?),
        requests: count(r.get(5)?),
        replies: count(r.get(6)?),
        gratuitous: count(r.get(7)?),
        unsolicited: count(r.get(8)?),
        conflict: r.get(9)?,
        info: endpoint(r, 10)?,
    })
}

/// One page of bindings by first activity.
pub fn bindings_page(
    conn: &Connection,
    filters: &BindingFilters,
    request: &PageRequest,
    range: Option<TimeRange>,
) -> Result<Page<ArpBindingEntry>> {
    let c = filters.conditions(range);
    let where_sql = c.sql();
    let query = Keyset {
        from: BINDING_FROM,
        select: binding_select(range),
        sort: "b.first_ts",
        tiebreak: "b.rowid",
        descending: false,
        filter: where_sql.as_deref(),
    };
    // The placeholders of the select come first in the statement.
    let select_values = overlap_values(range);
    let mut params: Vec<&dyn ToSql> = select_values.iter().map(|v| v as &dyn ToSql).collect();
    params.extend(c.params());
    keyset_page(conn, &query, &params, request, binding_entry)
}

/// Number of bindings matching `filters`.
pub fn count_bindings(
    conn: &Connection,
    filters: &BindingFilters,
    range: Option<TimeRange>,
) -> Result<u64> {
    let c = filters.conditions(range);
    let where_sql = c.sql().map(|w| format!(" WHERE {w}")).unwrap_or_default();
    let n: i64 = conn.query_row(
        &format!("SELECT count(*) FROM arp_bindings b{where_sql}"),
        c.params().as_slice(),
        |r| r.get(0),
    )?;
    Ok(count(n))
}

/// Bindings, distinct IP addresses and conflicting IP addresses (overlapping `range`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BindingFigures {
    pub bindings: u64,
    pub addresses: u64,
    pub conflicts: u64,
}

pub fn binding_figures(conn: &Connection, range: Option<TimeRange>) -> Result<BindingFigures> {
    let a = and_overlap(range, "first_ts", "last_ts");
    query_row_ranged(
        conn,
        &format!(
            "SELECT count(*), count(DISTINCT ip), \
                    (SELECT count(*) FROM (SELECT ip FROM arp_bindings WHERE 1{a} \
                     GROUP BY ip HAVING count(*) > 1)) \
             FROM arp_bindings WHERE 1{a}"
        ),
        &[],
        range,
        |r| {
            Ok(BindingFigures {
                bindings: count(r.get(0)?),
                addresses: count(r.get(1)?),
                conflicts: count(r.get(2)?),
            })
        },
    )
}

// --- conflicts --------------------------------------------------------------------------------

/// One MAC address of a conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictSide {
    pub mac: String,
    pub first_ts: i64,
    pub last_ts: i64,
    pub messages: u64,
    pub gratuitous: u64,
    pub unsolicited: u64,
    /// Other IP addresses claimed by this MAC (overlapping the range when set).
    pub other_ips: u64,
}

/// Why a conflict may be a spoofing attempt (stable labels, explained by the view).
pub const SIGNS: [&str; 5] = [
    "simultaneous",
    "successive",
    "gratuitous",
    "unsolicited",
    "multiple_ips",
];

/// An IP address claimed by several MAC addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictEntry {
    pub ip: IpAddr,
    pub info: EndpointInfo,
    /// Number of MAC addresses (all of them, `sides` may be cut).
    pub mac_count: u64,
    /// By first activity.
    pub sides: Vec<ConflictSide>,
    /// Labels of [`SIGNS`] that apply, in that order.
    pub signs: Vec<&'static str>,
}

/// Signs of a conflict: whether two periods of activity overlap (else the address changed
/// hands), and the gratuitous, unsolicited and multiple-address hints of its sides.
pub fn signs(sides: &[ConflictSide]) -> Vec<&'static str> {
    let mut sorted: Vec<(i64, i64)> = sides.iter().map(|s| (s.first_ts, s.last_ts)).collect();
    sorted.sort_unstable();
    let mut overlap = false;
    let mut end = i64::MIN;
    for (first, last) in sorted {
        if first <= end {
            overlap = true;
        }
        end = end.max(last);
    }
    let mut out = vec![if overlap { "simultaneous" } else { "successive" }];
    if sides.iter().any(|s| s.gratuitous > 0) {
        out.push("gratuitous");
    }
    if sides.iter().any(|s| s.unsolicited > 0) {
        out.push("unsolicited");
    }
    if sides.iter().any(|s| s.other_ips > 0) {
        out.push("multiple_ips");
    }
    out
}

/// Up to `limit` conflicting addresses (most MAC addresses first, then by address), each with up
/// to `max_sides` MAC addresses, and the number of conflicting addresses.
pub fn conflicts(
    conn: &Connection,
    limit: u32,
    max_sides: u32,
    range: Option<TimeRange>,
) -> Result<(Vec<ConflictEntry>, u64)> {
    let a = and_overlap(range, "first_ts", "last_ts");
    let total = binding_figures(conn, range)?.conflicts;
    let heads = query_ranged(
        conn,
        &format!(
            "SELECT c.ip, c.n, h.names, h.category, h.country FROM \
             (SELECT ip, count(*) AS n FROM arp_bindings WHERE 1{a} GROUP BY ip \
              HAVING count(*) > 1) c LEFT JOIN hosts h ON h.ip = c.ip \
             ORDER BY c.n DESC, c.ip LIMIT ?1"
        ),
        &[&limit],
        range,
        |r| {
            let raw: String = r.get(0)?;
            Ok((ip(&raw, 0)?, count(r.get(1)?), endpoint(r, 2)?))
        },
    )?;
    let sides_sql = format!(
        "SELECT b.mac, b.first_ts, b.last_ts, b.messages, b.gratuitous, b.unsolicited, \
                (SELECT count(*) FROM arp_bindings o WHERE o.mac = b.mac AND o.ip <> b.ip{oa}) \
         FROM arp_bindings b WHERE b.ip = ?1{ba} ORDER BY b.first_ts, b.mac LIMIT ?2",
        oa = and_overlap(range, "o.first_ts", "o.last_ts"),
        ba = and_overlap(range, "b.first_ts", "b.last_ts"),
    );
    let mut out = Vec::with_capacity(heads.len());
    for (address, mac_count, info) in heads {
        let text = address.to_string();
        let sides = query_ranged(conn, &sides_sql, &[&text, &max_sides], range, |r| {
            Ok(ConflictSide {
                mac: r.get(0)?,
                first_ts: r.get(1)?,
                last_ts: r.get(2)?,
                messages: count(r.get(3)?),
                gratuitous: count(r.get(4)?),
                unsolicited: count(r.get(5)?),
                other_ips: count(r.get(6)?),
            })
        })?;
        out.push(ConflictEntry {
            ip: address,
            info,
            mac_count,
            signs: signs(&sides),
            sides,
        });
    }
    Ok((out, total))
}

#[cfg(test)]
mod tests;
