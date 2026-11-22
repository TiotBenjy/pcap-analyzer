//! Rows and read queries of the SSDP analyzer (`ssdp_messages`, `ssdp_devices`).
//!
//! Under a time range (ADR-030, `docs/specs/ssdp.md`): messages are point records (`ts`), devices
//! are folded rows (overlap of `first_ts` / `last_ts`, counters of the session).

use std::net::IpAddr;

use rusqlite::types::Value;
use rusqlite::{Connection, params};

use crate::connections::EndpointInfo;
use crate::error::Result;
use crate::query::{Conditions, Keyset, Page, PageRequest, keyset_page};
use crate::range::{PointSql, TimeRange, query_ranged, query_row_ranged, where_overlap};
use crate::records::conversion;

fn ip(raw: &str, col: usize) -> rusqlite::Result<IpAddr> {
    raw.parse().map_err(|e| conversion(col, e))
}

fn json_strings(raw: Option<String>, col: usize) -> rusqlite::Result<Vec<String>> {
    match raw {
        None => Ok(Vec::new()),
        Some(raw) => serde_json::from_str(&raw).map_err(|e| conversion(col, e)),
    }
}

fn unsigned(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

/// `%q%` with LIKE wildcards escaped; `None` for an empty search.
fn like_pattern(q: Option<&str>) -> Option<String> {
    let q = q.map(str::trim).filter(|q| !q.is_empty())?;
    let mut out = String::with_capacity(q.len() + 2);
    out.push('%');
    for c in q.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    Some(out)
}

/// One SSDP datagram emitted by the analyzer. Inserting it also folds it into `ssdp_devices`
/// when it carries a device identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsdpRow {
    pub ts: i64,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub multicast: bool,
    /// `notify`, `search`, `response` or `invalid`.
    pub kind: String,
    pub nts: Option<String>,
    pub status: Option<u16>,
    pub target: Option<String>,
    pub usn: Option<String>,
    pub uuid: Option<String>,
    pub server: Option<String>,
    pub user_agent: Option<String>,
    pub location: Option<String>,
    pub max_age: Option<u32>,
    pub mx: Option<u32>,
    pub size: u64,
    pub raw: String,
    pub raw_truncated: bool,
    /// Device type announced or searched (`urn:...:device:...`), when the target is one.
    pub device_type: Option<String>,
}

/// Condition under which the incoming value of `col` replaces the stored one: it is non-empty,
/// and the stored one is empty, or older (its own timestamp column `col_ts`), or of the same
/// time but smaller. An empty stored value always loses, whatever its timestamp: the result does
/// not depend on the order of arrival.
macro_rules! newer {
    ($col:literal) => {
        concat!(
            "excluded.",
            $col,
            " <> '' AND (ssdp_devices.",
            $col,
            " = '' OR excluded.",
            $col,
            "_ts > ssdp_devices.",
            $col,
            "_ts OR (excluded.",
            $col,
            "_ts = ssdp_devices.",
            $col,
            "_ts AND excluded.",
            $col,
            " > ssdp_devices.",
            $col,
            "))"
        )
    };
}

/// `SET` of a text value and of its timestamp, by [`newer`].
macro_rules! latest {
    ($col:literal) => {
        concat!(
            $col,
            " = iif(",
            newer!($col),
            ", excluded.",
            $col,
            ", ssdp_devices.",
            $col,
            "), ",
            $col,
            "_ts = iif(",
            newer!($col),
            ", excluded.",
            $col,
            "_ts, ssdp_devices.",
            $col,
            "_ts)"
        )
    };
}

impl SsdpRow {
    pub(crate) fn insert(&self, conn: &Connection) -> Result<()> {
        conn.prepare_cached(
            "INSERT INTO ssdp_messages \
             (ts, src_ip, src_port, dst_ip, dst_port, multicast, kind, nts, status, target, usn, \
              uuid, server, user_agent, software, location, max_age, mx, size, raw, raw_truncated) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                     coalesce(?13, ?14), ?15, ?16, ?17, ?18, ?19, ?20)",
        )?
        .execute(params![
            self.ts,
            self.src_ip.to_string(),
            self.src_port,
            self.dst_ip.to_string(),
            self.dst_port,
            self.multicast,
            self.kind,
            self.nts,
            self.status,
            self.target,
            self.usn,
            self.uuid,
            self.server,
            self.user_agent,
            self.location,
            self.max_age,
            self.mx,
            i64::try_from(self.size).unwrap_or(i64::MAX),
            self.raw,
            self.raw_truncated,
        ])?;
        // Devices are those that announce (NOTIFY) or answer: a search names what it looks for.
        let Some(uuid) = self.uuid.as_ref().filter(|_| self.kind != "search") else {
            return Ok(());
        };
        let text = |v: &Option<String>| v.clone().unwrap_or_default();
        let ts_of = |v: &Option<String>| if v.is_some() { self.ts } else { 0 };
        let alive = self.kind == "notify" && self.nts.as_deref() == Some("alive");
        let byebye = self.kind == "notify" && self.nts.as_deref() == Some("byebye");
        let response = self.kind == "response";
        conn.prepare_cached(concat!(
            "INSERT INTO ssdp_devices \
             (uuid, ip, device_type, device_type_ts, server, server_ts, location, location_ts, \
              message_count, alive_count, byebye_count, response_count, first_ts, last_ts) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?10, ?11, ?12, ?12) \
             ON CONFLICT (uuid, ip) DO UPDATE SET \
             message_count = ssdp_devices.message_count + 1, \
             alive_count = ssdp_devices.alive_count + excluded.alive_count, \
             byebye_count = ssdp_devices.byebye_count + excluded.byebye_count, \
             response_count = ssdp_devices.response_count + excluded.response_count, \
             first_ts = min(ssdp_devices.first_ts, excluded.first_ts), \
             last_ts = max(ssdp_devices.last_ts, excluded.last_ts), ",
            latest!("device_type"),
            ", ",
            latest!("server"),
            ", ",
            latest!("location"),
        ))?
        .execute(params![
            uuid,
            self.src_ip.to_string(),
            text(&self.device_type),
            ts_of(&self.device_type),
            text(&self.server),
            ts_of(&self.server),
            text(&self.location),
            ts_of(&self.location),
            alive,
            byebye,
            response,
            self.ts,
        ])?;
        Ok(())
    }

    /// Rough heap size, for the writer's batch accounting.
    pub fn approx_size(&self) -> usize {
        let opt = |v: &Option<String>| v.as_ref().map_or(0, String::len);
        160 + self.kind.len()
            + self.raw.len()
            + opt(&self.nts)
            + opt(&self.target)
            + opt(&self.usn)
            + opt(&self.uuid)
            + opt(&self.server)
            + opt(&self.user_agent)
            + opt(&self.location)
            + opt(&self.device_type)
    }
}

// ---- messages ----------------------------------------------------------------------------------

/// Filters of the message list (all optional, combined with AND).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SsdpMessageFilter {
    /// `notify`, `search`, `response` or `invalid`.
    pub kind: Option<String>,
    /// Notification sub-type (`alive`, `byebye`, `update`).
    pub nts: Option<String>,
    /// Device identifier.
    pub uuid: Option<String>,
    /// Sending address.
    pub src: Option<IpAddr>,
    /// Exact `NT` / `ST`.
    pub target: Option<String>,
    /// Text in the target, USN, server, user agent or location.
    pub q: Option<String>,
    /// Messages whose `ts` is within this range.
    pub range: Option<TimeRange>,
}

/// One stored message with what the session knows about both ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsdpMessageEntry {
    pub id: i64,
    pub ts: i64,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub multicast: bool,
    pub kind: String,
    pub nts: Option<String>,
    pub status: Option<u16>,
    pub target: Option<String>,
    pub usn: Option<String>,
    pub uuid: Option<String>,
    pub server: Option<String>,
    pub user_agent: Option<String>,
    pub location: Option<String>,
    pub max_age: Option<u32>,
    pub mx: Option<u32>,
    pub size: u64,
    pub raw: String,
    pub raw_truncated: bool,
    pub source: EndpointInfo,
    pub destination: EndpointInfo,
}

const MESSAGE_FROM: &str = "ssdp_messages m \
    LEFT JOIN hosts hs ON hs.ip = m.src_ip LEFT JOIN hosts hd ON hd.ip = m.dst_ip";
const MESSAGE_SELECT: &str = "m.id, m.ts, m.src_ip, m.src_port, m.dst_ip, m.dst_port, \
    m.multicast, m.kind, m.nts, m.status, m.target, m.usn, m.uuid, m.server, m.user_agent, \
    m.location, m.max_age, m.mx, m.size, m.raw, m.raw_truncated, hs.names, hs.category, \
    hs.country, hd.names, hd.category, hd.country";

fn message_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<SsdpMessageEntry> {
    let src: String = r.get(2)?;
    let dst: String = r.get(4)?;
    Ok(SsdpMessageEntry {
        id: r.get(0)?,
        ts: r.get(1)?,
        src_ip: ip(&src, 2)?,
        src_port: r.get(3)?,
        dst_ip: ip(&dst, 4)?,
        dst_port: r.get(5)?,
        multicast: r.get(6)?,
        kind: r.get(7)?,
        nts: r.get(8)?,
        status: r.get(9)?,
        target: r.get(10)?,
        usn: r.get(11)?,
        uuid: r.get(12)?,
        server: r.get(13)?,
        user_agent: r.get(14)?,
        location: r.get(15)?,
        max_age: r.get(16)?,
        mx: r.get(17)?,
        size: unsigned(r.get(18)?),
        raw: r.get(19)?,
        raw_truncated: r.get(20)?,
        source: EndpointInfo {
            names: json_strings(r.get(21)?, 21)?,
            category: r.get(22)?,
            country: r.get(23)?,
        },
        destination: EndpointInfo {
            names: json_strings(r.get(24)?, 24)?,
            category: r.get(25)?,
            country: r.get(26)?,
        },
    })
}

/// The active filters (the search pattern repeated for each searched column).
fn message_conditions(filter: &SsdpMessageFilter) -> Conditions {
    let mut c = Conditions::new();
    if let Some(k) = &filter.kind {
        c.push("m.kind = ?", [Value::Text(k.clone())]);
    }
    if let Some(n) = &filter.nts {
        c.push("m.nts = ?", [Value::Text(n.clone())]);
    }
    if let Some(u) = &filter.uuid {
        c.push("m.uuid = ?", [Value::Text(u.clone())]);
    }
    if let Some(s) = filter.src {
        c.push("m.src_ip = ?", [Value::Text(s.to_string())]);
    }
    if let Some(t) = &filter.target {
        c.push("m.target = ?", [Value::Text(t.clone())]);
    }
    if let Some(p) = like_pattern(filter.q.as_deref()) {
        c.push(
            "m.target LIKE ? ESCAPE '\\' OR m.usn LIKE ? ESCAPE '\\' \
             OR m.server LIKE ? ESCAPE '\\' OR m.user_agent LIKE ? ESCAPE '\\' \
             OR m.location LIKE ? ESCAPE '\\'",
            std::iter::repeat_n(Value::Text(p), 5),
        );
    }
    if let Some(r) = filter.range {
        r.push_point(&mut c, "m.ts");
    }
    c
}

/// One page of messages, by time then id (ascending).
pub fn messages_page(
    conn: &Connection,
    filter: &SsdpMessageFilter,
    request: &PageRequest,
) -> Result<Page<SsdpMessageEntry>> {
    let c = message_conditions(filter);
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

/// Number of messages matching `filter`.
pub fn count_messages(conn: &Connection, filter: &SsdpMessageFilter) -> Result<u64> {
    let c = message_conditions(filter);
    let sql = match c.sql() {
        Some(w) => format!("SELECT count(*) FROM ssdp_messages m WHERE {w}"),
        None => "SELECT count(*) FROM ssdp_messages m".to_owned(),
    };
    let n: i64 = conn.query_row(&sql, c.params().as_slice(), |r| r.get(0))?;
    Ok(unsigned(n))
}

// ---- devices -----------------------------------------------------------------------------------

/// One folded device with what the session knows about its address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsdpDeviceEntry {
    pub uuid: String,
    pub ip: IpAddr,
    pub device_type: String,
    pub server: String,
    pub location: String,
    pub message_count: u64,
    pub alive_count: u64,
    pub byebye_count: u64,
    pub response_count: u64,
    pub first_ts: i64,
    pub last_ts: i64,
    pub address: EndpointInfo,
}

const DEVICE_FROM: &str = "ssdp_devices d LEFT JOIN hosts h ON h.ip = d.ip";
const DEVICE_SELECT: &str = "d.uuid, d.ip, d.device_type, d.server, d.location, \
    d.message_count, d.alive_count, d.byebye_count, d.response_count, d.first_ts, d.last_ts, \
    h.names, h.category, h.country";

fn device_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<SsdpDeviceEntry> {
    let addr: String = r.get(1)?;
    Ok(SsdpDeviceEntry {
        uuid: r.get(0)?,
        ip: ip(&addr, 1)?,
        device_type: r.get(2)?,
        server: r.get(3)?,
        location: r.get(4)?,
        message_count: unsigned(r.get(5)?),
        alive_count: unsigned(r.get(6)?),
        byebye_count: unsigned(r.get(7)?),
        response_count: unsigned(r.get(8)?),
        first_ts: r.get(9)?,
        last_ts: r.get(10)?,
        address: EndpointInfo {
            names: json_strings(r.get(11)?, 11)?,
            category: r.get(12)?,
            country: r.get(13)?,
        },
    })
}

fn device_conditions(q: Option<&str>, range: Option<TimeRange>) -> Conditions {
    let mut c = Conditions::new();
    if let Some(p) = like_pattern(q) {
        c.push(
            "d.uuid LIKE ? ESCAPE '\\' OR d.ip LIKE ? ESCAPE '\\' \
             OR d.device_type LIKE ? ESCAPE '\\' OR d.server LIKE ? ESCAPE '\\' \
             OR d.location LIKE ? ESCAPE '\\'",
            std::iter::repeat_n(Value::Text(p), 5),
        );
    }
    if let Some(r) = range {
        r.push_overlap(&mut c, "d.first_ts", "d.last_ts");
    }
    c
}

/// One page of devices, most messages first. `q`: text in the UUID, address, type, server or
/// location. Under a range, the devices whose span overlaps it (counters of the session).
pub fn devices_page(
    conn: &Connection,
    q: Option<&str>,
    range: Option<TimeRange>,
    request: &PageRequest,
) -> Result<Page<SsdpDeviceEntry>> {
    let c = device_conditions(q, range);
    let where_sql = c.sql();
    let query = Keyset {
        from: DEVICE_FROM,
        select: DEVICE_SELECT,
        sort: "d.message_count",
        tiebreak: "d.rowid",
        descending: true,
        filter: where_sql.as_deref(),
    };
    keyset_page(conn, &query, &c.params(), request, device_entry)
}

/// Number of devices matching the filters of [`devices_page`].
pub fn count_devices(conn: &Connection, q: Option<&str>, range: Option<TimeRange>) -> Result<u64> {
    let c = device_conditions(q, range);
    let sql = match c.sql() {
        Some(w) => format!("SELECT count(*) FROM ssdp_devices d WHERE {w}"),
        None => "SELECT count(*) FROM ssdp_devices d".to_owned(),
    };
    let n: i64 = conn.query_row(&sql, c.params().as_slice(), |r| r.get(0))?;
    Ok(unsigned(n))
}

/// Distinct targets (`NT` / `ST`) of a device, sorted, at most `limit` (whole session).
pub fn device_targets(
    conn: &Connection,
    uuid: &str,
    ip: IpAddr,
    limit: u32,
) -> Result<Vec<String>> {
    let mut stmt = conn.prepare_cached(
        "SELECT DISTINCT target FROM ssdp_messages \
         WHERE uuid = ?1 AND src_ip = ?2 AND target IS NOT NULL ORDER BY target LIMIT ?3",
    )?;
    let rows = stmt
        .query_map(params![uuid, ip.to_string(), limit], |r| r.get(0))?
        .collect::<rusqlite::Result<Vec<String>>>()?;
    Ok(rows)
}

// ---- statistics --------------------------------------------------------------------------------

/// Aggregates of the SSDP view (of the messages within `range` when set).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SsdpStatsRows {
    pub messages: u64,
    pub notify: u64,
    pub alive: u64,
    pub byebye: u64,
    pub update: u64,
    pub search: u64,
    pub response: u64,
    pub invalid: u64,
    /// Devices whose span overlaps the range (all without range).
    pub devices: u64,
    /// Distinct sending addresses.
    pub senders: u64,
    /// `(target, messages)`, most frequent first.
    pub targets: Vec<(String, u64)>,
    /// `(SERVER, else USER-AGENT, messages)`, most frequent first.
    pub software: Vec<(String, u64)>,
    /// `(address, messages, host info)`, most frequent first.
    pub senders_top: Vec<(IpAddr, u64, EndpointInfo)>,
}

/// Aggregates for the view, bounded to `limit` entries per ranking. Every index read ends with
/// `ts` (migration 1200), so a wide range reads the covering indexes only.
pub fn stats(conn: &Connection, limit: u32, range: Option<TimeRange>) -> Result<SsdpStatsRows> {
    let plan = PointSql::new(conn, "ssdp_messages", "ts", range)?;
    let w = plan.where_();
    let a = plan.and();
    let mut out = SsdpStatsRows::default();
    let kinds: Vec<(String, Option<String>, i64)> = query_ranged(
        conn,
        &format!("SELECT kind, nts, count(*) FROM ssdp_messages{w} GROUP BY kind, nts"),
        &[],
        range,
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    for (kind, nts, n) in kinds {
        let n = unsigned(n);
        out.messages += n;
        match kind.as_str() {
            "notify" => {
                out.notify += n;
                match nts.as_deref() {
                    Some("alive") => out.alive += n,
                    Some("byebye") => out.byebye += n,
                    Some("update") => out.update += n,
                    _ => {}
                }
            }
            "search" => out.search += n,
            "response" => out.response += n,
            _ => out.invalid += n,
        }
    }
    out.senders = unsigned(query_row_ranged(
        conn,
        &format!("SELECT count(DISTINCT src_ip) FROM ssdp_messages{w}"),
        &[],
        range,
        |r| r.get(0),
    )?);
    let ranking = |r: &rusqlite::Row<'_>| Ok((r.get::<_, String>(0)?, unsigned(r.get(1)?)));
    out.targets = query_ranged(
        conn,
        &format!(
            "SELECT target, count(*) AS n FROM ssdp_messages WHERE target IS NOT NULL{a} \
             GROUP BY target ORDER BY n DESC, target LIMIT ?1"
        ),
        &[&limit],
        range,
        ranking,
    )?;
    out.software = query_ranged(
        conn,
        &format!(
            "SELECT software, count(*) AS n FROM ssdp_messages WHERE software IS NOT NULL{a} \
             GROUP BY software ORDER BY n DESC, software LIMIT ?1"
        ),
        &[&limit],
        range,
        ranking,
    )?;
    out.senders_top = query_ranged(
        conn,
        &format!(
            "SELECT s.ip, s.n, h.names, h.category, h.country FROM \
             (SELECT src_ip AS ip, count(*) AS n FROM ssdp_messages{w} GROUP BY src_ip \
              ORDER BY n DESC, src_ip LIMIT ?1) s \
             LEFT JOIN hosts h ON h.ip = s.ip ORDER BY s.n DESC, s.ip"
        ),
        &[&limit],
        range,
        |r| {
            let raw: String = r.get(0)?;
            Ok((
                ip(&raw, 0)?,
                unsigned(r.get(1)?),
                EndpointInfo {
                    names: json_strings(r.get(2)?, 2)?,
                    category: r.get(3)?,
                    country: r.get(4)?,
                },
            ))
        },
    )?;
    let o = where_overlap(range, "first_ts", "last_ts");
    out.devices = unsigned(query_row_ranged(
        conn,
        &format!("SELECT count(*) FROM ssdp_devices{o}"),
        &[],
        range,
        |r| r.get(0),
    )?);
    Ok(out)
}

#[cfg(test)]
mod tests;
