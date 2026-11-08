//! Rows written by the batched writer.
//!
//! [`StoreRecord`] has one variant per table family. `netsift-engine` translates the analyzers'
//! `Record` enum into it; an analyzer that adds tables (migration `NNNN_<name>.sql`) adds
//! **one variant** in the sorted zone of [`StoreRecord`], one arm in [`StoreRecord::kind`]
//! and one arm in [`StoreRecord::insert`] (pointing to an `insert` function in its own module).
//!
//! # Merge rules
//!
//! Flow shards send records in a non-deterministic order, so every upsert fed by shards is
//! **commutative**: the final table does not depend on arrival order (nor on batch borders).
//!
//! - `timeseries`: counters are added (saturating at `i64::MAX`).
//! - `hosts`: `macs` and `names` are united (sorted, deduplicated, keeping the smallest
//!   [`MAX_HOST_MACS`] / [`MAX_HOST_NAMES`]); `first_ts` = min, `last_ts` = max;
//!   `country` / `category`: a non-NULL value wins over NULL, the smallest one between two.
//! - `flows`: `first_ts` = min, `last_ts` and every counter = max (snapshots are cumulative);
//!   `app_proto` / `tcp_state` follow the non-NULL-then-smallest rule. The 5-tuple is an
//!   invariant of a flow id and is never updated.
//! - `anomalies`: plain inserts (the set of rows is order independent).
//! - `meta` and `chunks` are **not** commutative (last write wins): they are written by a
//!   single ordered producer (the engine's reader thread), never by shards.
//!
//! Unsigned values above `i64::MAX` are saturated, except identifiers, which are rejected.

use std::net::IpAddr;

use rusqlite::{Connection, params};

use crate::connections::{ConversationRow, HostTrafficRow};
use crate::error::{Result, StoreError};
use crate::ports::OpenPortRow;

/// Maximum number of names kept per host.
pub const MAX_HOST_NAMES: usize = 64;
/// Maximum length of one host name, in bytes (DNS names are at most 253 bytes).
pub const MAX_HOST_NAME_LEN: usize = 255;
/// Maximum number of MAC addresses kept per host.
pub const MAX_HOST_MACS: usize = 16;

/// One row (or one upsert) for the writer.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum StoreRecord {
    // --- core ---
    /// Upsert of a `meta` key (last value wins; single producer).
    Meta(MetaRow),
    /// Upsert of a chunk by `id` (the whole row is replaced; single producer).
    Chunk(ChunkRow),
    /// New anomaly.
    Anomaly(AnomalyRow),
    /// Additive upsert of a `(bucket_s, proto)` counter.
    Timeseries(TimeseriesRow),
    /// Commutative merging upsert of a host by IP.
    Host(HostRow),
    /// Commutative merging upsert of a flow by `id`.
    Flow(FlowRow),
    // --- analyzers: one variant per table family, sorted alphabetically ---
    /// Additive upsert of a conversation by (client, server) (`connections`).
    Conversation(ConversationRow),
    /// Additive upsert of the traffic of a host (`connections`).
    HostTraffic(HostTrafficRow),
    /// New HTTP transaction with its headers (`http_*`), boxed: much larger than the others.
    Http(Box<crate::http::HttpRow>),
    /// Commutative merging upsert of an open port (`ports`).
    OpenPort(OpenPortRow),
    /// One TLS session with its hellos and certificates (`tls_*` tables).
    Tls(Box<crate::tls::TlsSessionRow>),
}

impl StoreRecord {
    /// Stable name of the record type, key of [`crate::WriterStats::rows`].
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Meta(_) => "meta",
            Self::Chunk(_) => "chunks",
            Self::Anomaly(_) => "anomalies",
            Self::Timeseries(_) => "timeseries",
            Self::Host(_) => "hosts",
            Self::Flow(_) => "flows",
            Self::Conversation(_) => "conversations",
            Self::HostTraffic(_) => "host_traffic",
            Self::Http(_) => "http_transactions",
            Self::OpenPort(_) => "open_ports",
            Self::Tls(_) => "tls_sessions",
        }
    }

    /// Writes the record with cached prepared statements (inside the writer's transaction).
    pub(crate) fn insert(&self, conn: &Connection) -> Result<()> {
        match self {
            Self::Meta(r) => r.insert(conn),
            Self::Chunk(r) => r.insert(conn),
            Self::Anomaly(r) => r.insert(conn),
            Self::Timeseries(r) => r.insert(conn),
            Self::Host(r) => r.insert(conn),
            Self::Flow(r) => r.insert(conn),
            Self::Conversation(r) => r.insert(conn),
            Self::HostTraffic(r) => r.insert(conn),
            Self::Http(r) => r.insert(conn),
            Self::OpenPort(r) => r.insert(conn),
            Self::Tls(r) => r.insert(conn),
        }
    }
}

/// Saturating conversion for counters and sizes.
pub(crate) fn sat(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Strict conversion for identifiers (saturating would merge distinct rows).
pub(crate) fn id_i64(v: u64, field: &'static str) -> Result<i64> {
    i64::try_from(v).map_err(|_| StoreError::InvalidValue {
        field,
        reason: "identifier above i64::MAX",
    })
}

/// `meta` key/value pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaRow {
    pub key: String,
    pub value: String,
}

impl MetaRow {
    fn insert(&self, conn: &Connection) -> Result<()> {
        conn.prepare_cached(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) \
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        )?
        .execute(params![self.key, self.value])?;
        Ok(())
    }
}

/// Capture file format of a chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkFormat {
    Pcap,
    PcapNg,
}

impl ChunkFormat {
    /// Text stored in the database.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pcap => "pcap",
            Self::PcapNg => "pcapng",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "pcap" => Some(Self::Pcap),
            "pcapng" => Some(Self::PcapNg),
            _ => None,
        }
    }
}

/// State of a chunk in the session (`docs/CHUNKED_CAPTURES.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkStatus {
    Ok,
    Truncated,
    Duplicate,
    Ignored,
}

impl ChunkStatus {
    /// Text stored in the database.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Truncated => "truncated",
            Self::Duplicate => "duplicate",
            Self::Ignored => "ignored",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "ok" => Some(Self::Ok),
            "truncated" => Some(Self::Truncated),
            "duplicate" => Some(Self::Duplicate),
            "ignored" => Some(Self::Ignored),
            _ => None,
        }
    }
}

/// One capture file of the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRow {
    /// Index in the ordered chunk set (`RawPacket::chunk_id`).
    pub id: u32,
    /// Sequence number parsed from the file name; `None` if absent or out of range.
    pub seq: Option<i64>,
    pub path: String,
    /// `None` when the file was not recognized.
    pub format: Option<ChunkFormat>,
    pub compressed: bool,
    pub linktypes: Vec<u32>,
    pub snaplen: Option<u32>,
    pub first_ts: Option<i64>,
    pub last_ts: Option<i64>,
    pub packets: u64,
    /// Captured packet bytes.
    pub bytes: u64,
    /// File size on disk.
    pub file_size: u64,
    pub mtime_ns: Option<i64>,
    /// Hex digest of the first 64 KiB.
    pub head_hash: Option<String>,
    pub status: ChunkStatus,
}

impl ChunkRow {
    fn insert(&self, conn: &Connection) -> Result<()> {
        let linktypes = serde_json::to_string(&self.linktypes)?;
        conn.prepare_cached(
            "INSERT INTO chunks (id, seq, path, format, compressed, linktypes, snaplen, first_ts, \
             last_ts, packets, bytes, file_size, mtime_ns, head_hash, status) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15) \
             ON CONFLICT (id) DO UPDATE SET seq = excluded.seq, path = excluded.path, \
             format = excluded.format, compressed = excluded.compressed, \
             linktypes = excluded.linktypes, snaplen = excluded.snaplen, \
             first_ts = excluded.first_ts, last_ts = excluded.last_ts, \
             packets = excluded.packets, bytes = excluded.bytes, \
             file_size = excluded.file_size, mtime_ns = excluded.mtime_ns, \
             head_hash = excluded.head_hash, status = excluded.status",
        )?
        .execute(params![
            self.id,
            self.seq,
            self.path,
            self.format.map(ChunkFormat::as_str),
            self.compressed,
            linktypes,
            self.snaplen,
            self.first_ts,
            self.last_ts,
            sat(self.packets),
            sat(self.bytes),
            sat(self.file_size),
            self.mtime_ns,
            self.head_hash,
            self.status.as_str(),
        ])?;
        Ok(())
    }

    pub(crate) fn from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        let linktypes: String = r.get(5)?;
        let format: Option<String> = r.get(3)?;
        let status: String = r.get(14)?;
        Ok(Self {
            id: r.get(0)?,
            seq: r.get(1)?,
            path: r.get(2)?,
            format: format.as_deref().and_then(ChunkFormat::parse),
            compressed: r.get(4)?,
            linktypes: serde_json::from_str(&linktypes).map_err(|e| conversion(5, e))?,
            snaplen: r.get(6)?,
            first_ts: r.get(7)?,
            last_ts: r.get(8)?,
            packets: r.get(9)?,
            bytes: r.get(10)?,
            file_size: r.get(11)?,
            mtime_ns: r.get(12)?,
            head_hash: r.get(13)?,
            status: ChunkStatus::parse(&status).ok_or_else(|| {
                conversion(
                    14,
                    StoreError::InvalidValue {
                        field: "status",
                        reason: "unknown chunk status",
                    },
                )
            })?,
        })
    }
}

/// One anomaly (gap, overlap, missing sequence number, truncated tail...).
#[derive(Debug, Clone, PartialEq)]
pub struct AnomalyRow {
    /// Snake-case kind, e.g. `time_gap`, `missing_sequence`, `truncated_tail`.
    pub kind: String,
    /// Chunk concerned, if any (`chunks.id`).
    pub chunk_id: Option<u32>,
    pub ts: Option<i64>,
    /// Structured details (JSON object).
    pub detail: serde_json::Value,
}

impl AnomalyRow {
    fn insert(&self, conn: &Connection) -> Result<()> {
        let detail = serde_json::to_string(&self.detail)?;
        conn.prepare_cached(
            "INSERT INTO anomalies (kind, chunk_id, ts, detail) VALUES (?1, ?2, ?3, ?4)",
        )?
        .execute(params![self.kind, self.chunk_id, self.ts, detail])?;
        Ok(())
    }
}

/// Traffic counter increment for one second and one protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeseriesRow {
    /// Seconds since the Unix epoch.
    pub bucket_s: i64,
    pub proto: String,
    pub bytes: u64,
    pub packets: u64,
}

impl TimeseriesRow {
    fn insert(&self, conn: &Connection) -> Result<()> {
        // On i64 overflow SQLite switches to REAL: min() brings it back to the integer bound.
        conn.prepare_cached(
            "INSERT INTO timeseries (bucket_s, proto, bytes, packets) VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT (bucket_s, proto) DO UPDATE SET \
             bytes = min(bytes + excluded.bytes, 9223372036854775807), \
             packets = min(packets + excluded.packets, 9223372036854775807)",
        )?
        .execute(params![
            self.bucket_s,
            self.proto,
            sat(self.bytes),
            sat(self.packets)
        ])?;
        Ok(())
    }
}

/// Observation of a host (merge rules: see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRow {
    pub ip: IpAddr,
    pub macs: Vec<[u8; 6]>,
    pub names: Vec<String>,
    /// ISO 3166-1 alpha-2 code.
    pub country: Option<String>,
    /// Address category (private, public, multicast...), see `netsift-geo`.
    pub category: Option<String>,
    pub first_ts: i64,
    pub last_ts: i64,
}

/// Sorted, deduplicated JSON array of the `limit` smallest values.
fn json_set<'a>(values: impl Iterator<Item = &'a str>, limit: usize) -> Result<String> {
    let mut v: Vec<&str> = values.collect();
    v.sort_unstable();
    v.dedup();
    v.truncate(limit);
    Ok(serde_json::to_string(&v)?)
}

/// SQL merging two JSON arrays of strings: sorted union, truncated to `?limit` values.
/// Keeping the N smallest of a union is associative and commutative.
macro_rules! json_union {
    ($col:literal, $limit:literal) => {
        concat!(
            $col,
            " = CASE WHEN excluded.",
            $col,
            " = '[]' THEN hosts.",
            $col,
            " ELSE (SELECT json_group_array(value ORDER BY value) FROM (",
            "SELECT value FROM json_each(hosts.",
            $col,
            ") UNION SELECT value FROM json_each(excluded.",
            $col,
            ") ORDER BY 1 LIMIT ",
            $limit,
            ")) END"
        )
    };
}

/// SQL of the "non-NULL wins, then the smallest" rule.
macro_rules! min_non_null {
    ($table:literal, $col:literal) => {
        concat!(
            $col,
            " = coalesce(min(",
            $table,
            ".",
            $col,
            ", excluded.",
            $col,
            "), ",
            $table,
            ".",
            $col,
            ", excluded.",
            $col,
            ")"
        )
    };
}

impl HostRow {
    fn insert(&self, conn: &Connection) -> Result<()> {
        let macs: Vec<String> = self.macs.iter().map(|m| format_mac(*m)).collect();
        let macs = json_set(macs.iter().map(String::as_str), MAX_HOST_MACS)?;
        let names = json_set(
            self.names
                .iter()
                .map(String::as_str)
                .filter(|n| !n.is_empty() && n.len() <= MAX_HOST_NAME_LEN),
            MAX_HOST_NAMES,
        )?;
        conn.prepare_cached(concat!(
            "INSERT INTO hosts (ip, macs, names, country, category, first_ts, last_ts) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT (ip) DO UPDATE SET ",
            json_union!("macs", "?8"),
            ", ",
            json_union!("names", "?9"),
            ", ",
            min_non_null!("hosts", "country"),
            ", ",
            min_non_null!("hosts", "category"),
            ", first_ts = min(hosts.first_ts, excluded.first_ts), \
             last_ts = max(hosts.last_ts, excluded.last_ts)"
        ))?
        .execute(params![
            self.ip.to_string(),
            macs,
            names,
            self.country,
            self.category,
            self.first_ts,
            self.last_ts,
            i64::try_from(MAX_HOST_MACS).unwrap_or(i64::MAX),
            i64::try_from(MAX_HOST_NAMES).unwrap_or(i64::MAX),
        ])?;
        Ok(())
    }
}

/// Lower-case, colon-separated MAC address (`aa:bb:cc:dd:ee:ff`).
pub fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A flow (5-tuple + counters). `fwd` is the initiator -> responder direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRow {
    /// Identifier assigned by the engine, referenced by analyzer tables (at most `i64::MAX`).
    pub id: u64,
    /// IP protocol number (6 TCP, 17 UDP, 1 ICMP...).
    pub transport: u8,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub first_ts: i64,
    pub last_ts: i64,
    pub bytes_fwd: u64,
    pub bytes_rev: u64,
    pub packets_fwd: u64,
    pub packets_rev: u64,
    /// Application protocol (`dns`, `http`, `tls`...), if classified.
    pub app_proto: Option<String>,
    /// Final TCP state, for TCP flows.
    pub tcp_state: Option<String>,
}

impl FlowRow {
    fn insert(&self, conn: &Connection) -> Result<()> {
        conn.prepare_cached(concat!(
            "INSERT INTO flows (id, transport, src_ip, src_port, dst_ip, dst_port, first_ts, \
             last_ts, bytes_fwd, bytes_rev, packets_fwd, packets_rev, app_proto, tcp_state) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14) \
             ON CONFLICT (id) DO UPDATE SET \
             first_ts = min(flows.first_ts, excluded.first_ts), \
             last_ts = max(flows.last_ts, excluded.last_ts), \
             bytes_fwd = max(flows.bytes_fwd, excluded.bytes_fwd), \
             bytes_rev = max(flows.bytes_rev, excluded.bytes_rev), \
             packets_fwd = max(flows.packets_fwd, excluded.packets_fwd), \
             packets_rev = max(flows.packets_rev, excluded.packets_rev), ",
            min_non_null!("flows", "app_proto"),
            ", ",
            min_non_null!("flows", "tcp_state"),
        ))?
        .execute(params![
            id_i64(self.id, "flows.id")?,
            self.transport,
            self.src_ip.to_string(),
            self.src_port,
            self.dst_ip.to_string(),
            self.dst_port,
            self.first_ts,
            self.last_ts,
            sat(self.bytes_fwd),
            sat(self.bytes_rev),
            sat(self.packets_fwd),
            sat(self.packets_rev),
            self.app_proto,
            self.tcp_state,
        ])?;
        Ok(())
    }

    pub(crate) fn from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        let src: String = r.get(2)?;
        let dst: String = r.get(4)?;
        Ok(Self {
            id: r.get(0)?,
            transport: r.get(1)?,
            src_ip: src.parse().map_err(|e| conversion(2, e))?,
            src_port: r.get(3)?,
            dst_ip: dst.parse().map_err(|e| conversion(4, e))?,
            dst_port: r.get(5)?,
            first_ts: r.get(6)?,
            last_ts: r.get(7)?,
            bytes_fwd: r.get(8)?,
            bytes_rev: r.get(9)?,
            packets_fwd: r.get(10)?,
            packets_rev: r.get(11)?,
            app_proto: r.get(12)?,
            tcp_state: r.get(13)?,
        })
    }
}

/// Columns of `flows` in the order expected by [`FlowRow::from_row`].
pub(crate) const FLOW_COLUMNS: &str = "id, transport, src_ip, src_port, dst_ip, dst_port, \
    first_ts, last_ts, bytes_fwd, bytes_rev, packets_fwd, packets_rev, app_proto, tcp_state";

/// Columns of `chunks` in the order expected by [`ChunkRow::from_row`].
pub(crate) const CHUNK_COLUMNS: &str = "id, seq, path, format, compressed, linktypes, snaplen, \
    first_ts, last_ts, packets, bytes, file_size, mtime_ns, head_hash, status";

pub(crate) fn conversion(
    col: usize,
    e: impl std::error::Error + Send + Sync + 'static,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(col, rusqlite::types::Type::Text, Box::new(e))
}

/// True when an error concerns one record only (bad value, constraint violation): the writer
/// then rejects that record and goes on, instead of aborting the whole import.
pub(crate) fn is_row_level(err: &StoreError) -> bool {
    match err {
        StoreError::InvalidValue { .. } | StoreError::Json(_) => true,
        StoreError::Sqlite(e) => {
            matches!(
                e,
                rusqlite::Error::ToSqlConversionFailure(_)
                    | rusqlite::Error::IntegralValueOutOfRange(..)
            ) || e.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation)
        }
        _ => false,
    }
}
