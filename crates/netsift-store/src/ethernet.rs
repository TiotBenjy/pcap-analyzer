//! Tables `eth_macs`, `eth_pairs`, `eth_types` and `eth_vlans` (migration `1100_ethernet.sql`):
//! rows written by the `ethernet` analyzer and the read queries of the Ethernet view.
//!
//! Merge rules (commutative, see `records.rs`): every counter is **added** (saturating at
//! `i64::MAX`), `first_ts` = min, `last_ts` = max, the JSON sets (`vlans`, `ethertypes`) are
//! sorted unions of at most [`MAX_SET`] values; the class columns of an address (`vendor`,
//! `registry`, `kind`, `local`, `grp`) derive from the address and keep their first value; the
//! outer TPID of a VLAN stack is the largest seen.
//!
//! Time range (ADR-030): every row is folded, so a row is kept when its span overlaps the range
//! and its counters stay those of the session.

use std::sync::LazyLock;

use rusqlite::types::Value;
use rusqlite::{Connection, params};

use crate::error::Result;
use crate::query::{Conditions, Keyset, Page, PageRequest, keyset_page};
use crate::range::{TimeRange, and_overlap, query_ranged, query_row_ranged, where_overlap};
use crate::records::{conversion, sat};

/// Largest JSON set kept per row (VLAN stacks, EtherTypes).
pub const MAX_SET: usize = 16;
/// Largest number of EtherType rows returned by [`ethertypes`].
pub const MAX_ETHERTYPES: u32 = 64;
/// Largest number of VLAN rows returned by [`vlans`].
pub const MAX_VLANS: u32 = 200;
/// Largest top N of [`vendor_counts`].
pub const MAX_VENDORS: u32 = 50;

/// Lower-case `aa:bb:cc:dd:ee:ff`.
pub fn mac_text(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Additive delta of one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthMacRow {
    pub mac: [u8; 6],
    pub vendor: Option<String>,
    /// `ma-l`, `ma-m` or `ma-s`.
    pub registry: Option<String>,
    /// `unicast`, `multicast` or `broadcast`.
    pub kind: String,
    pub local: bool,
    /// Well-known group (`ipv4_multicast`, `ipv6_multicast`, `ieee8021_reserved`).
    pub group: Option<String>,
    pub frames_sent: u64,
    pub bytes_sent: u64,
    pub frames_received: u64,
    pub bytes_received: u64,
    pub first_ts: i64,
    pub last_ts: i64,
    /// VLAN stacks (`100`, `100.20`).
    pub vlans: Vec<String>,
}

/// Additive delta of the frames from `src` to `dst`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthPairRow {
    pub src: [u8; 6],
    pub dst: [u8; 6],
    pub frames: u64,
    pub bytes: u64,
    pub first_ts: i64,
    pub last_ts: i64,
    /// EtherType keys (see `eth_types`).
    pub ethertypes: Vec<i32>,
    pub vlans: Vec<String>,
}

/// Additive delta of the frames of one EtherType key (`eth_types`) or VLAN stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthVolume {
    pub frames: u64,
    pub bytes: u64,
    pub first_ts: i64,
    pub last_ts: i64,
}

/// Additive delta of one VLAN stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthVlanRow {
    /// Identifiers outermost first (at least one).
    pub ids: Vec<u16>,
    pub outer_tpid: u16,
    pub volume: EthVolume,
}

impl EthVlanRow {
    /// `100` or `100.20`.
    pub fn stack(&self) -> String {
        self.ids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(".")
    }
}

/// Rows of the `ethernet` analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EthernetRow {
    Mac(EthMacRow),
    Pair(EthPairRow),
    /// EtherType key and its volume.
    Type(i32, EthVolume),
    Vlan(EthVlanRow),
}

/// Sorted union of two JSON arrays, at most [`MAX_SET`] values (`col` of `table`).
fn json_union(table: &str, col: &str) -> String {
    format!(
        "{col} = CASE WHEN excluded.{col} = '[]' THEN {table}.{col} \
         ELSE (SELECT json_group_array(value ORDER BY value) FROM (\
         SELECT value FROM json_each({table}.{col}) UNION \
         SELECT value FROM json_each(excluded.{col}) ORDER BY 1 LIMIT {MAX_SET})) END"
    )
}

fn add(col: &str) -> String {
    format!("{col} = min({col} + excluded.{col}, 9223372036854775807)")
}

static MAC_UPSERT: LazyLock<String> = LazyLock::new(|| {
    let sums = [
        "frames_sent",
        "bytes_sent",
        "frames_received",
        "bytes_received",
    ]
    .map(add)
    .join(", ");
    format!(
        "INSERT INTO eth_macs (mac, vendor, registry, kind, local, grp, frames_sent, bytes_sent, \
         frames_received, bytes_received, first_ts, last_ts, vlans) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13) \
         ON CONFLICT (mac) DO UPDATE SET {sums}, \
         first_ts = min(first_ts, excluded.first_ts), last_ts = max(last_ts, excluded.last_ts), \
         {}",
        json_union("eth_macs", "vlans")
    )
});

static PAIR_UPSERT: LazyLock<String> = LazyLock::new(|| {
    format!(
        "INSERT INTO eth_pairs (src_mac, dst_mac, frames, bytes, first_ts, last_ts, ethertypes, \
         vlans) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
         ON CONFLICT (src_mac, dst_mac) DO UPDATE SET {}, {}, \
         first_ts = min(first_ts, excluded.first_ts), last_ts = max(last_ts, excluded.last_ts), \
         {}, {}",
        add("frames"),
        add("bytes"),
        json_union("eth_pairs", "ethertypes"),
        json_union("eth_pairs", "vlans")
    )
});

/// Sorted, deduplicated, bounded JSON array.
fn json_set<T: Ord + Clone + Into<serde_json::Value>>(values: &[T]) -> Result<String> {
    let mut v: Vec<T> = values.to_vec();
    v.sort_unstable();
    v.dedup();
    v.truncate(MAX_SET);
    let array = serde_json::Value::Array(v.into_iter().map(Into::into).collect());
    Ok(serde_json::to_string(&array)?)
}

impl EthernetRow {
    /// Table written by the row (key of the writer statistics).
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Mac(_) => "eth_macs",
            Self::Pair(_) => "eth_pairs",
            Self::Type(..) => "eth_types",
            Self::Vlan(_) => "eth_vlans",
        }
    }

    pub(crate) fn insert(&self, conn: &Connection) -> Result<()> {
        match self {
            Self::Mac(r) => {
                conn.prepare_cached(&MAC_UPSERT)?.execute(params![
                    mac_text(r.mac),
                    r.vendor,
                    r.registry,
                    r.kind,
                    r.local,
                    r.group,
                    sat(r.frames_sent),
                    sat(r.bytes_sent),
                    sat(r.frames_received),
                    sat(r.bytes_received),
                    r.first_ts,
                    r.last_ts,
                    json_set(&r.vlans)?,
                ])?;
            }
            Self::Pair(r) => {
                conn.prepare_cached(&PAIR_UPSERT)?.execute(params![
                    mac_text(r.src),
                    mac_text(r.dst),
                    sat(r.frames),
                    sat(r.bytes),
                    r.first_ts,
                    r.last_ts,
                    json_set(&r.ethertypes)?,
                    json_set(&r.vlans)?,
                ])?;
            }
            Self::Type(key, v) => {
                conn.prepare_cached(
                    "INSERT INTO eth_types (ethertype, frames, bytes, first_ts, last_ts) \
                     VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT (ethertype) DO UPDATE SET \
                     frames = min(frames + excluded.frames, 9223372036854775807), \
                     bytes = min(bytes + excluded.bytes, 9223372036854775807), \
                     first_ts = min(first_ts, excluded.first_ts), \
                     last_ts = max(last_ts, excluded.last_ts)",
                )?
                .execute(params![
                    key,
                    sat(v.frames),
                    sat(v.bytes),
                    v.first_ts,
                    v.last_ts
                ])?;
            }
            Self::Vlan(r) => {
                let (Some(outer), Some(inner)) = (r.ids.first(), r.ids.last()) else {
                    return Ok(());
                };
                conn.prepare_cached(
                    "INSERT INTO eth_vlans (stack, outer_id, inner_id, depth, outer_tpid, frames, \
                     bytes, first_ts, last_ts) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
                     ON CONFLICT (stack) DO UPDATE SET \
                     outer_tpid = max(outer_tpid, excluded.outer_tpid), \
                     frames = min(frames + excluded.frames, 9223372036854775807), \
                     bytes = min(bytes + excluded.bytes, 9223372036854775807), \
                     first_ts = min(first_ts, excluded.first_ts), \
                     last_ts = max(last_ts, excluded.last_ts)",
                )?
                .execute(params![
                    r.stack(),
                    outer,
                    inner,
                    r.ids.len(),
                    r.outer_tpid,
                    sat(r.volume.frames),
                    sat(r.volume.bytes),
                    r.volume.first_ts,
                    r.volume.last_ts,
                ])?;
            }
        }
        Ok(())
    }
}

// --- read queries ------------------------------------------------------------------------

/// What the session knows about one address (class columns of `eth_macs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacRef {
    pub mac: String,
    pub vendor: Option<String>,
    pub kind: String,
    pub local: bool,
    pub group: Option<String>,
}

/// One stored address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacEntry {
    pub addr: MacRef,
    pub registry: Option<String>,
    pub frames_sent: u64,
    pub bytes_sent: u64,
    pub frames_received: u64,
    pub bytes_received: u64,
    pub first_ts: i64,
    pub last_ts: i64,
    pub vlans: Vec<String>,
}

/// Class filter of the address list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacClass {
    /// Unicast addresses (devices).
    Unicast,
    /// Locally administered unicast addresses (not registered, possibly random).
    Local,
    /// Multicast and broadcast addresses.
    Group,
}

/// A vendor bar: one IEEE organization, or the unicast addresses without one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VendorKey {
    Named(String),
    /// Locally administered unicast addresses.
    Local,
    /// Universally administered unicast addresses of an unlisted prefix.
    Unknown,
}

/// Filters of [`macs_page`] (all optional).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MacFilter {
    /// Part of the address (`08:00:27`, `08-00-27`, `080027`) or of the vendor name.
    pub q: Option<String>,
    pub class: Option<MacClass>,
    pub vendor: Option<VendorKey>,
    /// VLAN stack (`10`, `100.20`).
    pub vlan: Option<String>,
    pub range: Option<TimeRange>,
}

/// Sort orders of [`macs_page`]: counters and last activity descending, first activity and
/// address ascending.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MacSort {
    #[default]
    Frames,
    Bytes,
    FirstSeen,
    LastSeen,
    Mac,
}

impl MacSort {
    fn key(self) -> (&'static str, bool) {
        match self {
            Self::Frames => ("m.frames_total", true),
            Self::Bytes => ("m.bytes_total", true),
            Self::FirstSeen => ("m.first_ts", false),
            Self::LastSeen => ("m.last_ts", true),
            Self::Mac => ("m.mac", false),
        }
    }
}

/// `%q%` (LIKE wildcards escaped) for the vendor, and the same with the address normalized
/// (lower case, `-` and `.` as `:`, bare hex digits grouped by two) for the address.
fn search_patterns(q: &str) -> Option<(String, String)> {
    let q = q.trim();
    if q.is_empty() {
        return None;
    }
    let like = |s: &str| {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('%');
        for c in s.chars() {
            if matches!(c, '%' | '_' | '\\') {
                out.push('\\');
            }
            out.push(c);
        }
        out.push('%');
        out
    };
    let lower = q.to_ascii_lowercase();
    let mac = if lower.len() >= 4
        && lower.len() <= 12
        && lower.len().is_multiple_of(2)
        && lower.bytes().all(|b| b.is_ascii_hexdigit())
    {
        lower
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap_or_default())
            .collect::<Vec<_>>()
            .join(":")
    } else {
        lower.replace(['-', '.'], ":")
    };
    Some((like(&mac), like(q)))
}

fn mac_conditions(f: &MacFilter) -> Conditions {
    let mut c = Conditions::new();
    if let Some((mac, text)) = f.q.as_deref().and_then(search_patterns) {
        c.push(
            "m.mac LIKE ? ESCAPE '\\' OR m.vendor LIKE ? ESCAPE '\\'",
            [Value::Text(mac), Value::Text(text)],
        );
    }
    match f.class {
        None => {}
        Some(MacClass::Unicast) => c.push("m.kind = 'unicast'", []),
        Some(MacClass::Local) => c.push("m.kind = 'unicast' AND m.local = 1", []),
        Some(MacClass::Group) => c.push("m.kind != 'unicast'", []),
    }
    match &f.vendor {
        None => {}
        Some(VendorKey::Named(v)) => c.push(
            "m.kind = 'unicast' AND m.local = 0 AND m.vendor = ?",
            [Value::Text(v.clone())],
        ),
        Some(VendorKey::Local) => c.push("m.kind = 'unicast' AND m.local = 1", []),
        Some(VendorKey::Unknown) => {
            c.push(
                "m.kind = 'unicast' AND m.local = 0 AND m.vendor IS NULL",
                [],
            );
        }
    }
    if let Some(v) = &f.vlan {
        c.push(
            "EXISTS (SELECT 1 FROM json_each(m.vlans) WHERE value = ?)",
            [Value::Text(v.clone())],
        );
    }
    if let Some(r) = f.range {
        r.push_overlap(&mut c, "m.first_ts", "m.last_ts");
    }
    c
}

const MAC_SELECT: &str = "m.mac, m.vendor, m.kind, m.local, m.grp, m.registry, m.frames_sent, \
    m.bytes_sent, m.frames_received, m.bytes_received, m.first_ts, m.last_ts, m.vlans";

fn count(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn json_strings(raw: &str, col: usize) -> rusqlite::Result<Vec<String>> {
    serde_json::from_str(raw).map_err(|e| conversion(col, e))
}

fn mac_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<MacEntry> {
    Ok(MacEntry {
        addr: MacRef {
            mac: r.get(0)?,
            vendor: r.get(1)?,
            kind: r.get(2)?,
            local: r.get(3)?,
            group: r.get(4)?,
        },
        registry: r.get(5)?,
        frames_sent: count(r.get(6)?),
        bytes_sent: count(r.get(7)?),
        frames_received: count(r.get(8)?),
        bytes_received: count(r.get(9)?),
        first_ts: r.get(10)?,
        last_ts: r.get(11)?,
        vlans: json_strings(&r.get::<_, String>(12)?, 12)?,
    })
}

/// One page of addresses.
pub fn macs_page(
    conn: &Connection,
    filter: &MacFilter,
    sort: MacSort,
    request: &PageRequest,
) -> Result<Page<MacEntry>> {
    let c = mac_conditions(filter);
    let where_sql = c.sql();
    let (sort, descending) = sort.key();
    let query = Keyset {
        from: "eth_macs m",
        select: MAC_SELECT,
        sort,
        tiebreak: "m.mac",
        descending,
        filter: where_sql.as_deref(),
    };
    keyset_page(conn, &query, &c.params(), request, mac_entry)
}

/// Number of addresses matching `filter`.
pub fn count_macs(conn: &Connection, filter: &MacFilter) -> Result<u64> {
    let c = mac_conditions(filter);
    let w = c.sql().map_or_else(String::new, |s| format!(" WHERE {s}"));
    let n: i64 = conn.query_row(
        &format!("SELECT count(*) FROM eth_macs m{w}"),
        c.params().as_slice(),
        |r| r.get(0),
    )?;
    Ok(count(n))
}

/// One stored pair, with the class columns of both addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairEntry {
    pub id: i64,
    pub src: MacRef,
    pub dst: MacRef,
    pub frames: u64,
    pub bytes: u64,
    pub first_ts: i64,
    pub last_ts: i64,
    pub ethertypes: Vec<i32>,
    pub vlans: Vec<String>,
}

/// Filters of [`pairs_page`] (all optional).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PairFilter {
    /// Part of either address or of either vendor name.
    pub q: Option<String>,
    /// Pairs of this address, as source or destination (lower-case text).
    pub mac: Option<String>,
    pub vlan: Option<String>,
    /// EtherType key (see `eth_types`).
    pub ethertype: Option<i32>,
    pub range: Option<TimeRange>,
}

/// Sort orders of [`pairs_page`] (as [`MacSort`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PairSort {
    #[default]
    Frames,
    Bytes,
    FirstSeen,
    LastSeen,
}

impl PairSort {
    fn key(self) -> (&'static str, bool) {
        match self {
            Self::Frames => ("p.frames", true),
            Self::Bytes => ("p.bytes", true),
            Self::FirstSeen => ("p.first_ts", false),
            Self::LastSeen => ("p.last_ts", true),
        }
    }
}

const PAIR_FROM: &str = "eth_pairs p LEFT JOIN eth_macs s ON s.mac = p.src_mac \
    LEFT JOIN eth_macs d ON d.mac = p.dst_mac";
const PAIR_SELECT: &str = "p.id, p.src_mac, s.vendor, s.kind, s.local, s.grp, p.dst_mac, \
    d.vendor, d.kind, d.local, d.grp, p.frames, p.bytes, p.first_ts, p.last_ts, p.ethertypes, \
    p.vlans";

fn pair_conditions(f: &PairFilter) -> Conditions {
    let mut c = Conditions::new();
    if let Some((mac, text)) = f.q.as_deref().and_then(search_patterns) {
        c.push(
            "p.src_mac LIKE ? ESCAPE '\\' OR p.dst_mac LIKE ? ESCAPE '\\' \
             OR s.vendor LIKE ? ESCAPE '\\' OR d.vendor LIKE ? ESCAPE '\\'",
            [
                Value::Text(mac.clone()),
                Value::Text(mac),
                Value::Text(text.clone()),
                Value::Text(text),
            ],
        );
    }
    if let Some(m) = &f.mac {
        let m = m.trim().to_ascii_lowercase().replace('-', ":");
        c.push(
            "p.src_mac = ? OR p.dst_mac = ?",
            [Value::Text(m.clone()), Value::Text(m)],
        );
    }
    if let Some(v) = &f.vlan {
        c.push(
            "EXISTS (SELECT 1 FROM json_each(p.vlans) WHERE value = ?)",
            [Value::Text(v.clone())],
        );
    }
    if let Some(t) = f.ethertype {
        c.push(
            "EXISTS (SELECT 1 FROM json_each(p.ethertypes) WHERE value = ?)",
            [Value::Integer(i64::from(t))],
        );
    }
    if let Some(r) = f.range {
        r.push_overlap(&mut c, "p.first_ts", "p.last_ts");
    }
    c
}

fn mac_ref(r: &rusqlite::Row<'_>, at: usize) -> rusqlite::Result<MacRef> {
    Ok(MacRef {
        mac: r.get(at)?,
        vendor: r.get(at + 1)?,
        // A pair always has both addresses in `eth_macs` (same flush); defaults for safety.
        kind: r
            .get::<_, Option<String>>(at + 2)?
            .unwrap_or_else(|| "unicast".to_owned()),
        local: r.get::<_, Option<bool>>(at + 3)?.unwrap_or(false),
        group: r.get(at + 4)?,
    })
}

fn pair_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<PairEntry> {
    let types: String = r.get(15)?;
    Ok(PairEntry {
        id: r.get(0)?,
        src: mac_ref(r, 1)?,
        dst: mac_ref(r, 6)?,
        frames: count(r.get(11)?),
        bytes: count(r.get(12)?),
        first_ts: r.get(13)?,
        last_ts: r.get(14)?,
        ethertypes: serde_json::from_str(&types).map_err(|e| conversion(15, e))?,
        vlans: json_strings(&r.get::<_, String>(16)?, 16)?,
    })
}

/// One page of pairs.
pub fn pairs_page(
    conn: &Connection,
    filter: &PairFilter,
    sort: PairSort,
    request: &PageRequest,
) -> Result<Page<PairEntry>> {
    let c = pair_conditions(filter);
    let where_sql = c.sql();
    let (sort, descending) = sort.key();
    let query = Keyset {
        from: PAIR_FROM,
        select: PAIR_SELECT,
        sort,
        tiebreak: "p.id",
        descending,
        filter: where_sql.as_deref(),
    };
    keyset_page(conn, &query, &c.params(), request, pair_entry)
}

/// Number of pairs matching `filter`.
pub fn count_pairs(conn: &Connection, filter: &PairFilter) -> Result<u64> {
    let c = pair_conditions(filter);
    // The joins are only needed by the vendor search.
    let from = if filter.q.is_some() {
        PAIR_FROM
    } else {
        "eth_pairs p"
    };
    let w = c.sql().map_or_else(String::new, |s| format!(" WHERE {s}"));
    let n: i64 = conn.query_row(
        &format!("SELECT count(*) FROM {from}{w}"),
        c.params().as_slice(),
        |r| r.get(0),
    )?;
    Ok(count(n))
}

/// Counters of the Ethernet view, over `range` when set (rows that overlap it).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EthCounts {
    pub macs: u64,
    /// Unicast addresses (devices), universally or locally administered.
    pub unicast: u64,
    /// Locally administered unicast addresses.
    pub local: u64,
    /// Multicast and broadcast addresses.
    pub group: u64,
    /// Distinct vendors of the universally administered unicast addresses.
    pub vendors: u64,
    pub pairs: u64,
    pub vlans: u64,
    /// Frames and bytes of the EtherType rows (session counters).
    pub frames: u64,
    pub bytes: u64,
    /// Frames of the VLAN rows (session counters).
    pub tagged_frames: u64,
}

/// See [`EthCounts`].
pub fn counts(conn: &Connection, range: Option<TimeRange>) -> Result<EthCounts> {
    let w = where_overlap(range, "first_ts", "last_ts");
    let (macs, unicast, local, group, vendors) = query_row_ranged(
        conn,
        &format!(
            "SELECT count(*), coalesce(sum(kind = 'unicast'), 0), \
             coalesce(sum(kind = 'unicast' AND local = 1), 0), \
             coalesce(sum(kind != 'unicast'), 0), \
             count(DISTINCT CASE WHEN kind = 'unicast' AND local = 0 THEN vendor END) \
             FROM eth_macs{w}"
        ),
        &[],
        range,
        |r| {
            Ok((
                count(r.get(0)?),
                count(r.get(1)?),
                count(r.get(2)?),
                count(r.get(3)?),
                count(r.get(4)?),
            ))
        },
    )?;
    let pairs: i64 = query_row_ranged(
        conn,
        &format!("SELECT count(*) FROM eth_pairs{w}"),
        &[],
        range,
        |r| r.get(0),
    )?;
    let (frames, bytes) = query_row_ranged(
        conn,
        &format!("SELECT coalesce(sum(frames), 0), coalesce(sum(bytes), 0) FROM eth_types{w}"),
        &[],
        range,
        |r| Ok((count(r.get(0)?), count(r.get(1)?))),
    )?;
    let (vlans, tagged_frames) = query_row_ranged(
        conn,
        &format!("SELECT count(*), coalesce(sum(frames), 0) FROM eth_vlans{w}"),
        &[],
        range,
        |r| Ok((count(r.get(0)?), count(r.get(1)?))),
    )?;
    Ok(EthCounts {
        macs,
        unicast,
        local,
        group,
        vendors,
        pairs: count(pairs),
        vlans,
        frames,
        bytes,
        tagged_frames,
    })
}

/// Unicast addresses per vendor, most common first (at most `limit`, clamped to
/// [`MAX_VENDORS`]); the addresses of the other vendors are `unicast` minus their sum.
pub fn vendor_counts(
    conn: &Connection,
    limit: u32,
    range: Option<TimeRange>,
) -> Result<Vec<(VendorKey, u64)>> {
    let a = and_overlap(range, "first_ts", "last_ts");
    query_ranged(
        conn,
        &format!(
            "SELECT local, CASE WHEN local = 1 THEN NULL ELSE vendor END AS v, count(*) AS n \
             FROM eth_macs WHERE kind = 'unicast'{a} GROUP BY local, v \
             ORDER BY n DESC, local, v IS NULL, v LIMIT ?1"
        ),
        &[&limit.min(MAX_VENDORS)],
        range,
        |r| {
            let local: bool = r.get(0)?;
            let vendor: Option<String> = r.get(1)?;
            let key = match (local, vendor) {
                (true, _) => VendorKey::Local,
                (false, Some(v)) => VendorKey::Named(v),
                (false, None) => VendorKey::Unknown,
            };
            Ok((key, count(r.get(2)?)))
        },
    )
}

/// One EtherType key with its volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthTypeEntry {
    pub ethertype: i32,
    pub volume: EthVolume,
}

fn volume(r: &rusqlite::Row<'_>, at: usize) -> rusqlite::Result<EthVolume> {
    Ok(EthVolume {
        frames: count(r.get(at)?),
        bytes: count(r.get(at + 1)?),
        first_ts: r.get(at + 2)?,
        last_ts: r.get(at + 3)?,
    })
}

/// EtherType keys by frames, at most [`MAX_ETHERTYPES`] (the others are summed by the caller
/// from [`counts`]).
pub fn ethertypes(conn: &Connection, range: Option<TimeRange>) -> Result<Vec<EthTypeEntry>> {
    let w = where_overlap(range, "first_ts", "last_ts");
    query_ranged(
        conn,
        &format!(
            "SELECT ethertype, frames, bytes, first_ts, last_ts FROM eth_types{w} \
             ORDER BY frames DESC, ethertype LIMIT {MAX_ETHERTYPES}"
        ),
        &[],
        range,
        |r| {
            Ok(EthTypeEntry {
                ethertype: r.get(0)?,
                volume: volume(r, 1)?,
            })
        },
    )
}

/// One VLAN stack with its volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthVlanEntry {
    pub stack: String,
    pub outer_id: u16,
    pub inner_id: u16,
    pub depth: u8,
    pub outer_tpid: u16,
    pub volume: EthVolume,
}

/// VLAN stacks by frames, at most [`MAX_VLANS`].
pub fn vlans(conn: &Connection, range: Option<TimeRange>) -> Result<Vec<EthVlanEntry>> {
    let w = where_overlap(range, "first_ts", "last_ts");
    query_ranged(
        conn,
        &format!(
            "SELECT stack, outer_id, inner_id, depth, outer_tpid, frames, bytes, first_ts, \
             last_ts FROM eth_vlans{w} ORDER BY frames DESC, stack LIMIT {MAX_VLANS}"
        ),
        &[],
        range,
        |r| {
            Ok(EthVlanEntry {
                stack: r.get(0)?,
                outer_id: r.get(1)?,
                inner_id: r.get(2)?,
                depth: r.get(3)?,
                outer_tpid: r.get(4)?,
                volume: volume(r, 5)?,
            })
        },
    )
}

#[cfg(test)]
mod tests;
