//! Ethernet view routes (`docs/specs/ethernet.md`): MAC addresses with their IEEE vendor and
//! class, pairs (source -> destination), EtherTypes and VLANs.
//!
//! | Method | Path | Response |
//! |---|---|---|
//! | GET | `/sessions/{id}/ethernet/stats` | [`EthernetStats`] |
//! | GET | `/sessions/{id}/ethernet/macs` | [`Page`](crate::contract::Page)`<`[`MacInfo`]`>` |
//! | GET | `/sessions/{id}/ethernet/pairs` | [`Page`](crate::contract::Page)`<`[`MacPairInfo`]`>` |
//!
//! Every route accepts the time range (`from_us`, `to_us`, ADR-030). The tables are folded: under
//! a range, the rows whose span overlaps it are kept with their session counters (frames,
//! bytes), which the view marks as "whole session".

use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::routing::get;
use axum::{Json, Router};
use netsift_store::PageRequest;
use netsift_store::ethernet::{
    self, EthTypeEntry, EthVlanEntry, MacClass, MacEntry, MacFilter, MacRef, MacSort, PairEntry,
    PairFilter, PairSort, VendorKey,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::contract::Page;
use crate::extract::ApiQuery;
use crate::overview::open_ready;
use crate::range::ApiRange;
use crate::sessions::parse_id;
use crate::{ApiError, AppState, blocking, convert};

/// Vendor bars returned by `/ethernet/stats` (the others are summed in `vendors_other`).
const VENDOR_TOP: u32 = 12;
/// Vendor filter values that select the unicast addresses without vendor.
const VENDOR_LOCAL: &str = "~local";
const VENDOR_UNKNOWN: &str = "~unknown";

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sessions/{id}/ethernet/stats", get(stats))
        .route("/sessions/{id}/ethernet/macs", get(macs))
        .route("/sessions/{id}/ethernet/pairs", get(pairs))
}

/// Unicast, multicast or broadcast (I/G bit of the address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum MacKind {
    Unicast,
    Multicast,
    Broadcast,
}

impl MacKind {
    fn parse(s: &str) -> Self {
        match s {
            "multicast" => Self::Multicast,
            "broadcast" => Self::Broadcast,
            _ => Self::Unicast,
        }
    }
}

/// A MAC address with what the session knows about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MacAddress {
    /// Lower-case `aa:bb:cc:dd:ee:ff`.
    pub mac: String,
    /// IEEE organization of the prefix (universally administered addresses only).
    pub vendor: Option<String>,
    pub kind: MacKind,
    /// Locally administered (U/L bit): never registered, possibly random.
    pub local: bool,
    /// Well-known group: `ipv4_multicast`, `ipv6_multicast` or `ieee8021_reserved`.
    pub group: Option<String>,
}

fn address(r: MacRef) -> MacAddress {
    MacAddress {
        kind: MacKind::parse(&r.kind),
        mac: r.mac,
        vendor: r.vendor,
        local: r.local,
        group: r.group,
    }
}

/// One row of the address list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MacInfo {
    pub address: MacAddress,
    /// IEEE registry of the vendor's prefix: `ma-l` (24 bits), `ma-m` (28) or `ma-s` (36).
    pub registry: Option<String>,
    pub frames_sent: u64,
    pub bytes_sent: u64,
    pub frames_received: u64,
    pub bytes_received: u64,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
    /// VLAN stacks of its frames (`10`, `100.20` for Q-in-Q), at most 16.
    pub vlans: Vec<String>,
}

fn mac_info(e: MacEntry) -> MacInfo {
    MacInfo {
        address: address(e.addr),
        registry: e.registry,
        frames_sent: e.frames_sent,
        bytes_sent: e.bytes_sent,
        frames_received: e.frames_received,
        bytes_received: e.bytes_received,
        first_ts_us: convert::us(e.first_ts),
        last_ts_us: convert::us(e.last_ts),
        vlans: e.vlans,
    }
}

/// What a frame carries: an EtherType, or an 802.2 LLC header without EtherType.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum EtherKind {
    /// `value` is an EtherType (0x0600-0xffff).
    Ethertype,
    /// `value` is the DSAP of an 802.2 LLC header (802.3 framing).
    Llc,
    /// Truncated link header (`value` = -1).
    Unknown,
}

/// An EtherType (or LLC service access point) with its usual protocol name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct EtherTypeRef {
    /// Stored key: the EtherType, the DSAP (0-255) or -1.
    pub value: i32,
    pub kind: EtherKind,
    /// `0x0800`, or `0x42` for an LLC service access point; empty when unknown.
    pub code: String,
    /// Protocol name (`IPv4`, `LLDP`, `Spanning tree`...), when well known.
    pub name: Option<String>,
}

fn ether_ref(value: i32) -> EtherTypeRef {
    let (kind, code, name) = match (value, u16::try_from(value)) {
        (0x0600.., Ok(t)) => (EtherKind::Ethertype, format!("{t:#06x}"), ethertype_name(t)),
        (0..=0xff, Ok(sap)) => (
            EtherKind::Llc,
            format!("{sap:#04x}"),
            u8::try_from(sap).ok().and_then(llc_sap_name),
        ),
        _ => (EtherKind::Unknown, String::new(), None),
    };
    EtherTypeRef {
        value,
        kind,
        code,
        name: name.map(str::to_owned),
    }
}

/// Usual name of an EtherType (IEEE EtherType registry and common usage).
fn ethertype_name(t: u16) -> Option<&'static str> {
    Some(match t {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x0842 => "Wake-on-LAN",
        0x22f3 => "TRILL",
        0x6002 => "DEC MOP",
        0x8035 => "RARP",
        0x809b => "AppleTalk",
        0x80f3 => "AARP",
        0x8100 => "802.1Q",
        0x8137 | 0x8138 => "IPX",
        0x86dd => "IPv6",
        0x8808 => "Ethernet flow control",
        0x8809 => "Slow protocols (LACP)",
        0x8847 => "MPLS",
        0x8848 => "MPLS multicast",
        0x8863 => "PPPoE discovery",
        0x8864 => "PPPoE session",
        0x887b => "HomePlug",
        0x888e => "802.1X (EAPOL)",
        0x8892 => "PROFINET",
        0x88a2 => "ATA over Ethernet",
        0x88a4 => "EtherCAT",
        0x88a8 => "802.1ad",
        0x88ab => "Ethernet Powerlink",
        0x88b5 => "Local experimental 1",
        0x88b6 => "Local experimental 2",
        0x88b8 => "IEC 61850 GOOSE",
        0x88ba => "IEC 61850 SV",
        0x88c7 => "802.11 pre-authentication",
        0x88cc => "LLDP",
        0x88cd => "SERCOS III",
        0x88e1 => "HomePlug AV",
        0x88e3 => "MRP",
        0x88e5 => "MACsec",
        0x88e7 => "802.1ah (PBB)",
        0x88f7 => "PTP",
        0x88f8 => "NC-SI",
        0x88fb => "PRP",
        0x8902 => "CFM (802.1ag)",
        0x8906 => "FCoE",
        0x8914 => "FCoE initialization",
        0x8915 => "RoCE",
        0x892f => "HSR",
        0x893a => "IEEE 1905.1",
        0x9000 => "Loopback (CTP)",
        0x9100 => "Q-in-Q",
        _ => return None,
    })
}

/// Usual name of an 802.2 LLC service access point.
fn llc_sap_name(sap: u8) -> Option<&'static str> {
    Some(match sap {
        0x00 => "LLC null SAP",
        0x04 | 0x05 => "SNA",
        0x06 => "IP (LLC)",
        0x42 => "Spanning tree",
        0xaa => "SNAP",
        0xe0 => "IPX (LLC)",
        0xf0 => "NetBIOS",
        0xf4 => "LAN management",
        0xfe => "OSI (IS-IS, CLNP)",
        _ => return None,
    })
}

/// One row of the pair list (directional).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct MacPairInfo {
    /// Row id as a string (stable key within a session).
    pub id: String,
    pub src: MacAddress,
    pub dst: MacAddress,
    pub frames: u64,
    pub bytes: u64,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
    /// At most 16.
    pub ethertypes: Vec<EtherTypeRef>,
    /// VLAN stacks, at most 16.
    pub vlans: Vec<String>,
}

fn pair_info(e: PairEntry) -> MacPairInfo {
    MacPairInfo {
        id: e.id.to_string(),
        src: address(e.src),
        dst: address(e.dst),
        frames: e.frames,
        bytes: e.bytes,
        first_ts_us: convert::us(e.first_ts),
        last_ts_us: convert::us(e.last_ts),
        ethertypes: e.ethertypes.into_iter().map(ether_ref).collect(),
        vlans: e.vlans,
    }
}

/// How a vendor bar groups its addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum VendorKind {
    /// One IEEE organization (`name`).
    Named,
    /// Locally administered unicast addresses (no vendor by definition).
    Local,
    /// Universally administered unicast addresses of an unlisted prefix.
    Unknown,
}

/// One vendor bar: unicast addresses of one vendor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct VendorSlice {
    /// Value of the `vendor` filter of `/ethernet/macs` (`~local`, `~unknown` or the name).
    pub key: String,
    pub kind: VendorKind,
    pub name: Option<String>,
    pub count: u64,
}

fn vendor_slice((key, count): (VendorKey, u64)) -> VendorSlice {
    let (key, kind, name) = match key {
        VendorKey::Named(n) => (n.clone(), VendorKind::Named, Some(n)),
        VendorKey::Local => (VENDOR_LOCAL.to_owned(), VendorKind::Local, None),
        VendorKey::Unknown => (VENDOR_UNKNOWN.to_owned(), VendorKind::Unknown, None),
    };
    VendorSlice {
        key,
        kind,
        name,
        count,
    }
}

/// Frames of one EtherType (session counters).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct EtherTypeInfo {
    pub ethertype: EtherTypeRef,
    pub frames: u64,
    pub bytes: u64,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
}

fn ethertype_info(e: EthTypeEntry) -> EtherTypeInfo {
    EtherTypeInfo {
        ethertype: ether_ref(e.ethertype),
        frames: e.volume.frames,
        bytes: e.volume.bytes,
        first_ts_us: convert::us(e.volume.first_ts),
        last_ts_us: convert::us(e.volume.last_ts),
    }
}

/// Frames of one VLAN stack (session counters).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct VlanInfo {
    /// `10`, or `100.20` for a service tag 100 carrying a customer tag 20.
    pub stack: String,
    pub outer_id: u16,
    pub inner_id: u16,
    /// Number of tags.
    pub depth: u8,
    /// TPID of the outer tag: `0x8100` (802.1Q), `0x88a8` (802.1ad) or `0x9100`.
    pub outer_tpid: u16,
    pub frames: u64,
    pub bytes: u64,
    pub first_ts_us: i64,
    pub last_ts_us: i64,
}

fn vlan_info(e: EthVlanEntry) -> VlanInfo {
    VlanInfo {
        stack: e.stack,
        outer_id: e.outer_id,
        inner_id: e.inner_id,
        depth: e.depth,
        outer_tpid: e.outer_tpid,
        frames: e.volume.frames,
        bytes: e.volume.bytes,
        first_ts_us: convert::us(e.volume.first_ts),
        last_ts_us: convert::us(e.volume.last_ts),
    }
}

/// `GET /ethernet/stats`: counters, vendor bars, EtherTypes and VLANs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[ts(export)]
pub struct EthernetStats {
    pub mac_count: u64,
    /// Unicast addresses (devices), local ones included.
    pub unicast_count: u64,
    /// Locally administered unicast addresses.
    pub local_count: u64,
    /// Multicast and broadcast addresses.
    pub group_count: u64,
    /// Distinct vendors of the universally administered unicast addresses.
    pub vendor_count: u64,
    pub pair_count: u64,
    pub vlan_count: u64,
    /// Frames and bytes counted by EtherType (session counters).
    pub frames: u64,
    pub bytes: u64,
    /// Frames with at least one VLAN tag (session counters).
    pub tagged_frames: u64,
    /// Unicast addresses per vendor, most common first (at most 12).
    pub vendors: Vec<VendorSlice>,
    /// Unicast addresses of the vendors beyond `vendors`.
    pub vendors_other: u64,
    /// By frames, at most 64.
    pub ethertypes: Vec<EtherTypeInfo>,
    /// By frames, at most 200 (`vlan_count` gives the total).
    pub vlans: Vec<VlanInfo>,
}

#[derive(Debug, Default, Deserialize)]
struct MacQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    /// `frames` (default), `bytes`, `first_seen`, `last_seen` or `mac`.
    sort: Option<String>,
    q: Option<String>,
    /// `unicast`, `local` or `group`.
    class: Option<String>,
    /// Vendor name, `~local` or `~unknown` (keys of the vendor bars).
    vendor: Option<String>,
    vlan: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PairQuery {
    limit: Option<u32>,
    cursor: Option<String>,
    /// `frames` (default), `bytes`, `first_seen` or `last_seen`.
    sort: Option<String>,
    q: Option<String>,
    /// Pairs of this address, as source or destination.
    mac: Option<String>,
    vlan: Option<String>,
    /// EtherType key (`2048` or `0x0800`; `66` or `0x42` for an LLC DSAP).
    ethertype: Option<String>,
}

fn non_empty(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

fn bad(field: &str, reason: &str) -> ApiError {
    ApiError::BadRequest(format!("{field}: {reason}"))
}

fn mac_sort(raw: Option<&str>) -> Result<MacSort, ApiError> {
    Ok(match raw {
        None | Some("frames") => MacSort::Frames,
        Some("bytes") => MacSort::Bytes,
        Some("first_seen") => MacSort::FirstSeen,
        Some("last_seen") => MacSort::LastSeen,
        Some("mac") => MacSort::Mac,
        Some(_) => return Err(bad("sort", "unknown sort order")),
    })
}

fn pair_sort(raw: Option<&str>) -> Result<PairSort, ApiError> {
    Ok(match raw {
        None | Some("frames") => PairSort::Frames,
        Some("bytes") => PairSort::Bytes,
        Some("first_seen") => PairSort::FirstSeen,
        Some("last_seen") => PairSort::LastSeen,
        Some(_) => return Err(bad("sort", "unknown sort order")),
    })
}

fn mac_class(raw: Option<&str>) -> Result<Option<MacClass>, ApiError> {
    Ok(match raw {
        None => None,
        Some("unicast") => Some(MacClass::Unicast),
        Some("local") => Some(MacClass::Local),
        Some("group") => Some(MacClass::Group),
        Some(_) => return Err(bad("class", "expected unicast, local or group")),
    })
}

fn vendor_key(raw: Option<String>) -> Option<VendorKey> {
    raw.map(|v| match v.as_str() {
        VENDOR_LOCAL => VendorKey::Local,
        VENDOR_UNKNOWN => VendorKey::Unknown,
        _ => VendorKey::Named(v),
    })
}

/// A VLAN stack: one to four identifiers (0-4095) separated by dots.
fn vlan_stack(raw: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(raw) = raw else { return Ok(None) };
    let ids: Vec<&str> = raw.split('.').collect();
    let valid = ids.len() <= 4
        && ids
            .iter()
            .all(|id| id.parse::<u16>().is_ok_and(|v| v <= 4095) && !id.starts_with('+'));
    if !valid {
        return Err(bad("vlan", "expected identifiers separated by dots"));
    }
    Ok(Some(raw))
}

fn ethertype_key(raw: Option<&str>) -> Result<Option<i32>, ApiError> {
    let Some(raw) = raw else { return Ok(None) };
    let parsed = match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        Some(hex) => i32::from_str_radix(hex, 16).ok(),
        None => raw.parse::<i32>().ok(),
    };
    match parsed {
        Some(v) if (-1..=0xffff).contains(&v) => Ok(Some(v)),
        _ => Err(bad("ethertype", "expected an EtherType or an LLC SAP")),
    }
}

async fn stats(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiRange(range): ApiRange,
) -> Result<Json<EthernetStats>, ApiError> {
    let id = parse_id(&id)?;
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let range = range.resolve(&session)?;
        let conn = session.conn();
        let c = ethernet::counts(conn, range)?;
        let vendors: Vec<VendorSlice> = ethernet::vendor_counts(conn, VENDOR_TOP, range)?
            .into_iter()
            .map(vendor_slice)
            .collect();
        let shown: u64 = vendors.iter().map(|v| v.count).sum();
        Ok(EthernetStats {
            mac_count: c.macs,
            unicast_count: c.unicast,
            local_count: c.local,
            group_count: c.group,
            vendor_count: c.vendors,
            pair_count: c.pairs,
            vlan_count: c.vlans,
            frames: c.frames,
            bytes: c.bytes,
            tagged_frames: c.tagged_frames,
            vendors_other: c.unicast.saturating_sub(shown),
            vendors,
            ethertypes: ethernet::ethertypes(conn, range)?
                .into_iter()
                .map(ethertype_info)
                .collect(),
            vlans: ethernet::vlans(conn, range)?
                .into_iter()
                .map(vlan_info)
                .collect(),
        })
    })
    .await
    .map(Json)
}

async fn macs(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<MacQuery>,
    ApiRange(range): ApiRange,
) -> Result<Json<Page<MacInfo>>, ApiError> {
    let id = parse_id(&id)?;
    let sort = mac_sort(query.sort.as_deref())?;
    let class = mac_class(query.class.as_deref())?;
    let vlan = vlan_stack(non_empty(query.vlan))?;
    let request = PageRequest {
        limit: query.limit.unwrap_or(0),
        cursor: query.cursor,
    };
    let (q, vendor) = (non_empty(query.q), vendor_key(non_empty(query.vendor)));
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let filter = MacFilter {
            q,
            class,
            vendor,
            vlan,
            range: range.resolve(&session)?,
        };
        let page = ethernet::macs_page(session.conn(), &filter, sort, &request)?;
        Ok(Page {
            items: page.items.into_iter().map(mac_info).collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(ethernet::count_macs(session.conn(), &filter)?),
        })
    })
    .await
    .map(Json)
}

async fn pairs(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<String>,
    ApiQuery(query): ApiQuery<PairQuery>,
    ApiRange(range): ApiRange,
) -> Result<Json<Page<MacPairInfo>>, ApiError> {
    let id = parse_id(&id)?;
    let sort = pair_sort(query.sort.as_deref())?;
    let vlan = vlan_stack(non_empty(query.vlan))?;
    let ethertype = ethertype_key(non_empty(query.ethertype).as_deref())?;
    let request = PageRequest {
        limit: query.limit.unwrap_or(0),
        cursor: query.cursor,
    };
    let (q, mac) = (non_empty(query.q), non_empty(query.mac));
    blocking(&state, move |s| {
        let (_, session) = open_ready(s, &id)?;
        let filter = PairFilter {
            q,
            mac,
            vlan,
            ethertype,
            range: range.resolve(&session)?,
        };
        let page = ethernet::pairs_page(session.conn(), &filter, sort, &request)?;
        Ok(Page {
            items: page.items.into_iter().map(pair_info).collect(),
            next_cursor: page.next_cursor,
            total_estimate: Some(ethernet::count_pairs(session.conn(), &filter)?),
        })
    })
    .await
    .map(Json)
}

#[cfg(test)]
mod tests;
