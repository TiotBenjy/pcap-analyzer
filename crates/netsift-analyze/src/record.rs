//! Records emitted by analyzers.
//!
//! `netsift-analyze` does not depend on the store: the engine translates each [`Record`] into
//! the corresponding store row. An analyzer that adds tables (its own `NNNN_<name>.sql`
//! migration) adds **one variant** in the sorted zone of [`Record`] and the matching arm in the
//! engine's translation (`netsift-engine`, `translate.rs`).
//!
//! Records fed by several shards must be mergeable in any order: counters are additive,
//! hosts and flows are merged by key (see the merge rules of `netsift-store`).

use std::net::IpAddr;

use netsift_flow::{FlowCtx, FlowId};

use crate::classify::AppProto;
use crate::geo::{AddressCategory, CountryCode};

/// One record for the store. Not `Eq`: variants may carry floating-point values.
#[derive(Debug, Clone, PartialEq)]
pub enum Record {
    // --- core (built-in `core` analyzer) ---
    /// Traffic of one protocol during one second (additive).
    Timeseries(TrafficSample),
    /// Observation of a host (merged by IP).
    Host(HostSeen),
    /// Summary of a finished flow (merged by flow id).
    Flow(FlowSummary),
    // --- analyzers: registration point, one variant per analyzer, sorted alphabetically ---
}

/// Packets and wire bytes of one application protocol during one second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficSample {
    /// Seconds since the Unix epoch (floor of the packet time).
    pub bucket_s: i64,
    pub proto: AppProto,
    pub bytes: u64,
    pub packets: u64,
}

/// A host seen between `first_ts` and `last_ts` (nanoseconds, packet time).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSeen {
    pub ip: IpAddr,
    /// Unicast MAC addresses seen with this IP (sorted, deduplicated).
    pub macs: Vec<[u8; 6]>,
    /// Names learned for this IP (DNS, NBNS, DHCP...): empty for the `core` analyzer.
    pub names: Vec<String>,
    /// Category of `ip` (deterministic: the same for every observation).
    pub category: AddressCategory,
    /// Country of `ip` when it is public and a country database is loaded.
    pub country: Option<CountryCode>,
    pub first_ts: i64,
    pub last_ts: i64,
}

/// A finished flow and its application protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowSummary {
    pub flow: FlowCtx,
    /// Application protocol, when a well-known port identifies it (`None` for plain TCP/UDP).
    pub app_proto: Option<AppProto>,
}

impl FlowSummary {
    pub fn id(&self) -> FlowId {
        self.flow.id
    }
}
