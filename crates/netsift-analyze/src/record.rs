//! Records emitted by analyzers.
//!
//! `netsift-analyze` does not depend on the store: the engine translates each [`Record`] into
//! the corresponding store row. An analyzer that adds tables (its own `NNNN_<name>.sql`
//! migration) adds **one variant** in the sorted zone of [`Record`] and the matching arm in the
//! engine's translation (`netsift-engine`, `translate.rs`).
//!
//! Records fed by several shards must be mergeable in any order: counters are additive,
//! hosts and flows are merged by key (see the merge rules of `netsift-store`).

use std::fmt;
use std::net::IpAddr;

use netsift_flow::{Endpoint, FlowCtx, FlowId};

use crate::classify::AppProto;
use crate::connections::{ConversationDelta, HostTrafficDelta};
use crate::geo::{AddressCategory, CountryCode};
use crate::http::HttpTransaction;
use crate::ports::OpenPortSeen;

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
    /// `connections`: flows from a client to a server, folded per IP pair (additive).
    Conversation(ConversationDelta),
    /// Authentication material observed by any protocol analyzer. Generic by design so the
    /// Credentials tab (task P3.7) only has to aggregate: every emitting analyzer (SMB/NTLM
    /// here, later HTTP Basic, FTP, SNMP...) produces this one shape. Sensitive: never logged,
    /// masked in the UI (see `docs/specs/credentials.md`).
    Credential(Credential),
    /// A DNS, mDNS, LLMNR or NBNS transaction (`dns` analyzer).
    Dns(Box<crate::dns::DnsTransaction>),
    /// `connections`: traffic sent and received by one host (additive).
    HostTraffic(HostTrafficDelta),
    /// An HTTP request and its response (`http` analyzer), boxed: much larger than the others.
    Http(Box<HttpTransaction>),
    /// `ports`: a service seen answering (merged by host, transport and port).
    OpenPort(OpenPortSeen),
    /// `servers`: one DHCP message, NTP response or KDC reply.
    Server(crate::servers::ServerRecord),
    /// SMB / NetBIOS browser announcement or SMB session (negotiation + NTLM auth metadata).
    Smb(SmbRecord),
    /// One TLS session (`tls` analyzer).
    Tls(Box<crate::tls::TlsSession>),
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

/// How much of a credential's secret the capture exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretState {
    /// The secret itself is in the capture (clear text).
    Plaintext,
    /// Not the secret, but material from which it can be recovered offline (NTLM hashes...).
    Recoverable,
    /// Only non-secret metadata was observed.
    MetadataOnly,
}

impl SecretState {
    /// Stable label (`docs/specs/credentials.md`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::Recoverable => "recoverable",
            Self::MetadataOnly => "metadata-only",
        }
    }
}

/// A credential (or offline-recoverable material) seen in the capture.
///
/// In-memory contract only (task P3.5): the engine does **not** persist it yet
/// ([`crate::Record::Credential`] is dropped by `to_store`). The Credentials tab (task P3.7) owns
/// the storage schema and aggregates every protocol analyzer's `Credential`. The SMB view keeps
/// its own non-secret metadata in `smb_sessions`.
///
/// Sensitive fields (`secret`, `hashcat_line`) are never logged: [`fmt::Debug`] redacts them.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    /// Emitting protocol, lower case (`smb`, later `http`, `ftp`, `snmp`...).
    pub source_protocol: &'static str,
    /// Finer credential type, lower case (`ntlmv1`, `ntlmv2`, `http-basic`...).
    pub kind: &'static str,
    /// Flow the credential belongs to, when it comes from a tracked flow.
    pub flow_id: Option<FlowId>,
    pub client: Option<Endpoint>,
    pub server: Option<Endpoint>,
    pub ts: i64,
    /// User name (account), when observed.
    pub username: Option<String>,
    /// Domain or realm, when observed.
    pub domain: Option<String>,
    /// Workstation / host name, when observed.
    pub workstation: Option<String>,
    pub secret_state: SecretState,
    /// The secret itself, for `plaintext` credentials (never for NTLM). Masked in the UI.
    pub secret: Option<String>,
    /// hashcat mode number for offline recovery, when applicable (5500 `NetNTLMv1`, 5600 v2).
    pub hashcat_mode: Option<u32>,
    /// Ready-to-crack hashcat line, for `recoverable` credentials. Masked in the UI.
    pub hashcat_line: Option<String>,
    /// Extra non-secret context as ordered key/value pairs (e.g. SMB dialect, server challenge).
    pub details: Vec<(String, String)>,
}

impl fmt::Debug for Credential {
    /// Redacts `secret` and `hashcat_line` so a credential can never leak through logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redact = |o: &Option<String>| o.as_ref().map(|_| "<redacted>");
        f.debug_struct("Credential")
            .field("source_protocol", &self.source_protocol)
            .field("kind", &self.kind)
            .field("flow_id", &self.flow_id)
            .field("client", &self.client)
            .field("server", &self.server)
            .field("ts", &self.ts)
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("workstation", &self.workstation)
            .field("secret_state", &self.secret_state)
            .field("secret", &redact(&self.secret))
            .field("hashcat_mode", &self.hashcat_mode)
            .field("hashcat_line", &redact(&self.hashcat_line))
            .field("details", &self.details)
            .finish()
    }
}

/// A record of the `smb` analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmbRecord {
    /// NetBIOS browser announcement (UDP 138, `\MAILSLOT\BROWSE`).
    Announce(SmbAnnounce),
    /// SMB session over TCP (139/445): negotiation and NTLM authentication metadata.
    Session(SmbSession),
}

/// Browser announcement kind (MS-BRWS 2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnouncementKind {
    Host,
    LocalMaster,
    Domain,
}

impl AnnouncementKind {
    /// Stable label stored in the database.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::LocalMaster => "local_master",
            Self::Domain => "domain",
        }
    }
}

/// A NetBIOS browser announcement (`smb_announces`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbAnnounce {
    pub ts: i64,
    /// Address that sent the announcement.
    pub src_ip: IpAddr,
    pub kind: AnnouncementKind,
    /// Announced server (NetBIOS computer) name.
    pub server_name: String,
    /// NetBIOS destination the announcement was addressed to (workgroup/domain, suffix text).
    pub dst_name: String,
    /// Announced OS major/minor version.
    pub os_major: u8,
    pub os_minor: u8,
    /// Human-readable OS label derived from the version (donut of the SMB view).
    pub os_label: String,
    /// `SV_TYPE_*` server-role bit field.
    pub server_type: u32,
    pub comment: String,
}

/// SMB dialect family of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmbProtocol {
    Smb1,
    Smb2,
}

impl SmbProtocol {
    /// Stable label stored in the database.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Smb1 => "smb1",
            Self::Smb2 => "smb2",
        }
    }
}

/// Message signing posture negotiated by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signing {
    /// Signing not offered.
    Disabled,
    /// Signing enabled but not required.
    Enabled,
    /// Signing required.
    Required,
    /// Not observed.
    Unknown,
}

impl Signing {
    /// Stable label stored in the database.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Enabled => "enabled",
            Self::Required => "required",
            Self::Unknown => "unknown",
        }
    }
}

/// Highest NTLMSSP message reached in a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtlmPhase {
    Negotiate,
    Challenge,
    Authenticate,
}

impl NtlmPhase {
    /// Stable label stored in the database.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Negotiate => "negotiate",
            Self::Challenge => "challenge",
            Self::Authenticate => "authenticate",
        }
    }
}

/// One SMB session over TCP (`smb_sessions`), merged by flow id. Non-secret metadata only; the
/// NTLM secret material is emitted separately as a [`Credential`] (Credentials tab).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbSession {
    pub flow_id: FlowId,
    pub client: Endpoint,
    pub server: Endpoint,
    pub first_ts: i64,
    pub last_ts: i64,
    pub protocol: SmbProtocol,
    /// Negotiated dialect label (`SMB 2.1`, `SMB 3.1.1`, `NT LM 0.12`...), when seen.
    pub dialect: Option<String>,
    pub signing: Signing,
    /// Server GUID advertised in the SMB2 negotiate response.
    pub server_guid: Option<[u8; 16]>,
    /// NTLM account domain (from AUTHENTICATE), when an NTLM exchange was seen.
    pub domain: Option<String>,
    pub account: Option<String>,
    pub workstation: Option<String>,
    pub ntlm_phase: Option<NtlmPhase>,
}
