//! Result of decoding one frame from link layer to transport layer.

use core::fmt;
use std::net::IpAddr;

use crate::error::DecodeError;

/// Maximum number of stacked VLAN tags decoded in one frame (802.1Q, Q-in-Q and beyond).
pub const MAX_VLAN_TAGS: usize = 4;

/// Maximum number of IPv6 extension headers recorded in [`IpInfo::extensions`].
pub const MAX_IPV6_EXTENSIONS: usize = 8;

/// A frame decoded as far as possible, from link layer up to transport layer.
///
/// This is the per-packet input of the analyzers (`Analyzer::on_packet`, see
/// `docs/ARCHITECTURE.md`). Decoding never fails as a whole: each layer that could be
/// decoded is filled in, and [`Decoded::error`] tells why the next one could not.
///
/// [`Decoded::payload`] always borrows the original frame (no copy) and holds the bytes
/// that follow the last successfully decoded header:
///
/// | last decoded layer         | `payload`                                              |
/// |----------------------------|--------------------------------------------------------|
/// | TCP / UDP / ICMP           | transport payload (UDP trimmed to its length field)    |
/// | IP, other protocol         | IP payload (GRE, ESP, IGMP, ...), or a non-first fragment |
/// | ARP                        | bytes after the ARP packet (usually padding)           |
/// | link, unknown Ethertype    | link payload (LLDP, STP, encrypted 802.11 body, ...)   |
/// | nothing                    | the whole frame                                        |
///
/// IP fragments are reported in [`IpInfo::fragment`] but never reassembled here.
/// [`Decoded::ip_payload`] holds the bytes to reassemble: `netsift-flow` concatenates
/// them in offset order, then calls [`crate::decode_transport`] with
/// [`Fragment::next_header`].
///
/// Offsets ([`Decoded::l3_offset`], [`Decoded::l4_offset`], [`Decoded::payload_offset`])
/// are byte positions in the frame, the link header starting at 0.
#[derive(Clone, PartialEq, Eq)]
pub struct Decoded<'a> {
    /// Link-layer information.
    pub link: LinkInfo,
    /// Network layer (IP or ARP), if decoded.
    pub network: Option<Network>,
    /// Transport layer (TCP, UDP, ICMP), if decoded.
    pub transport: Option<Transport>,
    /// Bytes after the last decoded header, borrowed from the frame.
    pub payload: &'a [u8],
    /// IP payload borrowed from the frame; empty when there is no IP layer.
    ///
    /// - Fragment ([`IpInfo::fragment`] is `Some`): the raw fragmentable part, i.e. the
    ///   bytes after the IPv4 header (IHL) or after the IPv6 Fragment header, the part
    ///   that [`Fragment::offset`] counts from. Concatenated in offset order, the
    ///   fragments of one datagram form the input of [`crate::decode_transport`].
    /// - Unfragmented packet: the IP payload after all extension headers (and IPv4 AH),
    ///   i.e. the bytes the transport header is decoded from.
    ///
    /// Link padding and bytes beyond the IP length field are excluded.
    pub ip_payload: &'a [u8],
    /// Offset of the network header (IP or ARP) in the frame.
    pub l3_offset: Option<usize>,
    /// Offset of the transport header in the frame.
    pub l4_offset: Option<usize>,
    /// Offset of [`Decoded::payload`] in the frame.
    pub payload_offset: usize,
    /// First layer that could not be decoded, if any.
    pub error: Option<DecodeError>,
    /// The whole frame, used to compute offsets.
    frame: &'a [u8],
}

impl<'a> Decoded<'a> {
    pub(crate) fn new(linktype: u32, data: &'a [u8]) -> Self {
        Self {
            link: LinkInfo::new(linktype),
            network: None,
            transport: None,
            payload: data,
            ip_payload: data.get(data.len()..).unwrap_or_default(),
            l3_offset: None,
            l4_offset: None,
            payload_offset: 0,
            error: None,
            frame: data,
        }
    }

    /// Offset of `part` in the frame, if `part` borrows the frame.
    pub(crate) fn offset_of(&self, part: &[u8]) -> Option<usize> {
        let off = part
            .as_ptr()
            .addr()
            .checked_sub(self.frame.as_ptr().addr())?;
        (off.checked_add(part.len())? <= self.frame.len()).then_some(off)
    }

    /// Computes [`Decoded::payload_offset`] once decoding is over.
    pub(crate) fn finish(&mut self) {
        self.payload_offset = self.offset_of(self.payload).unwrap_or(self.frame.len());
    }

    /// IP layer, if present.
    pub fn ip(&self) -> Option<&IpInfo> {
        match &self.network {
            Some(Network::Ip(ip)) => Some(ip),
            _ => None,
        }
    }

    /// TCP header, if present.
    pub fn tcp(&self) -> Option<&TcpInfo> {
        match &self.transport {
            Some(Transport::Tcp(tcp)) => Some(tcp),
            _ => None,
        }
    }

    /// UDP header, if present.
    pub fn udp(&self) -> Option<&UdpInfo> {
        match &self.transport {
            Some(Transport::Udp(udp)) => Some(udp),
            _ => None,
        }
    }

    /// Source and destination ports when the transport is TCP or UDP.
    pub fn ports(&self) -> Option<(u16, u16)> {
        match &self.transport {
            Some(Transport::Tcp(t)) => Some((t.src_port, t.dst_port)),
            Some(Transport::Udp(u)) => Some((u.src_port, u.dst_port)),
            _ => None,
        }
    }
}

impl fmt::Debug for Decoded<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decoded")
            .field("link", &self.link)
            .field("network", &self.network)
            .field("transport", &self.transport)
            .field("payload", &PayloadPreview(self.payload))
            .field("ip_payload", &PayloadPreview(self.ip_payload))
            .field("l3_offset", &self.l3_offset)
            .field("l4_offset", &self.l4_offset)
            .field("payload_offset", &self.payload_offset)
            .field("error", &self.error)
            .finish()
    }
}

/// Debug helper: payload length and the first bytes in hex.
struct PayloadPreview<'a>(&'a [u8]);

impl fmt::Debug for PayloadPreview<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const PREVIEW: usize = 16;
        write!(f, "{} bytes", self.0.len())?;
        if !self.0.is_empty() {
            f.write_str(" [")?;
            for b in self.0.iter().take(PREVIEW) {
                write!(f, "{b:02x}")?;
            }
            if self.0.len() > PREVIEW {
                f.write_str("..")?;
            }
            f.write_str("]")?;
        }
        Ok(())
    }
}

/// IEEE 802 MAC address (EUI-48).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// Broadcast address `ff:ff:ff:ff:ff:ff`.
    pub const BROADCAST: Self = Self([0xff; 6]);

    pub(crate) fn from_slice(b: &[u8]) -> Option<Self> {
        b.get(..6)?.try_into().ok().map(Self)
    }

    /// Group (multicast or broadcast) address bit.
    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [b0, b1, b2, b3, b4, b5] = self.0;
        write!(f, "{b0:02x}:{b1:02x}:{b2:02x}:{b3:02x}:{b4:02x}:{b5:02x}")
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Link-layer encapsulation family of the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LinkKind {
    /// Ethernet II / IEEE 802.3.
    Ethernet,
    /// Linux cooked capture v1.
    LinuxSll,
    /// Linux cooked capture v2.
    LinuxSll2,
    /// Raw IP (no link header).
    RawIp,
    /// BSD loopback (`DLT_NULL` host order, or `DLT_LOOP` network order).
    Loopback,
    /// IEEE 802.11 without pseudo-header.
    Ieee80211,
    /// IEEE 802.11 preceded by a radiotap header.
    Ieee80211Radiotap,
    /// Unsupported linktype.
    Unknown,
}

/// Link-layer information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkInfo {
    /// Capture linktype (`LINKTYPE_*` value, see [`crate::linktype`]).
    pub linktype: u32,
    /// Encapsulation family.
    pub kind: LinkKind,
    /// Source MAC (Ethernet source, SLL address, 802.11 SA).
    pub src_mac: Option<MacAddr>,
    /// Destination MAC (Ethernet destination, 802.11 DA).
    pub dst_mac: Option<MacAddr>,
    /// VLAN tags, outermost first.
    pub vlans: Vlans,
    /// Ethertype of the link payload, after VLAN tags and LLC/SNAP. For raw IP and
    /// loopback captures it is synthesized (`0x0800` / `0x86dd`).
    pub ethertype: Option<u16>,
    /// IEEE 802.2 LLC header, when the frame uses 802.3 / 802.11 LLC framing.
    pub llc: Option<Llc>,
    /// Linux cooked capture header fields.
    pub sll: Option<SllInfo>,
    /// Radiotap pseudo-header fields.
    pub radiotap: Option<RadiotapInfo>,
    /// IEEE 802.11 MAC header fields.
    pub wifi: Option<WifiInfo>,
}

impl LinkInfo {
    const fn new(linktype: u32) -> Self {
        Self {
            linktype,
            kind: LinkKind::Unknown,
            src_mac: None,
            dst_mac: None,
            vlans: Vlans::new(),
            ethertype: None,
            llc: None,
            sll: None,
            radiotap: None,
            wifi: None,
        }
    }
}

/// One IEEE 802.1Q / 802.1ad tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct VlanTag {
    /// Tag protocol identifier (`0x8100`, `0x88a8` or `0x9100`).
    pub tpid: u16,
    /// Priority code point (0..=7).
    pub pcp: u8,
    /// Drop eligible indicator.
    pub dei: bool,
    /// VLAN identifier (0..=4095).
    pub id: u16,
}

/// Bounded list of VLAN tags (at most [`MAX_VLAN_TAGS`]), without heap allocation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Vlans {
    tags: [VlanTag; MAX_VLAN_TAGS],
    len: u8,
}

impl Vlans {
    const fn new() -> Self {
        Self {
            tags: [VlanTag {
                tpid: 0,
                pcp: 0,
                dei: false,
                id: 0,
            }; MAX_VLAN_TAGS],
            len: 0,
        }
    }

    /// Returns `false` when the list is full.
    pub(crate) fn push(&mut self, tag: VlanTag) -> bool {
        match self.tags.get_mut(usize::from(self.len)) {
            Some(slot) => {
                *slot = tag;
                self.len = self.len.saturating_add(1);
                true
            }
            None => false,
        }
    }

    /// Tags, outermost first.
    pub fn as_slice(&self) -> &[VlanTag] {
        self.tags.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// Number of tags.
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// No VLAN tag.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Innermost VLAN identifier, if any.
    pub fn inner_id(&self) -> Option<u16> {
        self.as_slice().last().map(|t| t.id)
    }
}

impl fmt::Debug for Vlans {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

/// IEEE 802.2 LLC header (with SNAP extension when DSAP = SSAP = `0xaa`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Llc {
    /// Destination service access point.
    pub dsap: u8,
    /// Source service access point.
    pub ssap: u8,
    /// Control field (1 byte for U-frames, 2 bytes for I/S-frames).
    pub control: u16,
    /// SNAP organization code, if a SNAP header follows.
    pub snap_oui: Option<[u8; 3]>,
}

/// Linux cooked capture (SLL / SLL2) header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SllInfo {
    /// Packet type (0 to host, 1 broadcast, 2 multicast, 3 other host, 4 outgoing).
    pub packet_type: u16,
    /// `ARPHRD_*` device type.
    pub arphrd_type: u16,
    /// Protocol field (Ethertype, or Linux pseudo-protocol for non-Ethernet framing).
    pub protocol: u16,
    /// Interface index (SLL2 only).
    pub if_index: Option<u32>,
}

/// Radiotap pseudo-header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RadiotapInfo {
    /// Total radiotap header length (`it_len`).
    pub header_len: u16,
    /// The 802.11 frame ends with a 4-byte FCS (stripped from the decoded frame).
    pub fcs_present: bool,
    /// The capture device flagged a bad FCS.
    pub bad_fcs: bool,
    /// Channel center frequency in MHz.
    pub channel_mhz: Option<u16>,
    /// Antenna signal in dBm.
    pub signal_dbm: Option<i8>,
}

/// IEEE 802.11 frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WifiFrameType {
    /// Management frame (beacon, probe, association, authentication, ...).
    Management,
    /// Control frame (RTS, CTS, ACK, block ack, ...).
    Control,
    /// Data frame.
    Data,
    /// Extension frame (type 3).
    Extension,
}

/// IEEE 802.11 MAC header fields.
///
/// `addr1`..`addr4` are the raw address fields; [`WifiInfo::bssid`] and the link
/// `src_mac` / `dst_mac` are derived from them according to the To/From DS bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::struct_excessive_bools)] // mirrors the frame control flag bits
pub struct WifiInfo {
    /// Frame type.
    pub frame_type: WifiFrameType,
    /// Frame subtype (0..=15).
    pub subtype: u8,
    /// Frame control: To DS.
    pub to_ds: bool,
    /// Frame control: From DS.
    pub from_ds: bool,
    /// Frame control: more fragments.
    pub more_fragments: bool,
    /// Frame control: retry.
    pub retry: bool,
    /// Frame control: protected (encrypted body).
    pub protected: bool,
    /// Address 1 (receiver).
    pub addr1: Option<MacAddr>,
    /// Address 2 (transmitter).
    pub addr2: Option<MacAddr>,
    /// Address 3.
    pub addr3: Option<MacAddr>,
    /// Address 4 (only when To DS and From DS are both set).
    pub addr4: Option<MacAddr>,
    /// BSSID, when it can be derived from the DS bits.
    pub bssid: Option<MacAddr>,
    /// Sequence number (management and data frames).
    pub sequence: Option<u16>,
    /// Fragment number (management and data frames).
    pub fragment: Option<u8>,
    /// `QoS` traffic identifier (`QoS` data frames).
    pub qos_tid: Option<u8>,
    /// `QoS` A-MSDU present bit (the body is a list of subframes, not decoded further).
    pub amsdu: bool,
}

/// Network layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// IPv4 or IPv6.
    Ip(IpInfo),
    /// ARP or RARP.
    Arp(ArpInfo),
}

/// IP version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpVersion {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

/// IPv4 or IPv6 header (including IPv6 extension headers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpInfo {
    /// IP version.
    pub version: IpVersion,
    /// Source address.
    pub src: IpAddr,
    /// Destination address.
    pub dst: IpAddr,
    /// Protocol number of the payload, after IPv6 extension headers / IPv4 AH.
    pub protocol: u8,
    /// TTL (IPv4) or hop limit (IPv6).
    pub ttl: u8,
    /// Length of the IP header plus extension headers, in bytes.
    pub header_len: usize,
    /// Length of the IP payload present in the frame (Ethernet padding excluded).
    pub payload_len: usize,
    /// The IP length field announces more bytes than captured (snaplen, truncation).
    pub truncated: bool,
    /// IPv4 identification field (IPv6: `None` unless a fragment header is present).
    pub ident: Option<u32>,
    /// IPv4 "don't fragment" flag.
    pub dont_fragment: bool,
    /// Fragment information when the packet is a fragment (offset != 0 or MF set).
    pub fragment: Option<Fragment>,
    /// IPv6 extension headers, in order, as protocol numbers (at most
    /// [`MAX_IPV6_EXTENSIONS`] recorded). IPv4: AH (51) when present.
    pub extensions: IpExtensions,
}

/// Bounded list of extension header protocol numbers, without heap allocation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct IpExtensions {
    items: [u8; MAX_IPV6_EXTENSIONS],
    len: u8,
}

impl IpExtensions {
    /// Records `proto`; returns `false` (and drops it) when the list is full.
    pub(crate) fn push(&mut self, proto: u8) -> bool {
        match self.items.get_mut(usize::from(self.len)) {
            Some(slot) => {
                *slot = proto;
                self.len = self.len.saturating_add(1);
                true
            }
            None => false,
        }
    }

    /// Protocol numbers, in header order.
    pub fn as_slice(&self) -> &[u8] {
        self.items.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// Number of recorded extension headers.
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// No extension header.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Debug for IpExtensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

/// IP fragment description (no reassembly is performed by this crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fragment {
    /// Identification (16 bits for IPv4, 32 bits for IPv6).
    pub id: u32,
    /// Fragment offset in bytes.
    pub offset: u16,
    /// More fragments follow.
    pub more: bool,
    /// Protocol of the fragmentable part ([`Decoded::ip_payload`]): the IPv4 protocol
    /// field, or the next header of the IPv6 Fragment header.
    pub next_header: u8,
}

impl Fragment {
    /// First fragment (offset 0): it carries the transport header.
    pub const fn is_first(&self) -> bool {
        self.offset == 0
    }
}

/// ARP / RARP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArpInfo {
    /// Hardware type (1 = Ethernet).
    pub hardware_type: u16,
    /// Protocol type (`0x0800` = IPv4).
    pub protocol_type: u16,
    /// Operation (1 request, 2 reply, 3/4 RARP).
    pub operation: u16,
    /// Sender hardware address (when 6 bytes long).
    pub sender_mac: Option<MacAddr>,
    /// Sender protocol address (when IPv4).
    pub sender_ip: Option<IpAddr>,
    /// Target hardware address (when 6 bytes long).
    pub target_mac: Option<MacAddr>,
    /// Target protocol address (when IPv4).
    pub target_ip: Option<IpAddr>,
}

/// Transport layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// TCP header.
    Tcp(TcpInfo),
    /// UDP header.
    Udp(UdpInfo),
    /// ICMP header.
    Icmpv4(IcmpInfo),
    /// `ICMPv6` header.
    Icmpv6(IcmpInfo),
}

/// TCP header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpInfo {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Sequence number.
    pub seq: u32,
    /// Acknowledgment number (meaningful when [`TcpFlags::ACK`] is set).
    pub ack: u32,
    /// Control flags.
    pub flags: TcpFlags,
    /// Receive window (unscaled).
    pub window: u16,
    /// Header length in bytes (20..=60).
    pub header_len: u8,
    /// Options relevant to analyzers.
    pub options: TcpOptions,
    /// Captured payload length in bytes.
    pub payload_len: usize,
}

/// TCP options relevant to analyzers (others are skipped).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TcpOptions {
    /// Maximum segment size (kind 2).
    pub mss: Option<u16>,
    /// Window scale shift count (kind 3).
    pub window_scale: Option<u8>,
    /// SACK permitted (kind 4).
    pub sack_permitted: bool,
    /// Timestamps: value and echo reply (kind 8).
    pub timestamps: Option<(u32, u32)>,
}

/// TCP control flags (NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TcpFlags(pub u16);

impl TcpFlags {
    /// FIN.
    pub const FIN: u16 = 0x001;
    /// SYN.
    pub const SYN: u16 = 0x002;
    /// RST.
    pub const RST: u16 = 0x004;
    /// PSH.
    pub const PSH: u16 = 0x008;
    /// ACK.
    pub const ACK: u16 = 0x010;
    /// URG.
    pub const URG: u16 = 0x020;
    /// ECE.
    pub const ECE: u16 = 0x040;
    /// CWR.
    pub const CWR: u16 = 0x080;
    /// NS (ECN nonce, RFC 3540).
    pub const NS: u16 = 0x100;

    const NAMES: [(u16, &'static str); 9] = [
        (Self::NS, "NS"),
        (Self::CWR, "CWR"),
        (Self::ECE, "ECE"),
        (Self::URG, "URG"),
        (Self::ACK, "ACK"),
        (Self::PSH, "PSH"),
        (Self::RST, "RST"),
        (Self::SYN, "SYN"),
        (Self::FIN, "FIN"),
    ];

    /// All bits of `mask` are set.
    pub const fn contains(self, mask: u16) -> bool {
        self.0 & mask == mask
    }

    /// SYN set.
    pub const fn syn(self) -> bool {
        self.contains(Self::SYN)
    }

    /// ACK set.
    pub const fn ack(self) -> bool {
        self.contains(Self::ACK)
    }

    /// FIN set.
    pub const fn fin(self) -> bool {
        self.contains(Self::FIN)
    }

    /// RST set.
    pub const fn rst(self) -> bool {
        self.contains(Self::RST)
    }
}

impl fmt::Debug for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (bit, name) in Self::NAMES {
            if self.contains(bit) {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        if first {
            f.write_str("-")?;
        }
        Ok(())
    }
}

/// UDP header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpInfo {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Length field (header + payload) as announced.
    pub length: u16,
    /// Captured payload length in bytes.
    pub payload_len: usize,
}

/// ICMP / `ICMPv6` header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IcmpInfo {
    /// Message type.
    pub icmp_type: u8,
    /// Message code.
    pub code: u8,
    /// Identifier of an echo request or reply.
    pub id: Option<u16>,
    /// Sequence number of an echo request or reply.
    pub sequence: Option<u16>,
}
