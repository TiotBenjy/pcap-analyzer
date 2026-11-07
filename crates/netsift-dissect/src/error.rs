//! Decoding errors attached to a partially decoded frame.

use core::fmt;

/// Protocol layer at which decoding stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Layer {
    /// Link-layer dispatch (unsupported linktype).
    Link,
    /// Ethernet II / IEEE 802.3 header.
    Ethernet,
    /// IEEE 802.1Q / 802.1ad VLAN tag.
    Vlan,
    /// IEEE 802.2 LLC / SNAP header.
    Llc,
    /// Linux "cooked" capture header (SLL or SLL2).
    LinuxSll,
    /// BSD loopback / null encapsulation header.
    Loopback,
    /// Radiotap pseudo-header.
    Radiotap,
    /// IEEE 802.11 MAC header.
    Ieee80211,
    /// ARP / RARP packet.
    Arp,
    /// IP header whose version nibble is neither 4 nor 6.
    Ip,
    /// IPv4 header (and its options / authentication header).
    Ipv4,
    /// IPv6 header and extension headers.
    Ipv6,
    /// TCP header.
    Tcp,
    /// UDP header.
    Udp,
    /// ICMP header.
    Icmpv4,
    /// `ICMPv6` header.
    Icmpv6,
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Link => "link",
            Self::Ethernet => "ethernet",
            Self::Vlan => "vlan",
            Self::Llc => "llc",
            Self::LinuxSll => "linux-sll",
            Self::Loopback => "loopback",
            Self::Radiotap => "radiotap",
            Self::Ieee80211 => "802.11",
            Self::Arp => "arp",
            Self::Ip => "ip",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmpv4 => "icmp",
            Self::Icmpv6 => "icmpv6",
        };
        f.write_str(name)
    }
}

/// Why a layer could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The frame ends before the header (or a length field) is complete.
    Truncated {
        /// Bytes required by the layer.
        needed: usize,
        /// Bytes actually available.
        available: usize,
    },
    /// The header is present but inconsistent (static, allocation-free reason).
    Malformed(&'static str),
    /// The capture linktype is not supported by this decoder.
    UnsupportedLinktype(u32),
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { needed, available } => {
                write!(f, "truncated ({available} of {needed} bytes)")
            }
            Self::Malformed(reason) => write!(f, "malformed: {reason}"),
            Self::UnsupportedLinktype(lt) => write!(f, "unsupported linktype {lt}"),
        }
    }
}

/// Error on the first layer that could not be decoded.
///
/// Layers decoded before it remain available in [`crate::Decoded`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{layer}: {kind}")]
pub struct DecodeError {
    /// Layer that failed.
    pub layer: Layer,
    /// Failure reason.
    pub kind: ErrorKind,
}

impl DecodeError {
    pub(crate) const fn truncated(layer: Layer, needed: usize, available: usize) -> Self {
        Self {
            layer,
            kind: ErrorKind::Truncated { needed, available },
        }
    }

    pub(crate) const fn malformed(layer: Layer, reason: &'static str) -> Self {
        Self {
            layer,
            kind: ErrorKind::Malformed(reason),
        }
    }
}
