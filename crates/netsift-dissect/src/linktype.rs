//! `LINKTYPE_*` values (tcpdump.org link-layer header types) supported by [`crate::decode`].

/// BSD loopback, 4-byte address family in the byte order of the capturing host.
pub const NULL: u32 = 0;
/// Ethernet II / IEEE 802.3, with optional 802.1Q / 802.1ad tags.
pub const ETHERNET: u32 = 1;
/// Raw IP: the frame starts with an IPv4 or IPv6 header.
pub const RAW: u32 = 101;
/// IEEE 802.11 MAC frame without pseudo-header.
pub const IEEE802_11: u32 = 105;
/// OpenBSD loopback, 4-byte address family in network byte order.
pub const LOOP: u32 = 108;
/// Linux cooked capture v1.
pub const LINUX_SLL: u32 = 113;
/// Radiotap header followed by an IEEE 802.11 frame.
pub const IEEE802_11_RADIOTAP: u32 = 127;
/// Raw IPv4.
pub const IPV4: u32 = 228;
/// Raw IPv6.
pub const IPV6: u32 = 229;
/// Linux cooked capture v2.
pub const LINUX_SLL2: u32 = 276;

/// All linktypes handled by [`crate::decode`].
pub const SUPPORTED: [u32; 10] = [
    NULL,
    ETHERNET,
    RAW,
    IEEE802_11,
    LOOP,
    LINUX_SLL,
    IEEE802_11_RADIOTAP,
    IPV4,
    IPV6,
    LINUX_SLL2,
];

/// `true` if [`crate::decode`] understands this linktype.
pub fn is_supported(linktype: u32) -> bool {
    SUPPORTED.contains(&linktype)
}
