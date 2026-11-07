//! Ethertype values used by the decoder.

/// IPv4.
pub const IPV4: u16 = 0x0800;
/// ARP.
pub const ARP: u16 = 0x0806;
/// Reverse ARP.
pub const RARP: u16 = 0x8035;
/// IEEE 802.1Q VLAN tag.
pub const VLAN: u16 = 0x8100;
/// IPv6.
pub const IPV6: u16 = 0x86dd;
/// IEEE 802.1ad service tag (Q-in-Q).
pub const QINQ: u16 = 0x88a8;
/// Pre-standard Q-in-Q tag.
pub const QINQ_OLD: u16 = 0x9100;
/// Smallest value of the Ethernet type field that is an Ethertype (below: 802.3 length).
pub const MIN_ETHERTYPE: u16 = 0x0600;
