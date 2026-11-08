//! Address classification, without any database.
//!
//! [`AddressCategory::of`] sorts an IP address into the categories of the network legends
//! (`docs/UI_GUIDELINES.md`): `private` is shown as "LAN", `link_local` as "Link-local". The
//! categories follow the IANA special-purpose address registries (RFC 6890 and updates).
//!
//! Limits, by design:
//! - a **directed subnet broadcast** (`192.168.1.255` for a `/24`) cannot be recognized
//!   without the subnet mask, which a capture does not carry: such an address keeps the
//!   category of its range (`private` here). Only the limited broadcast `255.255.255.255` is
//!   `broadcast`;
//! - IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are classified as their IPv4 address;
//! - IPv6 addresses outside the global unicast range `2000::/3` (and outside the special
//!   ranges below) are not allocated by IANA: they are `reserved`. The NAT64 well-known
//!   prefix `64:ff9b::/96` is globally reachable, hence `public`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Category of an IP address. Stored as its lower-case label ([`AddressCategory::as_str`]),
/// which never changes once released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AddressCategory {
    /// RFC 1918 (IPv4) and unique local addresses `fc00::/7` (IPv6). Legend: "LAN".
    Private,
    /// Globally routable unicast.
    Public,
    /// The limited broadcast `255.255.255.255`.
    Broadcast,
    /// `224.0.0.0/4` and `ff00::/8`.
    Multicast,
    /// `169.254.0.0/16` and `fe80::/10`.
    LinkLocal,
    /// `127.0.0.0/8` and `::1`.
    Loopback,
    /// Shared address space of carrier-grade NAT, `100.64.0.0/10` (RFC 6598).
    Cgnat,
    /// `0.0.0.0` and `::`.
    Unspecified,
    /// Documentation, benchmarking, `240.0.0.0/4`, protocol assignments, unallocated IPv6...
    Reserved,
}

impl AddressCategory {
    /// Every category, in declaration order.
    pub const ALL: [Self; 9] = [
        Self::Private,
        Self::Public,
        Self::Broadcast,
        Self::Multicast,
        Self::LinkLocal,
        Self::Loopback,
        Self::Cgnat,
        Self::Unspecified,
        Self::Reserved,
    ];

    /// Category of `ip`.
    pub fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => classify_v4(v4),
            IpAddr::V6(v6) => classify_v6(v6),
        }
    }

    /// Stable lower-case label (`"private"`, `"link_local"`...).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Public => "public",
            Self::Broadcast => "broadcast",
            Self::Multicast => "multicast",
            Self::LinkLocal => "link_local",
            Self::Loopback => "loopback",
            Self::Cgnat => "cgnat",
            Self::Unspecified => "unspecified",
            Self::Reserved => "reserved",
        }
    }
}

impl fmt::Display for AddressCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error of [`AddressCategory::from_str`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown address category")]
pub struct UnknownCategory;

impl FromStr for AddressCategory {
    type Err = UnknownCategory;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|c| c.as_str() == s)
            .ok_or(UnknownCategory)
    }
}

/// Is `addr` inside `net/len`?
fn in_v4(addr: u32, net: [u8; 4], len: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - len).unwrap_or(0);
    addr & mask == u32::from_be_bytes(net) & mask
}

fn in_v6(addr: u128, net: u128, len: u32) -> bool {
    let mask = u128::MAX.checked_shl(128 - len).unwrap_or(0);
    addr & mask == net & mask
}

fn classify_v4(ip: Ipv4Addr) -> AddressCategory {
    use AddressCategory as C;
    let a = u32::from(ip);
    // Globally reachable exceptions inside 192.0.0.0/24 (PCP and TURN anycast, RFC 7723/8155).
    if a == u32::from_be_bytes([192, 0, 0, 9]) || a == u32::from_be_bytes([192, 0, 0, 10]) {
        return C::Public;
    }
    match a {
        0 => C::Unspecified,
        u32::MAX => C::Broadcast,
        _ if in_v4(a, [10, 0, 0, 0], 8)
            || in_v4(a, [172, 16, 0, 0], 12)
            || in_v4(a, [192, 168, 0, 0], 16) =>
        {
            C::Private
        }
        _ if in_v4(a, [100, 64, 0, 0], 10) => C::Cgnat,
        _ if in_v4(a, [127, 0, 0, 0], 8) => C::Loopback,
        _ if in_v4(a, [169, 254, 0, 0], 16) => C::LinkLocal,
        _ if in_v4(a, [224, 0, 0, 0], 4) => C::Multicast,
        _ if in_v4(a, [0, 0, 0, 0], 8) // "this network"
            || in_v4(a, [192, 0, 0, 0], 24) // IETF protocol assignments
            || in_v4(a, [192, 0, 2, 0], 24) // TEST-NET-1
            || in_v4(a, [192, 88, 99, 0], 24) // deprecated 6to4 relay anycast
            || in_v4(a, [198, 18, 0, 0], 15) // benchmarking
            || in_v4(a, [198, 51, 100, 0], 24) // TEST-NET-2
            || in_v4(a, [203, 0, 113, 0], 24) // TEST-NET-3
            || in_v4(a, [240, 0, 0, 0], 4) =>
        {
            C::Reserved
        }
        _ => C::Public,
    }
}

const fn v6(segments: [u16; 8]) -> u128 {
    let s = segments;
    ((s[0] as u128) << 112)
        | ((s[1] as u128) << 96)
        | ((s[2] as u128) << 80)
        | ((s[3] as u128) << 64)
        | ((s[4] as u128) << 48)
        | ((s[5] as u128) << 32)
        | ((s[6] as u128) << 16)
        | (s[7] as u128)
}

fn classify_v6(ip: Ipv6Addr) -> AddressCategory {
    use AddressCategory as C;
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    let a = u128::from(ip);
    // Globally reachable exceptions inside 2001::/23 (IANA special-purpose registry).
    let global_in_2001 = a == v6([0x2001, 1, 0, 0, 0, 0, 0, 1])
        || a == v6([0x2001, 1, 0, 0, 0, 0, 0, 2])
        || a == v6([0x2001, 1, 0, 0, 0, 0, 0, 3])
        || in_v6(a, v6([0x2001, 3, 0, 0, 0, 0, 0, 0]), 32) // AMT
        || in_v6(a, v6([0x2001, 4, 0x112, 0, 0, 0, 0, 0]), 48) // AS112-v6
        || in_v6(a, v6([0x2001, 0x20, 0, 0, 0, 0, 0, 0]), 28); // ORCHIDv2
    match a {
        0 => C::Unspecified,
        1 => C::Loopback,
        _ if in_v6(a, v6([0xfc00, 0, 0, 0, 0, 0, 0, 0]), 7) => C::Private,
        _ if in_v6(a, v6([0xfe80, 0, 0, 0, 0, 0, 0, 0]), 10) => C::LinkLocal,
        _ if in_v6(a, v6([0xff00, 0, 0, 0, 0, 0, 0, 0]), 8) => C::Multicast,
        _ if in_v6(a, v6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0]), 96) => C::Public,
        _ if global_in_2001 => C::Public,
        _ if in_v6(a, v6([0x2001, 0, 0, 0, 0, 0, 0, 0]), 23) // IETF protocol assignments
            || in_v6(a, v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]), 32) // documentation
            || in_v6(a, v6([0x3fff, 0, 0, 0, 0, 0, 0, 0]), 20) =>
        // documentation (RFC 9637)
        {
            C::Reserved
        }
        _ if in_v6(a, v6([0x2000, 0, 0, 0, 0, 0, 0, 0]), 3) => C::Public,
        // Discard-only 100::/64, deprecated site-local fec0::/10, unallocated space.
        _ => C::Reserved,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use AddressCategory as C;

    fn cat(s: &str) -> AddressCategory {
        AddressCategory::of(s.parse().unwrap())
    }

    /// `(first, last)` of a range, plus the addresses just outside it.
    fn check_range(first: &str, last: &str, inside: C, before: C, after: C) {
        let f: IpAddr = first.parse().unwrap();
        let l: IpAddr = last.parse().unwrap();
        assert_eq!(AddressCategory::of(f), inside, "{first}");
        assert_eq!(AddressCategory::of(l), inside, "{last}");
        let (prev, next) = match (f, l) {
            (IpAddr::V4(f), IpAddr::V4(l)) => (
                IpAddr::V4(Ipv4Addr::from(u32::from(f) - 1)),
                IpAddr::V4(Ipv4Addr::from(u32::from(l) + 1)),
            ),
            (IpAddr::V6(f), IpAddr::V6(l)) => (
                IpAddr::V6(Ipv6Addr::from(u128::from(f) - 1)),
                IpAddr::V6(Ipv6Addr::from(u128::from(l) + 1)),
            ),
            _ => unreachable!(),
        };
        assert_eq!(AddressCategory::of(prev), before, "{prev} (before {first})");
        assert_eq!(AddressCategory::of(next), after, "{next} (after {last})");
    }

    #[test]
    fn ipv4_ranges_at_their_bounds() {
        check_range(
            "10.0.0.0",
            "10.255.255.255",
            C::Private,
            C::Public,
            C::Public,
        );
        check_range(
            "172.16.0.0",
            "172.31.255.255",
            C::Private,
            C::Public,
            C::Public,
        );
        check_range(
            "192.168.0.0",
            "192.168.255.255",
            C::Private,
            C::Public,
            C::Public,
        );
        check_range(
            "100.64.0.0",
            "100.127.255.255",
            C::Cgnat,
            C::Public,
            C::Public,
        );
        check_range(
            "127.0.0.0",
            "127.255.255.255",
            C::Loopback,
            C::Public,
            C::Public,
        );
        check_range(
            "169.254.0.0",
            "169.254.255.255",
            C::LinkLocal,
            C::Public,
            C::Public,
        );
        check_range(
            "224.0.0.0",
            "239.255.255.255",
            C::Multicast,
            C::Public,
            C::Reserved,
        );
        check_range(
            "240.0.0.0",
            "255.255.255.254",
            C::Reserved,
            C::Multicast,
            C::Broadcast,
        );
    }

    #[test]
    fn ipv4_reserved_ranges_at_their_bounds() {
        check_range(
            "0.0.0.1",
            "0.255.255.255",
            C::Reserved,
            C::Unspecified,
            C::Public,
        );
        check_range(
            "192.0.2.0",
            "192.0.2.255",
            C::Reserved,
            C::Public,
            C::Public,
        );
        check_range(
            "198.51.100.0",
            "198.51.100.255",
            C::Reserved,
            C::Public,
            C::Public,
        );
        check_range(
            "203.0.113.0",
            "203.0.113.255",
            C::Reserved,
            C::Public,
            C::Public,
        );
        check_range(
            "198.18.0.0",
            "198.19.255.255",
            C::Reserved,
            C::Public,
            C::Public,
        );
        check_range(
            "192.88.99.0",
            "192.88.99.255",
            C::Reserved,
            C::Public,
            C::Public,
        );
        check_range("192.0.0.0", "192.0.0.8", C::Reserved, C::Public, C::Public);
        check_range(
            "192.0.0.11",
            "192.0.0.255",
            C::Reserved,
            C::Public,
            C::Public,
        );
    }

    #[test]
    fn ipv4_single_addresses() {
        assert_eq!(cat("0.0.0.0"), C::Unspecified);
        assert_eq!(cat("255.255.255.255"), C::Broadcast);
        assert_eq!(cat("8.8.8.8"), C::Public);
        // A directed subnet broadcast cannot be told without the mask.
        assert_eq!(cat("192.168.1.255"), C::Private);
        assert_eq!(cat("192.0.0.9"), C::Public);
        assert_eq!(cat("192.0.0.10"), C::Public);
    }

    #[test]
    fn ipv6_ranges_at_their_bounds() {
        check_range(
            "fc00::",
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            C::Private,
            C::Reserved,
            C::Reserved,
        );
        check_range(
            "fe80::",
            "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            C::LinkLocal,
            C::Reserved,
            C::Reserved,
        );
        check_range(
            "ff00::",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe",
            C::Multicast,
            C::Reserved,
            C::Multicast,
        );
        check_range(
            "2000::",
            "2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            C::Public,
            C::Reserved,
            C::Reserved,
        );
        check_range(
            "2001:200::",
            "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            C::Public,
            C::Reserved,
            C::Reserved,
        );
        check_range(
            "2001:db8::",
            "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
            C::Reserved,
            C::Public,
            C::Public,
        );
        check_range(
            "3fff::",
            "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
            C::Reserved,
            C::Public,
            C::Public,
        );
        check_range(
            "64:ff9b::",
            "64:ff9b::ffff:ffff",
            C::Public,
            C::Reserved,
            C::Reserved,
        );
        check_range(
            "2001:3::",
            "2001:3:ffff:ffff:ffff:ffff:ffff:ffff",
            C::Public,
            C::Reserved,
            C::Reserved,
        );
        check_range(
            "2001:20::",
            "2001:2f:ffff:ffff:ffff:ffff:ffff:ffff",
            C::Public,
            C::Reserved,
            C::Reserved,
        );
        check_range(
            "2001:4:112::",
            "2001:4:112:ffff:ffff:ffff:ffff:ffff",
            C::Public,
            C::Reserved,
            C::Reserved,
        );
        check_range(
            "2001:1::1",
            "2001:1::3",
            C::Public,
            C::Reserved,
            C::Reserved,
        );
    }

    #[test]
    fn ipv6_single_addresses() {
        assert_eq!(cat("::"), C::Unspecified);
        assert_eq!(cat("::1"), C::Loopback);
        assert_eq!(cat("::2"), C::Reserved);
        assert_eq!(cat("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), C::Multicast);
        assert_eq!(cat("ff02::1"), C::Multicast);
        assert_eq!(cat("2001::1"), C::Reserved); // Teredo, inside 2001::/23
        assert_eq!(cat("2001:1ff:ffff::"), C::Reserved);
        assert_eq!(cat("2a00:1450::1"), C::Public);
        assert_eq!(cat("2002::1"), C::Public);
        assert_eq!(cat("100::1"), C::Reserved);
        assert_eq!(cat("fec0::1"), C::Reserved);
    }

    #[test]
    fn ipv4_mapped_addresses_follow_their_ipv4_category() {
        for (v4, expected) in [
            ("10.1.2.3", C::Private),
            ("8.8.8.8", C::Public),
            ("255.255.255.255", C::Broadcast),
            ("224.0.0.251", C::Multicast),
            ("169.254.1.1", C::LinkLocal),
            ("127.0.0.1", C::Loopback),
            ("100.64.0.1", C::Cgnat),
            ("0.0.0.0", C::Unspecified),
            ("203.0.113.5", C::Reserved),
        ] {
            assert_eq!(cat(&format!("::ffff:{v4}")), expected, "::ffff:{v4}");
            assert_eq!(cat(v4), expected, "{v4}");
        }
        // IPv4-compatible (deprecated, not mapped) addresses are not IPv4.
        assert_eq!(cat("::10.1.2.3"), C::Reserved);
    }

    #[test]
    fn labels_are_stable_and_round_trip() {
        let labels: Vec<_> = AddressCategory::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            labels,
            [
                "private",
                "public",
                "broadcast",
                "multicast",
                "link_local",
                "loopback",
                "cgnat",
                "unspecified",
                "reserved"
            ]
        );
        for c in AddressCategory::ALL {
            assert_eq!(c.as_str().parse::<AddressCategory>(), Ok(c));
            assert_eq!(c.to_string(), c.as_str());
        }
        assert_eq!("LAN".parse::<AddressCategory>(), Err(UnknownCategory));
    }
}
