//! MAC address vendors and classes: the IEEE Registration Authority listings, embedded at build
//! time, and the meaning of the address bits.
//!
//! Source: the IEEE public listings MA-L (24-bit prefixes), MA-M (28 bits), MA-S and IAB (36
//! bits), compacted by `scripts/gen-ieee-oui.py` into `data/ieee-oui.tsv` (organization names
//! only; procedure and terms of use in `data/README.md`, ADR-031). Nothing is fetched at run
//! time. The table is parsed once, on first use, into three sorted vectors searched by binary
//! search, longest prefix first: a block that the IEEE subdivided (MA-L "IEEE Registration
//! Authority") names the MA-M or MA-S holder when there is one.
//!
//! Classes (IEEE 802-2014, 8.2): the I/G bit (bit 0 of the first octet) marks a group
//! (multicast) address, all-ones being the broadcast address; the U/L bit (bit 1) marks a
//! locally administered address, never registered with the IEEE (virtual machines, randomized
//! addresses of phones and laptops): it has no vendor.

use std::sync::OnceLock;

const TSV: &str = include_str!("../data/ieee-oui.tsv");

/// IEEE registry of an assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Registry {
    /// MA-L, a 24-bit prefix (the historical OUI).
    MaL,
    /// MA-M, a 28-bit prefix.
    MaM,
    /// MA-S (or the older IAB), a 36-bit prefix.
    MaS,
}

impl Registry {
    /// Length of the prefix, in bits.
    pub const fn bits(self) -> u8 {
        match self {
            Self::MaL => 24,
            Self::MaM => 28,
            Self::MaS => 36,
        }
    }

    /// Stable label (`ma-l`, `ma-m`, `ma-s`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MaL => "ma-l",
            Self::MaM => "ma-m",
            Self::MaS => "ma-s",
        }
    }
}

/// The IEEE assignment that covers an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assignment {
    pub registry: Registry,
    /// Organization name as listed by the IEEE (`Private` for unlisted holders).
    pub organization: &'static str,
}

/// Unicast, multicast or broadcast (I/G bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MacKind {
    Unicast,
    Multicast,
    Broadcast,
}

impl MacKind {
    /// Stable label stored by the store (`unicast`, `multicast`, `broadcast`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unicast => "unicast",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
        }
    }
}

/// Well-known group addresses that no vendor lookup names (or names unhelpfully).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WellKnownGroup {
    /// `01:00:5e:00:00:00`-`01:00:5e:7f:ff:ff`, IPv4 multicast (RFC 1112).
    Ipv4Multicast,
    /// `33:33:xx:xx:xx:xx`, IPv6 multicast (RFC 2464).
    Ipv6Multicast,
    /// `01:80:c2:00:00:00`-`0f`, reserved for IEEE 802.1 bridges (STP, LACP, LLDP, 802.1X...).
    Ieee8021Reserved,
}

impl WellKnownGroup {
    /// Stable label (`ipv4_multicast`, `ipv6_multicast`, `ieee8021_reserved`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4Multicast => "ipv4_multicast",
            Self::Ipv6Multicast => "ipv6_multicast",
            Self::Ieee8021Reserved => "ieee8021_reserved",
        }
    }
}

/// Class of a MAC address, from its bits only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacClass {
    pub kind: MacKind,
    /// Locally administered (U/L bit set): not registered, possibly random.
    pub local: bool,
    pub group: Option<WellKnownGroup>,
}

/// Class of `mac`.
pub fn classify(mac: [u8; 6]) -> MacClass {
    let [b0, b1, b2, b3, b4, b5] = mac;
    let kind = if mac == [0xff; 6] {
        MacKind::Broadcast
    } else if b0 & 0x01 != 0 {
        MacKind::Multicast
    } else {
        MacKind::Unicast
    };
    let group = match (b0, b1, b2, b3, b4, b5) {
        (0x01, 0x00, 0x5e, 0x00..=0x7f, _, _) => Some(WellKnownGroup::Ipv4Multicast),
        (0x33, 0x33, _, _, _, _) => Some(WellKnownGroup::Ipv6Multicast),
        (0x01, 0x80, 0xc2, 0x00, 0x00, 0x00..=0x0f) => Some(WellKnownGroup::Ieee8021Reserved),
        _ => None,
    };
    MacClass {
        kind,
        local: b0 & 0x02 != 0,
        group,
    }
}

/// Vendor of `mac`: the IEEE assignment of its prefix, with the I/G bit cleared (a group address
/// such as `01:80:c2:...` belongs to the holder of `00:80:c2`). `None` for a locally administered
/// address (never assigned) and for an unassigned prefix.
pub fn vendor(mac: [u8; 6]) -> Option<Assignment> {
    let class = classify(mac);
    if class.local || class.kind == MacKind::Broadcast {
        return None;
    }
    let [b0, rest @ ..] = mac;
    let [b1, b2, b3, b4, b5] = rest;
    lookup([b0 & !0x01, b1, b2, b3, b4, b5])
}

/// IEEE assignment whose prefix covers `mac` (longest prefix first), whatever its class bits.
pub fn lookup(mac: [u8; 6]) -> Option<Assignment> {
    let t = table();
    let v = mac_u64(mac);
    let find = |entries: &[(u64, &'static str)], bits: u8| {
        let key = v >> (48 - u32::from(bits));
        entries
            .binary_search_by_key(&key, |e| e.0)
            .ok()
            .and_then(|i| entries.get(i))
            .map(|e| e.1)
    };
    [Registry::MaS, Registry::MaM, Registry::MaL]
        .into_iter()
        .find_map(|registry| {
            let entries = match registry {
                Registry::MaS => &t.mas,
                Registry::MaM => &t.mam,
                Registry::MaL => &t.mal,
            };
            find(entries, registry.bits()).map(|organization| Assignment {
                registry,
                organization,
            })
        })
}

/// Number of entries per registry of the embedded table: MA-L, MA-M, MA-S (diagnostics, tests).
pub fn table_len() -> (usize, usize, usize) {
    let t = table();
    (t.mal.len(), t.mam.len(), t.mas.len())
}

fn mac_u64(mac: [u8; 6]) -> u64 {
    mac.iter().fold(0, |acc, b| (acc << 8) | u64::from(*b))
}

struct Table {
    mal: Vec<(u64, &'static str)>,
    mam: Vec<(u64, &'static str)>,
    mas: Vec<(u64, &'static str)>,
}

fn table() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = Table {
            mal: Vec::with_capacity(40_000),
            mam: Vec::with_capacity(8_000),
            mas: Vec::with_capacity(12_000),
        };
        for line in TSV.lines() {
            if line.starts_with('#') {
                continue;
            }
            let Some((prefix, name)) = line.split_once('\t') else {
                continue;
            };
            let (Ok(value), name) = (u64::from_str_radix(prefix, 16), name.trim()) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            match prefix.len() {
                6 => t.mal.push((value, name)),
                7 => t.mam.push((value, name)),
                9 => t.mas.push((value, name)),
                _ => {}
            }
        }
        // The file is sorted; sorting again keeps the search correct if it is edited by hand.
        for v in [&mut t.mal, &mut t.mam, &mut t.mas] {
            v.sort_unstable_by_key(|e| e.0);
            v.dedup_by_key(|e| e.0);
        }
        t
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(s: &str) -> [u8; 6] {
        let mut out = [0u8; 6];
        for (o, part) in out.iter_mut().zip(s.split(':')) {
            *o = u8::from_str_radix(part, 16).unwrap();
        }
        out
    }

    #[test]
    fn every_data_line_is_parsed() {
        let data_lines = TSV
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .count();
        let (l, m, s) = table_len();
        assert_eq!(l + m + s, data_lines);
        assert!(l > 30_000, "the MA-L listing looks truncated");
        assert!(m > 4_000, "the MA-M listing looks truncated");
        assert!(s > 8_000, "the MA-S listing looks truncated");
    }

    #[test]
    fn well_known_vendors() {
        for (addr, org) in [
            ("08:00:27:09:d9:cb", "PCS Systemtechnik GmbH"),
            ("00:00:0c:12:34:56", "Cisco Systems, Inc"),
            ("00:50:56:aa:bb:cc", "VMware, Inc."),
            ("b8:27:eb:01:02:03", "Raspberry Pi Foundation"),
            ("3c:22:fb:00:00:01", "Apple, Inc."),
        ] {
            let a = vendor(mac(addr)).unwrap();
            assert_eq!((a.registry, a.organization), (Registry::MaL, org), "{addr}");
        }
        assert_eq!(vendor(mac("00:00:00:00:00:00")).unwrap().organization, "XEROX CORPORATION");
    }

    #[test]
    fn longest_prefix_wins() {
        // MA-M: 1C-87-74-0 is listed, inside an MA-L block of the IEEE itself.
        let a = vendor(mac("1c:87:74:01:02:03")).unwrap();
        assert_eq!(a.registry, Registry::MaM);
        assert_eq!(a.organization, "Philips Personal Health Solutions");
        // MA-S: 70-B3-D5-00-1 inside 70-B3-D5 ("IEEE Registration Authority").
        let a = vendor(mac("70:b3:d5:00:1a:bc")).unwrap();
        assert_eq!(a.registry, Registry::MaS);
        assert_eq!(a.organization, "SOREDI touch systems GmbH");
        // IAB entries are 36-bit prefixes too.
        assert_eq!(vendor(mac("00:50:c2:57:40:01")).unwrap().registry, Registry::MaS);
        assert_eq!(
            vendor(mac("00:50:c2:57:40:01")).unwrap().organization,
            "Ingeniería Almudí S.L."
        );
        // An unlisted 36-bit block falls back to the MA-L holder.
        let fallback = lookup(mac("70:b3:d5:ff:ff:f0")).unwrap();
        assert!(matches!(fallback.registry, Registry::MaL | Registry::MaS));
    }

    #[test]
    fn classes() {
        let b = classify([0xff; 6]);
        assert_eq!((b.kind, b.local, b.group), (MacKind::Broadcast, true, None));
        assert_eq!(vendor([0xff; 6]), None);

        let v4 = classify(mac("01:00:5e:00:00:fb"));
        assert_eq!(v4.kind, MacKind::Multicast);
        assert_eq!(v4.group, Some(WellKnownGroup::Ipv4Multicast));
        assert!(!v4.local);
        // Group bit cleared for the lookup: 00-00-5E belongs to IANA.
        assert_eq!(
            vendor(mac("01:00:5e:00:00:fb")).unwrap().organization,
            "ICANN, IANA Department"
        );
        assert_eq!(classify(mac("01:00:5e:80:00:01")).group, None);

        let v6 = classify(mac("33:33:00:00:00:01"));
        assert_eq!((v6.kind, v6.local), (MacKind::Multicast, true));
        assert_eq!(v6.group, Some(WellKnownGroup::Ipv6Multicast));
        assert_eq!(vendor(mac("33:33:00:00:00:01")), None);

        let stp = classify(mac("01:80:c2:00:00:00"));
        assert_eq!(stp.group, Some(WellKnownGroup::Ieee8021Reserved));
        assert_eq!(
            vendor(mac("01:80:c2:00:00:0e")).unwrap().organization,
            "IEEE 802.1 Working Group"
        );
        assert_eq!(classify(mac("01:80:c2:00:00:10")).group, None);
    }

    #[test]
    fn locally_administered_addresses_have_no_vendor() {
        // QEMU user networking, a randomized phone address, Docker.
        for addr in ["52:55:0a:00:02:01", "da:a1:19:3c:4e:7f", "02:42:ac:11:00:02"] {
            let c = classify(mac(addr));
            assert_eq!((c.kind, c.local), (MacKind::Unicast, true), "{addr}");
            assert_eq!(vendor(mac(addr)), None, "{addr}");
        }
    }
}
