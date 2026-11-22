//! ARP exchanges (RFC 826, RFC 5227) for the ARP view: requests and replies, probes, gratuitous
//! announcements, and a cache poisoning pattern (unsolicited replies that claim the router and a
//! workstation for a third MAC address).

use std::net::Ipv4Addr;

use crate::packet::Host;
use crate::scenario::Scenario;
use crate::scenarios::hosts;
use crate::time::NS_PER_SEC;

/// ARP operation codes.
pub const OP_REQUEST: u16 = 1;
pub const OP_REPLY: u16 = 2;

/// Hosts of the ARP showcase (documentation ranges only).
pub mod arp_hosts {
    use super::Host;

    /// Laptop that probes then announces 192.168.1.30 (RFC 5227).
    pub fn laptop() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x30], [192, 168, 1, 30])
    }

    /// Host that poisons the caches of the router and the workstation, 192.168.1.66.
    pub fn intruder() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x66], [192, 168, 1, 66])
    }
}

/// One ARP packet over Ethernet II, as sent on the wire (Ethernet + 28-byte ARP body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpFrame {
    /// Ethernet destination (broadcast for requests and announcements).
    pub eth_dst: [u8; 6],
    pub operation: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

impl ArpFrame {
    /// Frame bytes: Ethernet header (source = sender MAC), ARP for IPv4 over Ethernet, padding
    /// to the 60-byte Ethernet minimum.
    pub fn bytes(&self) -> Vec<u8> {
        let mut f = Vec::with_capacity(60);
        f.extend_from_slice(&self.eth_dst);
        f.extend_from_slice(&self.sender_mac);
        f.extend_from_slice(&0x0806u16.to_be_bytes());
        f.extend_from_slice(&1u16.to_be_bytes()); // hardware: Ethernet
        f.extend_from_slice(&0x0800u16.to_be_bytes()); // protocol: IPv4
        f.push(6);
        f.push(4);
        f.extend_from_slice(&self.operation.to_be_bytes());
        f.extend_from_slice(&self.sender_mac);
        f.extend_from_slice(&self.sender_ip.octets());
        f.extend_from_slice(&self.target_mac);
        f.extend_from_slice(&self.target_ip.octets());
        f.resize(60, 0);
        f
    }
}

fn v4(host: &Host) -> Ipv4Addr {
    host.ipv4().expect("ARP fixtures use IPv4 hosts")
}

impl Scenario {
    /// Any ARP packet; returns its index.
    pub fn arp(&mut self, frame: &ArpFrame) -> usize {
        self.push_frame(frame.bytes())
    }

    /// Who has `target_ip`? Tell `sender` (broadcast).
    pub fn arp_request(&mut self, sender: Host, target_ip: [u8; 4]) -> usize {
        self.arp(&ArpFrame {
            eth_dst: Host::BROADCAST_MAC,
            operation: OP_REQUEST,
            sender_mac: sender.mac,
            sender_ip: v4(&sender),
            target_mac: [0; 6],
            target_ip: Ipv4Addr::from(target_ip),
        })
    }

    /// `sender` is at its MAC, told to `target` (unicast).
    pub fn arp_reply(&mut self, sender: Host, target: Host) -> usize {
        self.arp(&ArpFrame {
            eth_dst: target.mac,
            operation: OP_REPLY,
            sender_mac: sender.mac,
            sender_ip: v4(&sender),
            target_mac: target.mac,
            target_ip: v4(&target),
        })
    }

    /// Request then reply; returns both indices.
    pub fn arp_exchange(&mut self, asker: Host, owner: Host) -> (usize, usize) {
        let owner_ip = v4(&owner).octets();
        let request = self.arp_request(asker, owner_ip);
        let reply = self.arp_reply(owner, asker);
        (request, reply)
    }

    /// RFC 5227 probe: sender address `0.0.0.0`, asking whether `ip` is taken.
    pub fn arp_probe(&mut self, mac: [u8; 6], ip: [u8; 4]) -> usize {
        self.arp(&ArpFrame {
            eth_dst: Host::BROADCAST_MAC,
            operation: OP_REQUEST,
            sender_mac: mac,
            sender_ip: Ipv4Addr::UNSPECIFIED,
            target_mac: [0; 6],
            target_ip: Ipv4Addr::from(ip),
        })
    }

    /// Gratuitous ARP announcement (request form, sender address = target address).
    pub fn arp_announce(&mut self, host: Host) -> usize {
        let ip = v4(&host);
        self.arp(&ArpFrame {
            eth_dst: Host::BROADCAST_MAC,
            operation: OP_REQUEST,
            sender_mac: host.mac,
            sender_ip: ip,
            target_mac: [0; 6],
            target_ip: ip,
        })
    }

    /// Unsolicited reply telling `victim` that `claimed` is at `mac` (cache poisoning).
    pub fn arp_spoof(&mut self, mac: [u8; 6], claimed: [u8; 4], victim: Host) -> usize {
        self.arp(&ArpFrame {
            eth_dst: victim.mac,
            operation: OP_REPLY,
            sender_mac: mac,
            sender_ip: Ipv4Addr::from(claimed),
            target_mac: victim.mac,
            target_ip: v4(&victim),
        })
    }
}

/// Packet counts of [`arp_showcase`], by type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ArpShowcase {
    pub requests: usize,
    pub replies: usize,
    pub gratuitous: usize,
    pub probes: usize,
    /// Replies without a matching request (all sent by the intruder).
    pub unsolicited: usize,
}

/// One exchange of every ARP pattern, over about 16 s:
///
/// 1. the workstation and the file server resolve each other and the router; one request for an
///    absent address stays unanswered;
/// 2. the laptop probes 192.168.1.30, then announces it (gratuitous ARP);
/// 3. after 11 s (outside the window in which a reply may answer a request sent before the
///    capture), the intruder resolves the router, then tells the workstation that the router is at
///    its MAC and the router that the workstation is at its MAC, three times each, one second
///    apart;
/// 4. the router answers the workstation again with its real MAC.
///
/// Conflicts: 192.168.1.1 and 192.168.1.10 are each claimed by two MAC addresses.
pub fn arp_showcase(sc: &mut Scenario) -> ArpShowcase {
    let ws = hosts::workstation();
    let router = hosts::router();
    let fs = hosts::file_server();
    let laptop = arp_hosts::laptop();
    let intruder = arp_hosts::intruder();
    let mut n = ArpShowcase::default();

    sc.arp_exchange(ws, router);
    sc.arp_exchange(fs, ws);
    sc.arp_exchange(ws, fs);
    n.requests += 3;
    n.replies += 3;
    sc.arp_request(ws, [192, 168, 1, 99]);
    n.requests += 1;

    sc.advance(NS_PER_SEC);
    sc.arp_probe(laptop.mac, [192, 168, 1, 30]);
    n.probes += 1;
    sc.advance(NS_PER_SEC);
    sc.arp_announce(laptop);
    n.gratuitous += 1;

    sc.advance(11 * NS_PER_SEC);
    sc.arp_exchange(intruder, router);
    n.requests += 1;
    n.replies += 1;
    let router_ip = v4(&router).octets();
    let ws_ip = v4(&ws).octets();
    for _ in 0..3 {
        sc.arp_spoof(intruder.mac, router_ip, ws);
        sc.arp_spoof(intruder.mac, ws_ip, router);
        n.replies += 2;
        n.unsolicited += 2;
        sc.advance(NS_PER_SEC);
    }

    sc.arp_exchange(ws, router);
    n.requests += 1;
    n.replies += 1;
    n
}

/// Periodic cache refreshes until `until_ns`, one round every `every_ns`: the workstation
/// resolves the router and the file server resolves the workstation; every third round, the
/// intruder repeats its unsolicited replies (demo session: ARP activity over the whole capture).
pub fn arp_background(sc: &mut Scenario, until_ns: i64, every_ns: i64) {
    let ws = hosts::workstation();
    let router = hosts::router();
    let intruder = arp_hosts::intruder();
    let mut round = 0u32;
    while sc.now() < until_ns {
        sc.arp_exchange(ws, router);
        sc.arp_exchange(hosts::file_server(), ws);
        if round % 3 == 2 {
            sc.arp_spoof(intruder.mac, v4(&router).octets(), ws);
            sc.arp_spoof(intruder.mac, v4(&ws).octets(), router);
        }
        round += 1;
        sc.advance(every_ns);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_60_bytes_with_the_arp_body_in_place() {
        let mut sc = Scenario::new();
        let i = sc.arp_request(hosts::workstation(), [192, 168, 1, 1]);
        let f = &sc.packets()[i].data;
        assert_eq!(f.len(), 60);
        assert_eq!(&f[12..14], &[0x08, 0x06]);
        assert_eq!(&f[20..22], &[0, 1]);
        assert_eq!(&f[38..42], &[192, 168, 1, 1]);
    }

    #[test]
    fn showcase_counts_add_up() {
        let mut sc = Scenario::new();
        let n = arp_showcase(&mut sc);
        assert_eq!(
            sc.len(),
            n.requests + n.replies + n.gratuitous + n.probes,
            "every packet has one type"
        );
        assert_eq!(n.unsolicited, 6);
    }

    #[test]
    fn background_stops_at_its_end() {
        let mut sc = Scenario::new();
        let end = sc.now() + 30 * NS_PER_SEC;
        arp_background(&mut sc, end, 10 * NS_PER_SEC);
        // Three rounds (0, 10, 20 s), the third with two spoofed replies.
        assert_eq!(sc.len(), 3 * 4 + 2);
        assert!(sc.packets().iter().all(|p| p.ts_ns < end));
    }
}
