//! Infrastructure exchanges for the Servers view: DHCP (DISCOVER, OFFER, REQUEST, ACK), NTP,
//! Kerberos over UDP and TCP, DNS SRV lookups of a domain controller and an LDAP connection.

use std::net::Ipv4Addr;

use crate::packet::Host;
use crate::proto::dhcp::{DhcpMessage, DhcpType};
use crate::proto::dns::{DnsAnswer, DnsData, DnsType};
use crate::proto::{kerberos, ntp};
use crate::scenario::{DnsExchange, Scenario, TcpOptions};
use crate::scenarios::hosts;

/// Hosts of the infrastructure exchanges (documentation ranges only).
pub mod servers_hosts {
    use super::{Host, hosts};

    /// Domain controller (DNS name `dc.corp.example`, LDAP, Kerberos), 192.168.1.5.
    pub fn domain_controller() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x05], [192, 168, 1, 5])
    }

    /// Public NTP server 203.0.113.123, reached through the router MAC.
    pub fn ntp_server() -> Host {
        Host::v4(hosts::router().mac, [203, 0, 113, 123])
    }

    /// MAC address of the laptop that obtains a lease in [`super::servers_showcase`].
    pub const LAPTOP_MAC: [u8; 6] = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x30];
}

/// Kerberos realm of the showcase.
pub const REALM: &str = "CORP.EXAMPLE";
/// DNS name of the domain controller.
pub const DC_NAME: &str = "dc.corp.example";

/// A DHCP lease handed out by a server (see [`Scenario::dhcp_dora`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpLease {
    pub xid: u32,
    pub client_mac: [u8; 6],
    /// Address offered and acknowledged.
    pub address: Ipv4Addr,
    /// Host name sent by the client in its REQUEST (option 12).
    pub hostname: Option<String>,
    pub lease_time: u32,
    pub router: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
}

/// Packet indices of a DHCP exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhcpIndices {
    pub discover: usize,
    pub offer: usize,
    pub request: usize,
    pub ack: usize,
}

impl Scenario {
    /// DHCP DISCOVER, OFFER, REQUEST and ACK between a new client (`0.0.0.0`, broadcast) and
    /// `server` (replies broadcast too, as for a client that cannot receive unicast yet).
    pub fn dhcp_dora(&mut self, server: Host, lease: &DhcpLease) -> DhcpIndices {
        let client = Host::v4(lease.client_mac, [0, 0, 0, 0]);
        let everyone = Host::broadcast_v4([255, 255, 255, 255]);
        let server_ip = server.ipv4().expect("DHCP requires IPv4");
        let reply = |kind| {
            let mut m = DhcpMessage::new(kind, lease.xid, lease.client_mac);
            m.yiaddr = lease.address;
            m.server_id = Some(server_ip);
            m.subnet_mask = Some(Ipv4Addr::new(255, 255, 255, 0));
            m.routers = vec![lease.router];
            m.dns_servers.clone_from(&lease.dns);
            m.lease_time = Some(lease.lease_time);
            m
        };
        let mut discover = DhcpMessage::new(DhcpType::Discover, lease.xid, lease.client_mac);
        discover.hostname.clone_from(&lease.hostname);
        let discover = self.udp(client, everyone, 68, 67, &discover.encode());
        let offer = self.udp(server, everyone, 67, 68, &reply(DhcpType::Offer).encode());
        let mut request = DhcpMessage::new(DhcpType::Request, lease.xid, lease.client_mac);
        request.requested_ip = Some(lease.address);
        request.server_id = Some(server_ip);
        request.hostname.clone_from(&lease.hostname);
        let request = self.udp(client, everyone, 68, 67, &request.encode());
        let ack = self.udp(server, everyone, 67, 68, &reply(DhcpType::Ack).encode());
        DhcpIndices {
            discover,
            offer,
            request,
            ack,
        }
    }

    /// NTP request (mode 3) from `client` and the response (mode 4) of `server`.
    pub fn ntp_query(
        &mut self,
        client: Host,
        server: Host,
        stratum: u8,
        reference_id: [u8; 4],
    ) -> (usize, usize) {
        let port = self.ephemeral_port();
        let request = self.udp(client, server, port, 123, &ntp::request(1));
        let response = self.udp(
            server,
            client,
            123,
            port,
            &ntp::response(stratum, reference_id, 2),
        );
        (request, response)
    }

    /// Kerberos AS exchange over UDP 88: AS-REQ, KRB-ERROR (pre-authentication required),
    /// AS-REQ again, AS-REP.
    pub fn kerberos_as_udp(&mut self, client: Host, kdc: Host, realm: &str, user: &str) {
        let port = self.ephemeral_port();
        let req = kerberos::kdc_req(false, realm, user);
        self.udp(client, kdc, port, 88, &req);
        let error = kerberos::krb_error(kerberos::ERR_PREAUTH_REQUIRED, realm);
        self.udp(kdc, client, 88, port, &error);
        self.udp(client, kdc, port, 88, &req);
        self.udp(
            kdc,
            client,
            88,
            port,
            &kerberos::kdc_rep(false, realm, user),
        );
    }

    /// Kerberos TGS exchange over TCP 88 (length-prefixed records, segmented by the MSS).
    pub fn kerberos_tgs_tcp(&mut self, client: Host, kdc: Host, realm: &str, user: &str) {
        let mut s = self.tcp_open(client, kdc, &TcpOptions::new(88));
        s.client_send(&kerberos::tcp_record(&kerberos::kdc_req(true, realm, user)));
        s.server_send(&kerberos::tcp_record(&kerberos::kdc_rep(true, realm, user)));
        s.close();
    }

    /// LDAP connection to `server:389`: handshake, a few bytes each way, close.
    pub fn ldap_connection(&mut self, client: Host, server: Host) {
        let mut s = self.tcp_open(client, server, &TcpOptions::new(389));
        // Anonymous bind request and its success response (LDAPv3).
        s.client_send(&[
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
        ]);
        s.server_send(&[
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
        ]);
        s.close();
    }
}

/// Every infrastructure exchange, once: the router (192.168.1.1) leases 192.168.1.30 to
/// `laptop-30` and answers the SRV lookup of the domain controller, which then serves LDAP and
/// Kerberos (UDP and TCP); the laptop asks the public NTP server for the time.
pub fn servers_showcase(sc: &mut Scenario) {
    use servers_hosts::{LAPTOP_MAC, domain_controller, ntp_server};
    let router = hosts::router();
    let dc = domain_controller();
    let lease = DhcpLease {
        xid: 0x3903_f326,
        client_mac: LAPTOP_MAC,
        address: Ipv4Addr::new(192, 168, 1, 30),
        hostname: Some("laptop-30".to_owned()),
        lease_time: 86_400,
        router: Ipv4Addr::new(192, 168, 1, 1),
        dns: vec![Ipv4Addr::new(192, 168, 1, 1)],
    };
    sc.dhcp_dora(router, &lease);
    let laptop = Host::v4(LAPTOP_MAC, [192, 168, 1, 30]);
    sc.ntp_query(laptop, ntp_server(), 2, [192, 0, 2, 1]);

    let mut srv = DnsExchange::new("_ldap._tcp.dc._msdcs.corp.example", DnsType::Srv);
    srv.answers.push(DnsAnswer::new(
        srv.name.clone(),
        600,
        DnsData::Srv {
            priority: 0,
            weight: 100,
            port: 389,
            target: DC_NAME.to_owned(),
        },
    ));
    sc.dns(laptop, router, &srv);
    let mut kdc = DnsExchange::new("_kerberos._tcp.corp.example", DnsType::Srv);
    kdc.answers.push(DnsAnswer::new(
        kdc.name.clone(),
        600,
        DnsData::Srv {
            priority: 0,
            weight: 100,
            port: 88,
            target: DC_NAME.to_owned(),
        },
    ));
    sc.dns(laptop, router, &kdc);
    let ip = dc.ipv4().expect("IPv4 domain controller").octets();
    sc.dns(laptop, router, &DnsExchange::a(DC_NAME, ip));

    sc.ldap_connection(laptop, dc);
    sc.kerberos_as_udp(laptop, dc, REALM, "jdoe");
    sc.kerberos_tgs_tcp(laptop, dc, REALM, "jdoe");
}
