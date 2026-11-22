//! SSDP exchanges (`UPnP` discovery, UDP 1900) for the SSDP view: `NOTIFY` announcements
//! (`ssdp:alive`, `ssdp:byebye`), `M-SEARCH` searches over IPv4 and IPv6 multicast, unicast
//! `200 OK` answers, and malformed datagrams (binary, oversized header).
//!
//! Devices, addresses and UUIDs are invented (documentation ranges only).

use std::fmt::Write as _;
use std::net::Ipv6Addr;

use crate::packet::Host;
use crate::scenario::Scenario;
use crate::scenarios::hosts;
use crate::time::NS_PER_MS;

/// SSDP port.
pub const PORT: u16 = 1900;
/// `NT` / `ST` of every root device.
pub const ROOT_DEVICE: &str = "upnp:rootdevice";
/// Search target of every device and service.
pub const ALL: &str = "ssdp:all";

/// Hosts of the SSDP exchanges.
pub mod ssdp_hosts {
    use super::{Host, Ipv6Addr, hosts};

    /// IPv4 SSDP multicast group `239.255.255.250` (MAC `01:00:5e:7f:ff:fa`).
    pub fn multicast_v4() -> Host {
        Host::v4([0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa], [239, 255, 255, 250])
    }

    /// IPv6 link-local SSDP multicast group `ff02::c` (MAC `33:33:00:00:00:0c`).
    pub fn multicast_v6() -> Host {
        Host::v6(
            [0x33, 0x33, 0x00, 0x00, 0x00, 0x0c],
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0c),
        )
    }

    /// Internet gateway, the LAN router 192.168.1.1.
    pub fn gateway() -> Host {
        hosts::router()
    }

    /// Smart TV, 192.168.1.40.
    pub fn tv() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x40], [192, 168, 1, 40])
    }

    /// Network printer, 192.168.1.50.
    pub fn printer() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x50], [192, 168, 1, 50])
    }

    /// Media server (NAS) reached over IPv6, `2001:db8:1::60`.
    pub fn nas_v6() -> Host {
        Host::v6(
            [0x02, 0x00, 0x5e, 0x10, 0x00, 0x60],
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x60),
        )
    }

    /// Host sending garbage to the SSDP port, 192.168.1.66.
    pub fn noisy() -> Host {
        Host::v4([0x02, 0x00, 0x5e, 0x10, 0x00, 0x66], [192, 168, 1, 66])
    }
}

/// A `UPnP` root device: what it announces in its `NOTIFY` messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub host: Host,
    /// Device UUID (without `uuid:`).
    pub uuid: &'static str,
    /// `urn:...:device:...` type.
    pub device_type: &'static str,
    /// `urn:...:service:...` types.
    pub services: Vec<&'static str>,
    pub server: &'static str,
    /// `LOCATION` URL of the device description.
    pub location: String,
    pub max_age: u32,
}

impl Device {
    /// The `NT` values of a full announcement: root device, UUID, device type, services.
    pub fn targets(&self) -> Vec<String> {
        let mut out = vec![
            ROOT_DEVICE.to_owned(),
            format!("uuid:{}", self.uuid),
            self.device_type.to_owned(),
        ];
        out.extend(self.services.iter().map(|s| (*s).to_owned()));
        out
    }

    /// `USN` for one target (`uuid:<id>` alone for the UUID target).
    pub fn usn(&self, target: &str) -> String {
        if target.starts_with("uuid:") {
            target.to_owned()
        } else {
            format!("uuid:{}::{target}", self.uuid)
        }
    }

    /// `HOST` header value of the multicast group of the device's address family.
    fn host_header(&self) -> &'static str {
        if self.host.ipv4().is_some() {
            "239.255.255.250:1900"
        } else {
            "[FF02::C]:1900"
        }
    }

    /// `NOTIFY` of one target; `nts` is `ssdp:alive`, `ssdp:byebye` or `ssdp:update`.
    pub fn notify(&self, target: &str, nts: &str) -> String {
        let mut m = format!(
            "NOTIFY * HTTP/1.1\r\nHOST: {}\r\nNT: {target}\r\nNTS: {nts}\r\nUSN: {}\r\n",
            self.host_header(),
            self.usn(target)
        );
        if nts != "ssdp:byebye" {
            let _ = write!(
                m,
                "CACHE-CONTROL: max-age={}\r\nLOCATION: {}\r\nSERVER: {}\r\n",
                self.max_age, self.location, self.server
            );
        }
        m.push_str("\r\n");
        m
    }

    /// `200 OK` answer to a search for `target`.
    pub fn response(&self, target: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age={}\r\nDATE: Sun, 22 Nov 2026 10:00:00 GMT\r\n\
             EXT:\r\nLOCATION: {}\r\nSERVER: {}\r\nST: {target}\r\nUSN: {}\r\n\r\n",
            self.max_age,
            self.location,
            self.server,
            self.usn(target)
        )
    }
}

/// `M-SEARCH` for `target`, to the multicast group of `host` (`239.255.255.250:1900` or
/// `[FF02::C]:1900`).
pub fn search(host: &str, target: &str, mx: u32, user_agent: &str) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {host}\r\nMAN: \"ssdp:discover\"\r\nMX: {mx}\r\nST: {target}\r\n\
         USER-AGENT: {user_agent}\r\n\r\n"
    )
}

/// Internet gateway device of the showcase.
pub fn gateway() -> Device {
    Device {
        host: ssdp_hosts::gateway(),
        uuid: "6f1c2a40-1dd2-11b2-a5c3-020000000001",
        device_type: "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        services: vec![
            "urn:schemas-upnp-org:service:Layer3Forwarding:1",
            "urn:schemas-upnp-org:service:WANIPConnection:1",
        ],
        server: "Linux/5.10 UPnP/1.0 ExampleGateway/2.1",
        location: "http://192.168.1.1:5000/rootDesc.xml".to_owned(),
        max_age: 120,
    }
}

/// Smart TV of the showcase (media renderer with DIAL).
pub fn tv() -> Device {
    Device {
        host: ssdp_hosts::tv(),
        uuid: "a7d3b0c2-4e5f-4a6b-8c7d-020000000040",
        device_type: "urn:schemas-upnp-org:device:MediaRenderer:1",
        services: vec![
            "urn:schemas-upnp-org:service:AVTransport:1",
            "urn:dial-multiscreen-org:service:dial:1",
        ],
        server: "Linux/4.19 UPnP/1.0 ExampleTV/7.3",
        location: "http://192.168.1.40:8060/dial/dd.xml".to_owned(),
        max_age: 1800,
    }
}

/// Network printer of the showcase.
pub fn printer() -> Device {
    Device {
        host: ssdp_hosts::printer(),
        uuid: "16a65700-007c-1000-bb49-020000000050",
        device_type: "urn:schemas-upnp-org:device:Printer:1",
        services: vec!["urn:schemas-upnp-org:service:PrintBasic:1"],
        server: "ExampleOS/1.0 UPnP/1.0 ExamplePrinter/4.0",
        location: "http://192.168.1.50:80/upnp/printer.xml".to_owned(),
        max_age: 900,
    }
}

/// Media server reached over IPv6 of the showcase.
pub fn nas() -> Device {
    Device {
        host: ssdp_hosts::nas_v6(),
        uuid: "4d696e69-444c-164e-9d41-020000000060",
        device_type: "urn:schemas-upnp-org:device:MediaServer:1",
        services: vec!["urn:schemas-upnp-org:service:ContentDirectory:1"],
        server: "Linux/6.1 DLNADOC/1.50 UPnP/1.0 ExampleNAS/1.4",
        location: "http://[2001:db8:1::60]:8200/rootDesc.xml".to_owned(),
        max_age: 1800,
    }
}

/// User agent of the workstation's searches.
pub const SEARCH_AGENT: &str = "Windows/10.0 UPnP/2.0 ExampleClient/1.0";

/// Datagrams of the showcase, by kind (to check what an analyzer reads).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShowcaseCounts {
    pub alive: usize,
    pub byebye: usize,
    pub search: usize,
    pub response: usize,
    pub invalid: usize,
}

impl ShowcaseCounts {
    pub fn notify(&self) -> usize {
        self.alive + self.byebye
    }

    pub fn total(&self) -> usize {
        self.notify() + self.search + self.response + self.invalid
    }
}

impl Scenario {
    /// Every `NOTIFY` of `device` (one per target), to its multicast group, 1 ms apart. Returns
    /// the number of datagrams.
    pub fn ssdp_notify(&mut self, device: &Device, nts: &str) -> usize {
        let group = if device.host.ipv4().is_some() {
            ssdp_hosts::multicast_v4()
        } else {
            ssdp_hosts::multicast_v6()
        };
        let targets = device.targets();
        for t in &targets {
            self.udp(
                device.host,
                group,
                PORT,
                PORT,
                device.notify(t, nts).as_bytes(),
            );
            self.advance(NS_PER_MS);
        }
        targets.len()
    }

    /// `M-SEARCH` from `client:port` to the multicast group of its address family.
    pub fn ssdp_search(&mut self, client: Host, port: u16, target: &str) -> usize {
        let (group, header) = if client.ipv4().is_some() {
            (ssdp_hosts::multicast_v4(), "239.255.255.250:1900")
        } else {
            (ssdp_hosts::multicast_v6(), "[FF02::C]:1900")
        };
        let m = search(header, target, 2, SEARCH_AGENT);
        self.udp(client, group, port, PORT, m.as_bytes())
    }

    /// Unicast `200 OK` of `device` to `client:port`.
    pub fn ssdp_response(
        &mut self,
        device: &Device,
        client: Host,
        port: u16,
        target: &str,
    ) -> usize {
        self.udp(
            device.host,
            client,
            PORT,
            port,
            device.response(target).as_bytes(),
        )
    }
}

/// The SSDP showcase, in this order:
///
/// 1. `ssdp:alive` of the gateway, TV and printer (IPv4) and of the NAS (IPv6, `ff02::c`);
/// 2. the workstation searches `ssdp:all` and the gateway, TV and printer answer with their
///    device type; then it searches the DIAL service, which the TV answers;
/// 3. the workstation searches over IPv6, the NAS answers;
/// 4. `ssdp:byebye` of the printer;
/// 5. malformed datagrams: binary bytes, and a `NOTIFY` with a 3000-byte `SERVER` header.
pub fn ssdp_showcase(sc: &mut Scenario) -> ShowcaseCounts {
    let mut n = ShowcaseCounts::default();
    let (gw, tv, printer, nas) = (gateway(), tv(), printer(), nas());
    for d in [&gw, &tv, &printer, &nas] {
        n.alive += sc.ssdp_notify(d, "ssdp:alive");
        sc.advance(10 * NS_PER_MS);
    }

    let ws = hosts::workstation();
    let port = sc.ephemeral_port();
    sc.ssdp_search(ws, port, ALL);
    n.search += 1;
    sc.advance(5 * NS_PER_MS);
    for d in [&gw, &tv, &printer] {
        sc.ssdp_response(d, ws, port, d.device_type);
        n.response += 1;
        sc.advance(2 * NS_PER_MS);
    }
    let port = sc.ephemeral_port();
    let dial = "urn:dial-multiscreen-org:service:dial:1";
    sc.ssdp_search(ws, port, dial);
    sc.advance(3 * NS_PER_MS);
    sc.ssdp_response(&tv, ws, port, dial);
    n.search += 1;
    n.response += 1;

    let ws6 = hosts::workstation_v6();
    let port = sc.ephemeral_port();
    sc.advance(20 * NS_PER_MS);
    sc.ssdp_search(ws6, port, ROOT_DEVICE);
    sc.advance(4 * NS_PER_MS);
    sc.ssdp_response(&nas, ws6, port, ROOT_DEVICE);
    n.search += 1;
    n.response += 1;

    sc.advance(50 * NS_PER_MS);
    n.byebye += sc.ssdp_notify(&printer, "ssdp:byebye");

    sc.advance(10 * NS_PER_MS);
    let garbage: Vec<u8> = (0u8..=200).map(|b| b.wrapping_mul(37)).collect();
    sc.udp(
        ssdp_hosts::noisy(),
        ssdp_hosts::multicast_v4(),
        40_000,
        PORT,
        &garbage,
    );
    n.invalid += 1;
    sc.advance(NS_PER_MS);
    sc.udp(
        ssdp_hosts::noisy(),
        ssdp_hosts::multicast_v4(),
        PORT,
        PORT,
        oversized_notify().as_bytes(),
    );
    n.alive += 1;
    n
}

/// A `NOTIFY ssdp:alive` whose `SERVER` value is 3000 bytes long (field and raw text bounds).
pub fn oversized_notify() -> String {
    format!(
        "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\n\
         NTS: ssdp:alive\r\nUSN: uuid:0000dead-beef-0000-0000-020000000066::upnp:rootdevice\r\n\
         SERVER: {}\r\n\r\n",
        "X".repeat(3000)
    )
}

/// One periodic round of the demo session: the gateway and TV re-announce (`ssdp:alive`), and
/// every `search_every`-th round the workstation searches and both answer.
pub fn ssdp_round(sc: &mut Scenario, round: usize, search_every: usize) {
    let (gw, tv) = (gateway(), tv());
    sc.ssdp_notify(&gw, "ssdp:alive");
    sc.advance(5 * NS_PER_MS);
    sc.ssdp_notify(&tv, "ssdp:alive");
    if search_every > 0 && round.is_multiple_of(search_every) {
        let ws = hosts::workstation();
        let port = sc.ephemeral_port();
        sc.advance(5 * NS_PER_MS);
        sc.ssdp_search(ws, port, ALL);
        sc.advance(3 * NS_PER_MS);
        sc.ssdp_response(&gw, ws, port, gw.device_type);
        sc.ssdp_response(&tv, ws, port, tv.device_type);
    }
}
