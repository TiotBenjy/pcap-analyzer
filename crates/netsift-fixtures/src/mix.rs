//! Large mixed-traffic captures for benchmarks (`netsift-fixtures big`, `docs/PERFORMANCE.md`).
//!
//! A [`MixGen`] produces packets in timestamp order, window after window, until a target
//! number of frame bytes is reached. Each window holds [`EXCHANGES_PER_WINDOW`] independent
//! exchanges (DNS lookups, TLS handshakes, HTTP transactions, bulk transfers, UDP services,
//! logins, short connections), each built in its own [`Scenario`] at a random start inside the
//! window, so that flows overlap like in a real capture. Windows are stretched so that the
//! whole capture spans [`MixOptions::span_ns`].
//!
//! Hosts: `lan_hosts` workstations in 10.0.0.0/16 (plus IPv6 in `2001:db8:1::/64`), two LAN
//! resolvers, `public_hosts` servers at addresses scattered over public IPv4 space (and
//! `2001:db8:ff::/48`), chosen with a log-uniform popularity (a few servers get most
//! exchanges). About half the packets are small (DNS, handshakes, ACKs) and most bytes travel
//! in bulk transfers: about 10 million packets for 5 GB.
//!
//! Deterministic: the same options give the same bytes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::credentials::{http_basic, pop3_login};
use crate::packet::{Host, Packet};
use crate::proto::dns::DnsType;
use crate::proto::netbios::{HostAnnouncement, NetbiosName};
use crate::proto::png::png_image;
use crate::proto::x509::{CertSpec, certificate};
use crate::rng::SplitMix64;
use crate::scenario::{
    DnsExchange, FtpLogin, HttpGet, Scenario, SnmpGet, TcpOptions, TcpSession, TlsHandshake,
};
use crate::time::{NS_PER_MS, NS_PER_SEC};

/// Exchanges generated per window.
pub const EXCHANGES_PER_WINDOW: usize = 1_000;

const ROUTER_MAC: [u8; 6] = [0x02, 0x00, 0x5e, 0x20, 0x00, 0x01];
const FILLER_LEN: usize = 1 << 20;
const CERTS: usize = 256;
const IMAGES: u32 = 24;
const PATHS: [&str; 12] = [
    "/",
    "/index.html",
    "/api/v1/items",
    "/api/v1/status",
    "/static/app.js",
    "/static/style.css",
    "/search",
    "/login",
    "/news/latest",
    "/feed.xml",
    "/assets/fonts/main.woff2",
    "/robots.txt",
];
const WORDS: [&str; 16] = [
    "cdn",
    "api",
    "static",
    "mail",
    "news",
    "shop",
    "video",
    "update",
    "auth",
    "img",
    "ads",
    "cloud",
    "sync",
    "telemetry",
    "portal",
    "files",
];
const TLDS: [&str; 6] = ["com", "net", "org", "io", "example", "test"];
const AGENTS: [&str; 4] = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
    "curl/8.5.0",
    "Updater/2.3 (compatible)",
];
/// First octets of the public IPv4 servers: no private, loopback, link-local, CGNAT, multicast
/// or reserved /8 (10, 100, 127, 169, 172, 192 and 224+ are left out).
const PUBLIC_FIRST_OCTETS: [u8; 12] = [23, 31, 45, 52, 62, 80, 91, 104, 142, 151, 185, 203];

/// Parameters of a mixed capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MixOptions {
    pub seed: u64,
    /// Timestamp of the first window.
    pub start_ns: i64,
    /// Time covered by the whole capture.
    pub span_ns: i64,
    /// Frame bytes after which generation stops (the last window is completed).
    pub target_bytes: u64,
    pub lan_hosts: u32,
    pub public_hosts: u32,
    pub domains: u32,
}

impl Default for MixOptions {
    /// 5 GB over seven days, 1 000 workstations, 200 000 servers, 50 000 domains.
    fn default() -> Self {
        Self {
            seed: crate::scenario::DEFAULT_SEED,
            start_ns: crate::scenario::DEFAULT_START_NS,
            span_ns: 7 * 86_400 * NS_PER_SEC,
            target_bytes: 5_000_000_000,
            lan_hosts: 1_000,
            public_hosts: 200_000,
            domains: 50_000,
        }
    }
}

/// Streaming generator of a mixed capture.
pub struct MixGen {
    opts: MixOptions,
    rng: SplitMix64,
    certs: Vec<Vec<u8>>,
    images: Vec<Vec<u8>>,
    filler: Vec<u8>,
    tls12: TlsHandshake,
    tls13: TlsHandshake,
    /// Packets generated but not yet released (they belong to a later window).
    pending: Vec<Packet>,
    window_start: i64,
    produced: u64,
    done: bool,
}

impl MixGen {
    pub fn new(opts: MixOptions) -> Self {
        let mut rng = SplitMix64::new(opts.seed);
        let certs = (0..CERTS)
            .map(|i| {
                let mut spec = CertSpec::new(domain_name(u32::try_from(i).unwrap_or(0)));
                spec.serial = 0x2000 + u64::try_from(i).unwrap_or(0);
                certificate(&spec)
            })
            .collect();
        let images = (0..IMAGES)
            .map(|i| png_image(32 + i * 7, 24 + i * 5))
            .collect();
        let mut filler = vec![0u8; FILLER_LEN];
        rng.fill(&mut filler);
        let template = TlsHandshake::new("template.example.test");
        Self {
            window_start: opts.start_ns,
            tls12: template.clone(),
            tls13: TlsHandshake::tls13("template.example.test"),
            opts,
            rng,
            certs,
            images,
            filler,
            pending: Vec::new(),
            produced: 0,
            done: false,
        }
    }

    /// Frame bytes released so far.
    pub fn produced_bytes(&self) -> u64 {
        self.produced
    }

    /// Packets of the next window, in timestamp order; `None` once the target is reached and
    /// every pending packet has been released.
    pub fn next_window(&mut self) -> Option<Vec<Packet>> {
        if self.done {
            return None;
        }
        let mut exchanges: Vec<Vec<Packet>> = Vec::with_capacity(EXCHANGES_PER_WINDOW);
        let mut bytes = 0u64;
        for _ in 0..EXCHANGES_PER_WINDOW {
            let mut sc = Scenario::starting_at(0).with_seed(self.rng.next_u64());
            self.exchange(&mut sc);
            let packets = sc.into_packets();
            bytes += packets.iter().map(|p| p.data.len() as u64).sum::<u64>();
            exchanges.push(packets);
        }
        // The window lasts its share of the span, in proportion to its bytes.
        let span = u128::try_from(self.opts.span_ns.max(1)).unwrap_or(1);
        let target = u128::from(self.opts.target_bytes.max(1));
        let duration = i64::try_from(span * u128::from(bytes) / target)
            .unwrap_or(i64::MAX)
            .max(1);
        let duration_u = u64::try_from(duration).unwrap_or(1);
        for packets in exchanges {
            let offset = i64::try_from(self.rng.next_u64() % duration_u).unwrap_or(0);
            let base = self.window_start + offset;
            self.pending.extend(packets.into_iter().map(|mut p| {
                p.ts_ns += base;
                p
            }));
        }
        self.window_start += duration;
        self.produced += bytes;
        // Stable: packets of one exchange keep their order on equal timestamps.
        self.pending.sort_by_key(|p| p.ts_ns);
        let last = self.produced >= self.opts.target_bytes;
        let cut = if last {
            self.done = true;
            self.pending.len()
        } else {
            self.pending
                .partition_point(|p| p.ts_ns < self.window_start)
        };
        let rest = self.pending.split_off(cut);
        Some(std::mem::replace(&mut self.pending, rest))
    }

    fn pick(&mut self, n: u32) -> u32 {
        u32::try_from(self.rng.next_u64() % u64::from(n.max(1))).unwrap_or(0)
    }

    /// Log-uniform index in `0..n`: index 0 is the most popular.
    fn popular(&mut self, n: u32) -> u32 {
        let n = n.max(1);
        #[allow(clippy::cast_precision_loss)]
        let u = (self.rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let i = ((f64::from(n) + 1.0).powf(u) - 1.0).floor() as u32;
        i.min(n - 1)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.rng.next_u64() % n.max(1)
    }

    /// Log-uniform size in `lo..hi`.
    fn size(&mut self, lo: usize, hi: usize) -> usize {
        #[allow(clippy::cast_precision_loss)]
        let u = (self.rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        #[allow(clippy::cast_precision_loss)]
        let (l, h) = ((lo.max(1)) as f64, (hi.max(lo + 1)) as f64);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let s = (l * (h / l).powf(u)) as usize;
        s.clamp(lo, hi)
    }

    fn workstation(&mut self, v6: bool) -> Host {
        let i = self.pick(self.opts.lan_hosts);
        lan_host(i, v6)
    }

    fn server(&mut self, v6: bool) -> (u32, Host) {
        let i = self.popular(self.opts.public_hosts);
        (i, public_host(i, v6))
    }

    fn resolver(&mut self) -> Host {
        let i = 1 + self.pick(2);
        Host::v4(
            [0x02, 0x00, 0x5e, 0x20, 0x01, u8::try_from(i).unwrap_or(1)],
            [10, 0, 255, u8::try_from(i).unwrap_or(1)],
        )
    }

    fn domain(&mut self) -> String {
        let d = self.popular(self.opts.domains);
        domain_name(d)
    }

    fn port(&mut self) -> u16 {
        49_152 + u16::try_from(self.below(16_000)).unwrap_or(0)
    }

    fn filler(&mut self, len: usize) -> &[u8] {
        let len = len.min(FILLER_LEN);
        let start = usize::try_from(self.below((FILLER_LEN - len + 1) as u64)).unwrap_or(0);
        self.filler.get(start..start + len).unwrap_or_default()
    }

    fn exchange(&mut self, sc: &mut Scenario) {
        let v6 = self.below(100) < 5;
        match self.below(1000) {
            0..450 => self.dns(sc, v6),
            450..650 => self.tls(sc, v6),
            650..800 => self.http(sc, v6, false),
            800..812 => self.http(sc, v6, true),
            812..820 => self.bulk(sc, v6),
            820..882 => self.udp_service(sc),
            882..902 => self.login(sc),
            _ => self.short_tcp(sc, v6),
        }
    }

    fn dns(&mut self, sc: &mut Scenario, v6: bool) {
        let client = self.workstation(false);
        let resolver = self.resolver();
        let name = self.domain();
        let ip = public_v4(self.popular(self.opts.public_hosts)).octets();
        let mut ex = match self.below(100) {
            0..5 => DnsExchange::nxdomain(name, DnsType::A),
            5..15 => DnsExchange::cname(name.clone(), format!("edge.{name}"), ip),
            15..30 => DnsExchange::aaaa(
                name,
                Ipv6Addr::new(0x2001, 0xdb8, 0xff, 0, 0, 0, 0, u16::from(ip[3])),
            ),
            _ if v6 => DnsExchange::new(name, DnsType::Txt),
            _ => DnsExchange::a(name, ip),
        };
        if self.below(100) < 3 {
            ex = ex.unanswered();
        }
        ex.client_port = Some(self.port());
        sc.dns(client, resolver, &ex);
    }

    fn tls(&mut self, sc: &mut Scenario, v6: bool) {
        let client = self.workstation(v6);
        let (index, server) = self.server(v6);
        let name = domain_name(index % self.opts.domains.max(1));
        let mut hs = if self.below(2) == 0 {
            self.tls13.clone()
        } else {
            self.tls12.clone()
        };
        hs.sni = Some(name);
        let cert = usize::try_from(index).unwrap_or(0) % CERTS;
        hs.certificate_chain = self.certs.get(cert).cloned().into_iter().collect();
        hs.tcp.client_port = Some(self.port());
        sc.tls_handshake(client, server, &hs);
    }

    fn http(&mut self, sc: &mut Scenario, v6: bool, image: bool) {
        let client = self.workstation(v6);
        let (index, server) = self.server(v6);
        let path = PATHS
            .get(usize::try_from(self.below(PATHS.len() as u64)).unwrap_or(0))
            .copied()
            .unwrap_or("/");
        let agent = AGENTS
            .get(usize::try_from(self.below(AGENTS.len() as u64)).unwrap_or(0))
            .copied()
            .unwrap_or("curl/8.5.0");
        let (status, reason) = match self.below(100) {
            0..85 => (200, "OK"),
            85..90 => (301, "Moved Permanently"),
            90..97 => (404, "Not Found"),
            _ => (500, "Internal Server Error"),
        };
        let mut get = HttpGet {
            host: domain_name(index % self.opts.domains.max(1)),
            path: format!("{path}?q={}", self.below(1000)),
            user_agent: agent.to_owned(),
            status,
            reason: reason.to_owned(),
            ..HttpGet::default()
        };
        get.tcp.client_port = Some(self.port());
        if image {
            let i = usize::try_from(self.below(u64::from(IMAGES))).unwrap_or(0);
            get.path = format!("/img/{i}.png");
            get.body = self.images.get(i).cloned().unwrap_or_default();
        } else {
            let (kind, len) = match self.below(4) {
                0 => ("text/html", self.size(300, 40_000)),
                1 => ("application/json", self.size(100, 8_000)),
                2 => ("application/javascript", self.size(1_000, 60_000)),
                _ => ("text/css", self.size(200, 20_000)),
            };
            kind.clone_into(&mut get.content_type);
            // Printable body: the HTTP views show previews.
            get.body = self.filler(len).iter().map(|b| b'a' + b % 26).collect();
        }
        sc.http_get(client, server, &get);
    }

    /// Large download: HTTP `application/octet-stream` on port 80 or raw bytes on another
    /// port, acknowledged every two segments.
    fn bulk(&mut self, sc: &mut Scenario, v6: bool) {
        let client = self.workstation(v6);
        let (index, server) = self.server(v6);
        let len = self.size(20_000, 3_000_000);
        let port = [80u16, 443, 22, 445, 8080]
            .get(usize::try_from(self.below(5)).unwrap_or(0))
            .copied()
            .unwrap_or(80);
        let mut payload = Vec::with_capacity(len + 256);
        let mut request = Vec::new();
        if port == 80 {
            let host = domain_name(index % self.opts.domains.max(1));
            request = format!(
                "GET /downloads/file-{}.bin HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8.5.0\r\n\r\n",
                self.below(10_000)
            )
            .into_bytes();
            payload.extend_from_slice(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {len}\r\n\r\n"
                )
                .as_bytes(),
            );
        } else {
            request.extend_from_slice(self.filler(200));
        }
        payload.extend_from_slice(self.filler(len));
        let mut opts = TcpOptions::new(port);
        opts.client_port = Some(self.port());
        let mut s = sc.tcp_open(client, server, &opts);
        s.client_send(&request);
        send_acked(&mut s, &payload);
        s.close();
    }

    fn udp_service(&mut self, sc: &mut Scenario) {
        let client = self.workstation(false);
        match self.below(4) {
            0 => {
                let (_, server) = self.server(false);
                sc.ntp_query(client, server, 2, [192, 0, 2, 1]);
            }
            1 => {
                let get = SnmpGet {
                    request_id: i32::try_from(self.below(1 << 20)).unwrap_or(1),
                    client_port: Some(self.port()),
                    ..SnmpGet::default()
                };
                let agent = self.resolver();
                sc.snmp_get(client, agent, &get);
            }
            2 => {
                let name = NetbiosName::new(format!("HOST{}", self.below(500)), 0x20);
                let id = u16::try_from(self.below(65_536)).unwrap_or(0);
                sc.nbns_query(client, Host::broadcast_v4([10, 0, 255, 255]), id, &name);
            }
            _ => {
                let ann = HostAnnouncement::default();
                sc.smb_host_announcement(client, Host::broadcast_v4([10, 0, 255, 255]), &ann);
            }
        }
    }

    fn login(&mut self, sc: &mut Scenario) {
        let client = self.workstation(false);
        let user = format!("user{}", self.below(2_000));
        let server = lan_host(60_000 + self.pick(8), false);
        match self.below(3) {
            0 => {
                let login = FtpLogin {
                    user,
                    password: format!("pw-{}", self.below(100)),
                    tcp: TcpOptions {
                        client_port: Some(self.port()),
                        ..TcpOptions::new(21)
                    },
                    ..FtpLogin::default()
                };
                sc.ftp_login(client, server, &login);
            }
            1 => http_basic(sc, client, server, &user, "basic-pw", false),
            _ => pop3_login(sc, client, server, &user, "pop-pw"),
        }
    }

    /// Connection opened and closed without data (open ports, scans).
    fn short_tcp(&mut self, sc: &mut Scenario, v6: bool) {
        let client = self.workstation(v6);
        let server = if self.below(2) == 0 {
            lan_host(self.pick(self.opts.lan_hosts), v6)
        } else {
            self.server(v6).1
        };
        let port = [22u16, 25, 110, 139, 143, 389, 445, 3389, 5432, 8443]
            .get(usize::try_from(self.below(10)).unwrap_or(0))
            .copied()
            .unwrap_or(22);
        let mut opts = TcpOptions::new(port);
        opts.client_port = Some(self.port());
        let s = sc.tcp_open(client, server, &opts);
        s.close();
        sc.advance(NS_PER_MS);
    }
}

/// Sends `data` from the server two segments at a time, each pair acknowledged by the client.
fn send_acked(s: &mut TcpSession<'_>, data: &[u8]) {
    for piece in data.chunks(2 * 1460) {
        s.server_send(piece);
    }
}

/// Workstation `i` (10.0.x.y, or `2001:db8:1::x:y`).
fn lan_host(i: u32, v6: bool) -> Host {
    let [_, _, hi, lo] = i.to_be_bytes();
    let mac = [0x02, 0x00, 0x5e, 0x30, hi, lo];
    if v6 {
        Host::v6(
            mac,
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, u16::from(hi), u16::from(lo)),
        )
    } else {
        // 10.0.255.0/24 holds the resolvers and the subnet broadcast.
        Host::v4(mac, [10, 0, hi.min(254), lo.max(1)])
    }
}

/// Public IPv4 address of server `i` (scattered, never private or reserved).
fn public_v4(i: u32) -> Ipv4Addr {
    let mut hash = SplitMix64::new(u64::from(i) ^ 0x5eed);
    let x = hash.next_u64();
    let first = PUBLIC_FIRST_OCTETS
        .get(usize::try_from(x % PUBLIC_FIRST_OCTETS.len() as u64).unwrap_or(0))
        .copied()
        .unwrap_or(23);
    let [_, second, third, fourth] = u32::try_from(x >> 32).unwrap_or(0).to_be_bytes();
    // `i` is unique per address: its low bits pick the last two octets.
    let [_, _, ih, il] = i.to_be_bytes();
    Ipv4Addr::new(first, second ^ ih, third ^ il, fourth.max(1))
}

fn public_host(i: u32, v6: bool) -> Host {
    let ip = if v6 {
        let [_, _, hi, lo] = i.to_be_bytes();
        IpAddr::V6(Ipv6Addr::new(
            0x2001,
            0xdb8,
            0xff,
            u16::from(hi),
            0,
            0,
            0,
            u16::from(lo) + 1,
        ))
    } else {
        IpAddr::V4(public_v4(i))
    };
    Host::new(ROUTER_MAC, ip)
}

/// Domain name `d` (`<word><n>.<tld>`).
pub fn domain_name(d: u32) -> String {
    let w = WORDS
        .get(usize::try_from(d).unwrap_or(0) % WORDS.len())
        .copied()
        .unwrap_or("www");
    let t = TLDS
        .get(usize::try_from(d / 16).unwrap_or(0) % TLDS.len())
        .copied()
        .unwrap_or("test");
    format!("{w}{}.site{}.{t}", d / 96, d % 7)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> MixOptions {
        MixOptions {
            target_bytes: 3_000_000,
            span_ns: 3_600 * NS_PER_SEC,
            ..MixOptions::default()
        }
    }

    #[test]
    fn windows_are_ordered_and_reach_the_target() {
        let mut generator = MixGen::new(small());
        let mut last = i64::MIN;
        let mut bytes = 0u64;
        let mut packets = 0usize;
        while let Some(window) = generator.next_window() {
            for p in &window {
                assert!(p.ts_ns >= last, "timestamps go back");
                last = p.ts_ns;
                bytes += p.data.len() as u64;
            }
            packets += window.len();
        }
        assert!(bytes >= 3_000_000);
        assert_eq!(bytes, generator.produced_bytes());
        // Small packets dominate the count, bulk transfers the bytes.
        let avg = bytes / u64::try_from(packets).unwrap();
        assert!((300..800).contains(&avg), "average frame {avg} bytes");
        // Windows share the span in proportion to their bytes (the last one may overshoot).
        let span =
            i64::try_from(i128::from(3_600 * NS_PER_SEC) * i128::from(bytes) / 3_000_000).unwrap();
        assert!(
            last - DEFAULT_START <= span + 60 * NS_PER_SEC,
            "{bytes} {}",
            last - DEFAULT_START
        );
    }

    const DEFAULT_START: i64 = crate::scenario::DEFAULT_START_NS;

    #[test]
    fn generation_is_deterministic() {
        let a = MixGen::new(small()).next_window().unwrap();
        let b = MixGen::new(small()).next_window().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn public_addresses_are_public_and_distinct() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..50_000 {
            let ip = public_v4(i);
            assert!(
                !ip.is_private() && !ip.is_loopback() && !ip.is_multicast(),
                "{ip}"
            );
            seen.insert(ip);
        }
        assert!(seen.len() > 49_000);
    }
}
