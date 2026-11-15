//! Seed corpus of the fuzz targets, built from `netsift-fixtures` traffic: nothing binary is
//! committed, `./x.sh fuzz corpus` regenerates it.
//!
//! Usage: `gen_corpus <out_dir>`, writes `<out_dir>/<target>/<name>`.
//!
//! The scenarios are run once through a flow table; what it reports (TCP stream data per
//! direction, UDP payloads) is cut into the inputs of each target with the framings of
//! `netsift_fuzz`, so that every seed decodes exactly as its target reads it.

#![allow(clippy::print_stdout)]

use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fs;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use netsift_analyze::dissect::{Decoded, linktype};
use netsift_analyze::flow::{
    Direction, FlowConfig, FlowCtx, FlowId, FlowKey, FlowSink, FlowTable, PacketCtx, StreamCtx,
};
use netsift_fixtures::proto::{smb, x509};
use netsift_fixtures::scenario::Scenario;
use netsift_fixtures::scenarios::{self, Kind};
use netsift_fixtures::writer::{Encoding, encode};
use netsift_fixtures::{Packet, credentials, http_mix, images, servers};
use netsift_fuzz::{Conversation, conversation_head, push_frame, push_segment};
use netsift_geo::test_util::MmdbBuilder;

/// Largest capture-file seed.
const MAX_FILE: usize = 64 * 1024;
/// Largest stream seed.
const MAX_STREAM: usize = 32 * 1024;
/// Most seeds per target and source scenario.
const MAX_PER_SOURCE: usize = 24;

/// What the flow table reported for one flow.
#[derive(Debug)]
struct Flow {
    key: FlowKey,
    udp: bool,
    /// `(to_server, gap, bytes)` in arrival order.
    pieces: Vec<(bool, u64, Vec<u8>)>,
}

#[derive(Default)]
struct Collector {
    order: Vec<FlowId>,
    flows: BTreeMap<FlowId, Flow>,
}

impl Collector {
    fn flow(&mut self, id: FlowId, key: FlowKey, udp: bool) -> &mut Flow {
        if !self.flows.contains_key(&id) {
            self.order.push(id);
        }
        self.flows.entry(id).or_insert_with(|| Flow {
            key,
            udp,
            pieces: Vec::new(),
        })
    }
}

impl FlowSink for Collector {
    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>) {
        let (Some(f), Some(_)) = (ctx.flow, pkt.udp()) else {
            return;
        };
        let to_server = f.dir == Direction::ToServer;
        let payload = pkt.payload.to_vec();
        self.flow(f.id, f.key, true)
            .pieces
            .push((to_server, 0, payload));
    }

    fn on_stream(&mut self, ctx: &StreamCtx, dir: Direction, data: &[u8]) {
        let to_server = dir == Direction::ToServer;
        self.flow(ctx.id, ctx.key, false)
            .pieces
            .push((to_server, ctx.gap_before, data.to_vec()));
    }

    fn on_flow_end(&mut self, _ctx: &FlowCtx) {}
}

struct Out {
    root: PathBuf,
    count: usize,
    seen: HashSet<(String, Vec<u8>)>,
}

impl Out {
    fn put(&mut self, target: &str, name: &str, data: &[u8]) -> Result<(), Box<dyn Error>> {
        if data.is_empty() || !self.seen.insert((target.to_owned(), data.to_vec())) {
            return Ok(());
        }
        let dir = self.root.join(target);
        fs::create_dir_all(&dir)?;
        let n = fs::read_dir(&dir)?.count();
        fs::write(dir.join(format!("{name}-{n:03}")), data)?;
        self.count += 1;
        Ok(())
    }
}

fn sources() -> Vec<(String, Vec<Packet>)> {
    let mut out: Vec<(String, Vec<Packet>)> = Kind::ALL
        .iter()
        .map(|k| (k.name().to_owned(), scenarios::generate(*k, 1, 7)))
        .collect();
    let build = |f: &dyn Fn(&mut Scenario)| {
        let mut sc = Scenario::new();
        f(&mut sc);
        sc.into_packets()
    };
    out.push((
        "credentials".into(),
        build(&credentials::credentials_showcase),
    ));
    out.push(("servers".into(), build(&servers::servers_showcase)));
    out.push(("httpmix".into(), build(&http_mix::round)));
    out.push(("images".into(), build(&images::gallery)));
    out.push(("tlsshow".into(), build(&scenarios::tls_showcase)));
    out.push(("frag".into(), scenarios::fragmentation().0.into_packets()));
    out
}

/// The first packets of `packets` whose encoding stays under [`MAX_FILE`].
fn bounded_file(packets: &[Packet], encoding: &Encoding) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut n = packets.len();
    loop {
        let file = encode(packets.get(..n).unwrap_or_default(), encoding)?;
        if file.len() <= MAX_FILE || n <= 1 {
            return Ok(file);
        }
        n = n * 3 / 4;
    }
}

fn collect(packets: &[Packet]) -> Collector {
    let mut table = FlowTable::new(FlowConfig::default());
    let mut sink = Collector::default();
    for (frame, p) in (0u64..).zip(packets) {
        let len = u32::try_from(p.data.len()).unwrap_or(u32::MAX);
        table.process(p.ts_ns, 0, frame, p.linktype, len, &p.data, &mut sink);
    }
    table.finish(&mut sink);
    sink
}

/// The pieces of `flow` in the segments framing, bounded.
fn segments_of(flow: &Flow) -> Vec<u8> {
    let mut out = Vec::new();
    for (to_server, gap, data) in &flow.pieces {
        if out.len() + data.len() > MAX_STREAM {
            break;
        }
        push_segment(
            &mut out,
            *to_server,
            u8::try_from(*gap).unwrap_or(u8::MAX),
            data,
        );
    }
    out
}

/// Concatenated bytes of one direction, bounded.
fn side(flow: &Flow, to_server: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for (dir, _, data) in &flow.pieces {
        if *dir == to_server && out.len() + data.len() <= MAX_STREAM {
            out.extend_from_slice(data);
        }
    }
    out
}

fn linktype_index(lt: u32) -> u8 {
    let i = linktype::SUPPORTED
        .iter()
        .position(|&l| l == lt)
        .unwrap_or(0);
    u8::try_from(i).unwrap_or(0)
}

/// `GET /x HTTP/1.1\r\nA: b\r\n\r\nbody` -> `/x\nA: b\n\nbody` (input of `http_auth`).
fn http_auth_input(request: &[u8]) -> Option<Vec<u8>> {
    let text = String::from_utf8_lossy(request);
    let (head, body) = text.split_once("\r\n\r\n")?;
    let mut lines = head.split("\r\n");
    let target = lines.next()?.split(' ').nth(1)?;
    let mut out = format!("{target}\n");
    for l in lines {
        out.push_str(l);
        out.push('\n');
    }
    out.push('\n');
    out.push_str(body);
    Some(out.into_bytes())
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn from_scenario(out: &mut Out, name: &str, packets: &[Packet]) -> Result<(), Box<dyn Error>> {
    // Whole files: capture readers and the end-to-end pipeline.
    let encodings = [
        ("pcap", Encoding::pcap()),
        ("pcapns", Encoding::pcap_ns()),
        ("pcapng", Encoding::pcapng()),
        ("pcapnggz", Encoding::pcapng().gz()),
    ];
    for (i, (ename, enc)) in encodings.iter().enumerate() {
        let file = bounded_file(packets, enc)?;
        out.put("capture", &format!("{name}-{ename}"), &file)?;
        if i == 0 || i == 2 {
            out.put("pipeline", &format!("{name}-{ename}"), &file)?;
        }
    }

    // Frames: dissect (one per seed) and the flow layer (sequences).
    let mut seq = vec![linktype_index(
        packets.first().map_or(linktype::ETHERNET, |p| p.linktype),
    )];
    let mut prev = packets.first().map_or(0, |p| p.ts_ns);
    for (i, p) in packets.iter().enumerate() {
        if i < MAX_PER_SOURCE * 2 {
            let mut d = vec![linktype_index(p.linktype)];
            d.extend_from_slice(&p.data);
            out.put("dissect", name, &d)?;
            // The same frame without its Ethernet header, as raw IP.
            if p.linktype == linktype::ETHERNET && p.data.len() > 14 {
                let mut raw = vec![linktype_index(linktype::RAW)];
                raw.extend_from_slice(p.data.get(14..).unwrap_or_default());
                out.put("dissect", &format!("{name}-raw"), &raw)?;
            }
        }
        if seq.len() + p.data.len() < MAX_FILE {
            let step = u8::try_from(((p.ts_ns - prev) / 10_000_000).clamp(0, 239)).unwrap_or(0);
            push_frame(&mut seq, step, &p.data);
            prev = p.ts_ns;
        }
    }
    out.put("flow_table", name, &seq)?;

    // What the flow table reported, per flow.
    let collected = collect(packets);
    for id in collected.order.iter().take(64) {
        let Some(flow) = collected.flows.get(id) else {
            continue;
        };
        let (sport, cport) = (flow.key.server.port, flow.key.client.port);
        let segs = segments_of(flow);
        let conv = Conversation {
            udp: flow.udp,
            client_port: cport,
            server_port: sport,
            handshake: true,
            close: true,
        };
        if let Some(head) = conversation_head(&conv) {
            let mut d = head.to_vec();
            d.extend_from_slice(&segs);
            out.put("analyzers", name, &d)?;
        }
        for (_, _, payload) in &flow.pieces {
            if let Some(at) = find(payload, b"NTLMSSP\0") {
                out.put("ntlmssp", name, payload.get(at..).unwrap_or_default())?;
            }
        }
        if flow.udp {
            for (_, _, payload) in flow.pieces.iter().take(MAX_PER_SOURCE) {
                let target = match sport {
                    53 | 137 | 5353 | 5355 => "dns",
                    67 | 68 | 88 | 123 => "udp_services",
                    138 => "smb",
                    161 | 162 => "snmp",
                    _ => continue,
                };
                out.put(target, name, payload)?;
            }
            continue;
        }
        match sport {
            80 | 8080 => {
                out.put("http", name, &segs)?;
                let request = side(flow, true);
                if let Some(input) = http_auth_input(&request) {
                    out.put("http_auth", name, &input)?;
                }
            }
            389 | 3268 => out.put("ldap", name, &segs)?,
            21 | 25 | 110 | 143 | 587 | 2525 => {
                let sel = match sport {
                    21 => 0u8,
                    25 | 587 | 2525 => 1,
                    110 => 2,
                    _ => 3,
                };
                let mut d = vec![sel];
                d.extend_from_slice(&segs);
                out.put("lineproto", name, &d)?;
            }
            443 | 8443 => {
                let mut stream = vec![1u8];
                stream.extend_from_slice(&segs);
                out.put("tls", name, &stream)?;
                for to_server in [true, false] {
                    let mut records = vec![0u8];
                    records.extend_from_slice(&side(flow, to_server));
                    out.put("tls", name, &records)?;
                }
            }
            139 | 445 => {
                out.put("smb", name, &side(flow, true))?;
                out.put("smb", name, &side(flow, false))?;
            }
            88 => out.put("udp_services", name, &side(flow, true))?,
            _ => {}
        }
    }
    Ok(())
}

fn handmade(out: &mut Out) -> Result<(), Box<dyn Error>> {
    // NTLMSSP messages, bare and as a Negotiate header.
    let auth = smb::ntlmssp_authenticate("CORP", "alice", "WS01", &[1; 24], &[2; 48]);
    out.put("ntlmssp", "negotiate", &smb::ntlmssp_negotiate())?;
    out.put(
        "ntlmssp",
        "challenge",
        &smb::ntlmssp_challenge([7; 8], "CORP"),
    )?;
    out.put("ntlmssp", "authenticate", &auth)?;
    out.put(
        "smb",
        "session-setup",
        &smb::nbss(&smb::smb2_session_setup_request(&auth)),
    )?;
    out.put(
        "smb",
        "smb1-setup",
        &smb::nbss(&smb::smb1_session_setup_andx_request(&auth)),
    )?;
    out.put(
        "smb",
        "negotiate",
        &smb::nbss(&smb::smb2_negotiate_response(0x0311, 1, [3; 16])),
    )?;

    // HTTP credentials.
    let b64 = credentials::base64(&auth);
    let challenge = credentials::base64(&smb::ntlmssp_challenge([9; 8], "CORP"));
    for input in [
        "/login\nAuthorization: Basic YWxpY2U6c2VjcmV0\n\n".to_owned(),
        "/proxy\nProxy-Authorization: Basic Ym9iOnB3ZA==\n\n".to_owned(),
        format!("/ntlm\nWWW-Authenticate: NTLM {challenge}\nAuthorization: NTLM {b64}\n\n"),
        format!(
            "/neg\nWWW-Authenticate: Negotiate {challenge}\nAuthorization: Negotiate {b64}\n\n"
        ),
        "/form\nContent-Type: application/x-www-form-urlencoded\n\nuser=alice&password=s%3Acr+t"
            .to_owned(),
        "/q?username=bob&passwd=hunter2&x=%zz\nHost: example.test\n\n".to_owned(),
    ] {
        out.put("http_auth", "handmade", input.as_bytes())?;
    }

    // Certificates (bare DER, TLS pure mode).
    for (i, cn) in ["example.test", "ca.example.test"].iter().enumerate() {
        let mut spec = x509::CertSpec::new(*cn);
        spec.dns_names = vec![(*cn).to_owned(), format!("www.{cn}")];
        spec.ca = i == 1;
        let mut d = vec![0u8];
        d.extend_from_slice(&x509::self_signed_certificate(&spec));
        out.put("tls", "cert", &d)?;
    }

    // Country databases, raw and gzip.
    let dbs = [
        MmdbBuilder::new()
            .database_type("DBIP-Country-Lite")
            .network(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 0)), 24, "AU")
            .network(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 0)), 24, "US")
            .build(),
        MmdbBuilder::new()
            .database_type("GeoLite2-Country")
            .network(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 0)),
                32,
                "US",
            )
            .network(IpAddr::V4(Ipv4Addr::new(81, 2, 69, 0)), 24, "GB")
            .build(),
    ];
    for db in &dbs {
        out.put("mmdb", "db", db)?;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(db)?;
        out.put("mmdb", "dbgz", &gz.finish()?)?;
    }

    // Images of every decoded format, plus truncated and oversized ones.
    let imgs = [
        ("png", images::png(24, 16, 0)),
        ("jpeg", images::jpeg(24, 16, 1)),
        ("gif", images::gif(24, 16, 2)),
        ("webp", images::webp(24, 16, 3)),
        ("bmp", images::bmp(24, 16, 4)),
        ("ico", images::ico(16)),
        ("pixel", images::pixel_gif()),
        ("truncated", images::truncated_jpeg(24, 16, 200)),
        ("bomb", images::dimension_bomb_png(100_000, 100_000)),
    ];
    for (name, img) in &imgs {
        out.put("thumbs", name, img)?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: gen_corpus <out_dir>")?;
    fs::create_dir_all(&root)?;
    let mut out = Out {
        root,
        count: 0,
        seen: HashSet::new(),
    };
    for (name, packets) in sources() {
        from_scenario(&mut out, &name, &packets)?;
    }
    handmade(&mut out)?;
    report(&out.root, out.count)?;
    Ok(())
}

fn report(root: &Path, total: usize) -> Result<(), Box<dyn Error>> {
    let mut dirs: Vec<_> = fs::read_dir(root)?.filter_map(Result::ok).collect();
    dirs.sort_by_key(fs::DirEntry::file_name);
    for d in dirs {
        let n = fs::read_dir(d.path())?.count();
        println!("{:<14} {n}", d.file_name().to_string_lossy());
    }
    println!("{total} seeds in {}", root.display());
    Ok(())
}
