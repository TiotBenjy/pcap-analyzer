//! Independent reader built on `pcap-file` (never on netsift crates) and stream helpers.
#![allow(dead_code)]

use std::io::Read as _;
use std::path::Path;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use flate2::read::GzDecoder;
use netsift_fixtures::Packet;
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;
use pcap_file::pcapng::{Block, PcapNgReader};

/// A packet as decoded by `pcap-file`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadPacket {
    pub ts_ns: i64,
    pub linktype: u32,
    pub interface: u32,
    pub data: Vec<u8>,
}

impl From<&Packet> for ReadPacket {
    fn from(p: &Packet) -> Self {
        Self {
            ts_ns: p.ts_ns,
            linktype: p.linktype,
            interface: p.interface,
            data: p.data.clone(),
        }
    }
}

/// Decompresses gzip input (by magic), returns raw capture bytes.
pub fn raw_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        GzDecoder::new(bytes)
            .read_to_end(&mut out)
            .expect("valid gzip");
        out
    } else {
        bytes.to_vec()
    }
}

/// Reads every packet of a pcap / pcapng (optionally gzip) file.
pub fn read_bytes(bytes: &[u8]) -> Vec<ReadPacket> {
    let raw = raw_bytes(bytes);
    if raw.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        read_pcapng(&raw)
    } else {
        read_pcap(&raw)
    }
}

pub fn read_file(path: &Path) -> Vec<ReadPacket> {
    read_bytes(&std::fs::read(path).expect("readable file"))
}

fn read_pcap(raw: &[u8]) -> Vec<ReadPacket> {
    let mut reader = PcapReader::new(raw).expect("valid pcap header");
    let linktype = u32::from(reader.header().datalink);
    let mut out = Vec::new();
    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt.expect("valid pcap record");
        out.push(ReadPacket {
            ts_ns: i64::try_from(pkt.timestamp.as_nanos()).unwrap(),
            linktype,
            interface: 0,
            data: pkt.data.into_owned(),
        });
    }
    out
}

/// pcap-file reports EPB timestamps as raw units wrapped in a `Duration::from_nanos`;
/// conversion with `if_tsresol` is done here, independently of the crate under test.
fn read_pcapng(raw: &[u8]) -> Vec<ReadPacket> {
    let mut reader = PcapNgReader::new(raw).expect("valid pcapng header");
    let mut interfaces: Vec<(u32, u8)> = Vec::new(); // (linktype, if_tsresol)
    let mut out = Vec::new();
    while let Some(block) = reader.next_block() {
        match block.expect("valid pcapng block") {
            Block::InterfaceDescription(idb) => {
                let resol = idb
                    .options
                    .iter()
                    .find_map(|o| match o {
                        InterfaceDescriptionOption::IfTsResol(r) => Some(*r),
                        _ => None,
                    })
                    .unwrap_or(6);
                interfaces.push((u32::from(idb.linktype), resol));
            }
            Block::EnhancedPacket(epb) => {
                let (linktype, resol) = interfaces[epb.interface_id as usize];
                let units = epb.timestamp.as_nanos();
                let ns = if resol & 0x80 == 0 {
                    let exp = u32::from(resol);
                    if exp <= 9 {
                        units * 10u128.pow(9 - exp)
                    } else {
                        units / 10u128.pow(exp - 9)
                    }
                } else {
                    (units * 1_000_000_000) >> (resol & 0x7f)
                };
                out.push(ReadPacket {
                    ts_ns: i64::try_from(ns).unwrap(),
                    linktype,
                    interface: epb.interface_id,
                    data: epb.data.into_owned(),
                });
            }
            _ => {}
        }
    }
    out
}

/// Expected read-back of `packets` when timestamps are truncated to `unit_ns`.
pub fn expected(packets: &[Packet], unit_ns: i64) -> Vec<ReadPacket> {
    packets
        .iter()
        .map(|p| ReadPacket {
            ts_ns: p.ts_ns - p.ts_ns % unit_ns,
            ..ReadPacket::from(p)
        })
        .collect()
}

/// Decoded TCP segment of a frame.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: Option<u32>,
    pub syn: bool,
    pub fin: bool,
    pub psh: bool,
    pub rst: bool,
    pub payload: Vec<u8>,
}

pub fn tcp_segment(frame: &[u8]) -> Option<Segment> {
    let sliced = SlicedPacket::from_ethernet(frame).expect("valid frame");
    match sliced.transport? {
        TransportSlice::Tcp(tcp) => Some(Segment {
            src_port: tcp.source_port(),
            dst_port: tcp.destination_port(),
            seq: tcp.sequence_number(),
            ack: tcp.ack().then(|| tcp.acknowledgment_number()),
            syn: tcp.syn(),
            fin: tcp.fin(),
            psh: tcp.psh(),
            rst: tcp.rst(),
            payload: tcp.payload().to_vec(),
        }),
        _ => None,
    }
}

/// UDP ports and payload of a frame.
pub fn udp_payload(frame: &[u8]) -> Option<(u16, u16, Vec<u8>)> {
    let sliced = SlicedPacket::from_ethernet(frame).expect("valid frame");
    match sliced.transport? {
        TransportSlice::Udp(udp) => Some((
            udp.source_port(),
            udp.destination_port(),
            udp.payload().to_vec(),
        )),
        _ => None,
    }
}

/// Source and destination IP addresses (textual) of a frame.
pub fn ip_pair(frame: &[u8]) -> (String, String) {
    let sliced = SlicedPacket::from_ethernet(frame).expect("valid frame");
    match sliced.net.expect("IP layer") {
        NetSlice::Ipv4(v4) => (
            v4.header().source_addr().to_string(),
            v4.header().destination_addr().to_string(),
        ),
        NetSlice::Ipv6(v6) => (
            v6.header().source_addr().to_string(),
            v6.header().destination_addr().to_string(),
        ),
        NetSlice::Arp(_) => panic!("unexpected ARP"),
    }
}

/// Checks sequence/acknowledgement coherence of one TCP connection (`frames` in order,
/// client = sender of the first SYN) and returns the reassembled (client, server) streams.
pub fn check_tcp_connection(frames: &[&[u8]], mss: usize) -> (Vec<u8>, Vec<u8>) {
    let segments: Vec<Segment> = frames.iter().filter_map(|f| tcp_segment(f)).collect();
    assert_eq!(segments.len(), frames.len(), "every frame is TCP");
    let syn = &segments[0];
    assert!(syn.syn && syn.ack.is_none(), "connection starts with a SYN");
    let client_port = syn.src_port;
    let synack = &segments[1];
    assert!(synack.syn && synack.ack == Some(syn.seq.wrapping_add(1)));

    let mut next = [syn.seq, synack.seq]; // [client, server] next expected seq
    let mut streams = (Vec::new(), Vec::new());
    let mut fins = [false, false];
    for seg in &segments {
        let dir = usize::from(seg.src_port != client_port);
        assert_eq!(seg.seq, next[dir], "sequence number continuity");
        if let Some(ack) = seg.ack {
            assert_eq!(ack, next[1 - dir], "ACK acknowledges everything received");
        }
        assert!(seg.payload.len() <= mss, "segment within MSS");
        assert!(!seg.rst);
        let advance =
            u32::try_from(seg.payload.len()).unwrap() + u32::from(seg.syn) + u32::from(seg.fin);
        next[dir] = next[dir].wrapping_add(advance);
        if dir == 0 {
            streams.0.extend_from_slice(&seg.payload);
        } else {
            streams.1.extend_from_slice(&seg.payload);
        }
        fins[dir] |= seg.fin;
    }
    assert_eq!(fins, [true, true], "both sides closed with FIN");
    let last = segments.last().unwrap();
    assert!(
        last.ack.is_some() && !last.fin && last.payload.is_empty(),
        "final ACK"
    );
    streams
}
