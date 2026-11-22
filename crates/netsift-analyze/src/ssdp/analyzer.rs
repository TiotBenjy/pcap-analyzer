//! The `ssdp` analyzer: every UDP datagram from or to port 1900 (multicast `239.255.255.250`,
//! `ff02::c`, `ff05::c`, or unicast answers) becomes one [`SsdpRecord`]. Stateless, so nothing
//! is buffered: memory does not grow with the capture.

use netsift_dissect::Decoded;
use netsift_flow::{Endpoint, PacketCtx};

use super::parser::{self, SsdpMessage};
use crate::analyzer::{Analyzer, AnalyzerId, RecordSink};
use crate::record::Record;
use crate::registry::AnalyzerConfig;

/// SSDP port (`UPnP` Device Architecture, section 1).
pub const SSDP_PORT: u16 = 1900;

/// One SSDP datagram (`ssdp_messages`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsdpRecord {
    pub ts: i64,
    pub src: Endpoint,
    pub dst: Endpoint,
    /// The destination is a multicast address.
    pub multicast: bool,
    pub message: SsdpMessage,
}

/// See the module documentation.
#[derive(Debug, Default)]
pub struct SsdpAnalyzer;

impl SsdpAnalyzer {
    pub const ID: AnalyzerId = AnalyzerId("ssdp");

    pub fn new(_config: &AnalyzerConfig) -> Self {
        Self
    }

    /// [`crate::registry::Factory`] of this analyzer.
    pub fn boxed(config: &AnalyzerConfig) -> Box<dyn Analyzer> {
        Box::new(Self::new(config))
    }
}

impl Analyzer for SsdpAnalyzer {
    fn id(&self) -> AnalyzerId {
        Self::ID
    }

    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>, out: &mut dyn RecordSink) {
        let Some(udp) = pkt.udp() else { return };
        if udp.src_port != SSDP_PORT && udp.dst_port != SSDP_PORT {
            return;
        }
        let Some(ip) = pkt.ip() else { return };
        if pkt.payload.is_empty() {
            return;
        }
        out.emit(Record::Ssdp(Box::new(SsdpRecord {
            ts: ctx.ts_ns,
            src: Endpoint {
                ip: ip.src,
                port: udp.src_port,
            },
            dst: Endpoint {
                ip: ip.dst,
                port: udp.dst_port,
            },
            multicast: ip.dst.is_multicast(),
            message: parser::parse(pkt.payload),
        })));
    }
}
