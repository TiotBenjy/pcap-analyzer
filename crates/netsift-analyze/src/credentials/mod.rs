//! The `credentials` analyzer: authentication material of the protocols that have no analyzer
//! of their own. Every credential is a [`Record::Credential`]; the Credentials tab aggregates
//! them with those of the other analyzers (SMB/NTLM in `smb`, HTTP Basic, forms and NTLM in
//! `http`).
//!
//! - [`lineproto`]: FTP, SMTP AUTH, POP3 and IMAP (TCP, by server port);
//! - [`ldap`]: LDAP simple binds (TCP 389 / 3268);
//! - [`snmp`]: SNMP v1/v2c communities (UDP 161 / 162).
//!
//! Recognition is by well-known port (both ends are tried, for connections picked up in the
//! middle). Per-flow state is small and bounded (lines, one BER message, a few pending binds),
//! and at most [`MAX_PER_FLOW`] credentials are emitted per flow. Secrets never reach a log:
//! [`Credential`]'s `Debug` redacts them.

mod ldap;
mod lineproto;
mod snmp;
pub(crate) mod text;

use std::collections::HashMap;
use std::fmt;

use netsift_dissect::Decoded;
use netsift_flow::{Direction, FlowCtx, FlowId, FlowKey, PacketCtx, StreamCtx};

use crate::analyzer::{Analyzer, AnalyzerId, RecordSink};
use crate::record::{Credential, Record, SecretState};
use crate::registry::AnalyzerConfig;
use ldap::LdapFlow;
use lineproto::{LineFlow, LineProto};
use text::LineBuf;

pub use lineproto::HASHCAT_CRAM_MD5;

/// Most credentials emitted for one flow (a brute-force session stays bounded).
pub const MAX_PER_FLOW: usize = 128;

/// A credential with the common fields of a flow and no secret yet.
pub(crate) fn base_credential(
    protocol: &'static str,
    kind: &'static str,
    id: FlowId,
    key: &FlowKey,
    ts: i64,
    state: SecretState,
) -> Credential {
    Credential {
        source_protocol: protocol,
        kind,
        flow_id: Some(id),
        client: Some(key.client),
        server: Some(key.server),
        ts,
        username: None,
        domain: None,
        workstation: None,
        secret_state: state,
        secret: None,
        hashcat_mode: None,
        hashcat_line: None,
        details: Vec::new(),
    }
}

/// What a TCP flow is parsed as.
enum Parser {
    Lines {
        flow: Box<LineFlow>,
        client: LineBuf,
        server: LineBuf,
    },
    Ldap(Box<LdapFlow>),
}

impl fmt::Debug for Parser {
    /// The variant only: the line buffers may hold a password.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lines { flow, .. } => f.debug_tuple("Lines").field(flow).finish(),
            Self::Ldap(flow) => f.debug_tuple("Ldap").field(flow).finish(),
        }
    }
}

#[derive(Debug)]
struct TcpFlow {
    /// The flow key's client is the real server (connection picked up in the middle).
    swapped: bool,
    parser: Parser,
}

/// The `credentials` analyzer (one instance per shard). `Debug` shows counts only.
#[derive(Default)]
pub struct CredentialsAnalyzer {
    flows: HashMap<FlowId, Option<TcpFlow>>,
    /// Communities emitted per SNMP flow (bounded by [`MAX_PER_FLOW`]).
    snmp: HashMap<FlowId, usize>,
}

impl fmt::Debug for CredentialsAnalyzer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialsAnalyzer")
            .field("tcp_flows", &self.flows.len())
            .field("snmp_flows", &self.snmp.len())
            .finish()
    }
}

impl CredentialsAnalyzer {
    pub const ID: AnalyzerId = AnalyzerId("credentials");

    pub fn new(_config: &AnalyzerConfig) -> Self {
        Self::default()
    }

    pub fn boxed(config: &AnalyzerConfig) -> Box<dyn Analyzer> {
        Box::new(Self::new(config))
    }
}

/// Parser of a TCP flow, from its ports (server side first).
fn parser_for(id: FlowId, key: &FlowKey) -> Option<TcpFlow> {
    let pick = |port: u16, key: FlowKey| -> Option<Parser> {
        if let Some(proto) = LineProto::of_port(port) {
            return Some(Parser::Lines {
                flow: Box::new(LineFlow::new(proto, id, key)),
                client: LineBuf::default(),
                server: LineBuf::default(),
            });
        }
        ldap::PORTS
            .contains(&port)
            .then(|| Parser::Ldap(Box::new(LdapFlow::new(id, key))))
    };
    if let Some(parser) = pick(key.server.port, *key) {
        return Some(TcpFlow {
            swapped: false,
            parser,
        });
    }
    let reversed = FlowKey {
        proto: key.proto,
        client: key.server,
        server: key.client,
    };
    pick(key.client.port, reversed).map(|parser| TcpFlow {
        swapped: true,
        parser,
    })
}

impl Analyzer for CredentialsAnalyzer {
    fn id(&self) -> AnalyzerId {
        Self::ID
    }

    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>, out: &mut dyn RecordSink) {
        if pkt.udp().is_none() {
            return;
        }
        let (Some((sport, dport)), Some(ip)) = (pkt.ports(), pkt.ip()) else {
            return;
        };
        let Some((client, server)) = snmp::orient((ip.src, sport), (ip.dst, dport)) else {
            return;
        };
        // Datagrams outside a tracked flow are not counted, so not emitted either.
        let Some(flow) = ctx.flow.map(|f| f.id) else {
            return;
        };
        let emitted = self.snmp.entry(flow).or_insert(0);
        if *emitted >= MAX_PER_FLOW {
            return;
        }
        if let Some(c) = snmp::parse(pkt.payload) {
            *emitted += 1;
            out.emit(Record::Credential(snmp::credential(
                c,
                Some(flow),
                client,
                server,
                ctx.ts_ns,
            )));
        }
    }

    fn on_stream(
        &mut self,
        ctx: &StreamCtx,
        dir: Direction,
        data: &[u8],
        out: &mut dyn RecordSink,
    ) {
        let entry = self
            .flows
            .entry(ctx.id)
            .or_insert_with(|| parser_for(ctx.id, &ctx.key));
        let Some(flow) = entry.as_mut() else {
            return;
        };
        let to_server = (dir == Direction::ToServer) != flow.swapped;
        let gap = ctx.gap_before > 0;
        match &mut flow.parser {
            Parser::Lines {
                flow,
                client,
                server,
            } => {
                let buf = if to_server { client } else { server };
                if gap {
                    buf.reset();
                }
                for line in buf.push(data) {
                    if to_server {
                        flow.client_line(&line, ctx.ts_ns, out);
                    } else {
                        flow.server_line(&line, out);
                    }
                }
            }
            Parser::Ldap(flow) => {
                if to_server {
                    flow.client_data(data, gap, ctx.ts_ns, out);
                } else {
                    flow.server_data(data, gap, out);
                }
            }
        }
    }

    fn on_flow_end(&mut self, ctx: &FlowCtx, out: &mut dyn RecordSink) {
        self.snmp.remove(&ctx.id);
        if let Some(Some(flow)) = self.flows.remove(&ctx.id) {
            end(flow, out);
        }
    }

    fn finish(&mut self, out: &mut dyn RecordSink) {
        self.snmp.clear();
        let mut left: Vec<(FlowId, Option<TcpFlow>)> = self.flows.drain().collect();
        left.sort_unstable_by_key(|(id, _)| *id);
        for flow in left.into_iter().filter_map(|(_, f)| f) {
            end(flow, out);
        }
    }
}

fn end(flow: TcpFlow, out: &mut dyn RecordSink) {
    match flow.parser {
        Parser::Lines { mut flow, .. } => flow.end(out),
        Parser::Ldap(mut flow) => flow.end(out),
    }
}

#[cfg(test)]
mod tests;
