//! Tests of the `smb` analyzer. Scenario-level tests run packets through the real flow layer;
//! framing and pairing tests drive `on_stream` directly to control segmentation, gaps and
//! session ids.

use std::net::{IpAddr, Ipv4Addr};

use netsift_dissect::Decoded;
use netsift_fixtures::Packet;
use netsift_fixtures::proto::netbios::{AnnouncementKind as FxKind, HostAnnouncement};
use netsift_fixtures::proto::smb;
use netsift_fixtures::scenario::SmbNtlm;
use netsift_fixtures::scenarios::hosts;
use netsift_flow::{
    Direction, Endpoint, FlowConfig, FlowCtx, FlowId, FlowKey, FlowSink, FlowTable, PacketCtx,
    StreamCtx,
};

use super::SmbAnalyzer;
use crate::analyzer::Analyzer;
use crate::record::{Credential, Record, SecretState, SmbRecord};
use crate::registry::AnalyzerConfig;

// ---- scenario-level harness (real flow layer) --------------------------------------------------

struct Harness<'a> {
    analyzer: &'a mut SmbAnalyzer,
    out: Vec<Record>,
}

impl FlowSink for Harness<'_> {
    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>) {
        self.analyzer.on_packet(ctx, pkt, &mut self.out);
    }
    fn on_stream(&mut self, ctx: &StreamCtx, dir: Direction, data: &[u8]) {
        self.analyzer.on_stream(ctx, dir, data, &mut self.out);
    }
    fn on_flow_end(&mut self, ctx: &FlowCtx) {
        self.analyzer.on_flow_end(ctx, &mut self.out);
    }
}

fn run(packets: &[Packet]) -> Vec<Record> {
    let mut analyzer = SmbAnalyzer::new(&AnalyzerConfig::default());
    let mut table = FlowTable::new(FlowConfig::default());
    let mut sink = Harness {
        analyzer: &mut analyzer,
        out: Vec::new(),
    };
    for (i, p) in packets.iter().enumerate() {
        let wire = u32::try_from(p.data.len()).unwrap_or(u32::MAX);
        table.process(p.ts_ns, 0, i as u64, p.linktype, wire, &p.data, &mut sink);
    }
    table.finish(&mut sink);
    sink.analyzer.finish(&mut sink.out);
    sink.out
}

fn credential(records: &[Record]) -> Option<&Credential> {
    records.iter().find_map(|r| match r {
        Record::Credential(c) => Some(c),
        _ => None,
    })
}

fn credentials(records: &[Record]) -> Vec<&Credential> {
    records
        .iter()
        .filter_map(|r| match r {
            Record::Credential(c) => Some(c),
            _ => None,
        })
        .collect()
}

// ---- direct framing harness --------------------------------------------------------------------

fn smb_key() -> FlowKey {
    FlowKey {
        proto: 6,
        client: Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            port: 50_000,
        },
        server: Endpoint {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: 445,
        },
    }
}

/// Feeds `data` to one direction of an SMB flow and collects the emitted records.
struct Direct {
    analyzer: SmbAnalyzer,
    key: FlowKey,
    id: FlowId,
    out: Vec<Record>,
}

impl Direct {
    fn new() -> Self {
        let key = smb_key();
        Self {
            analyzer: SmbAnalyzer::new(&AnalyzerConfig::default()),
            key,
            id: FlowId::derive(&key, 1),
            out: Vec::new(),
        }
    }

    fn feed(&mut self, dir: Direction, gap: u64, data: &[u8]) {
        let ctx = StreamCtx {
            ts_ns: 1,
            chunk_id: 0,
            frame: 0,
            id: self.id,
            key: self.key,
            gap_before: gap,
        };
        self.analyzer.on_stream(&ctx, dir, data, &mut self.out);
    }

    fn finish(mut self) -> Vec<Record> {
        let ctx = FlowCtx {
            id: self.id,
            key: self.key,
            first_ts_ns: 1,
            last_ts_ns: 2,
            to_server: netsift_flow::DirStats::default(),
            to_client: netsift_flow::DirStats::default(),
            tcp_state: None,
            end: netsift_flow::EndReason::EndOfCapture,
        };
        self.analyzer.on_flow_end(&ctx, &mut self.out);
        self.out
    }
}

/// The four SMB2 messages of an NTLM session, each NBSS-framed, as `(to_server, to_client)` bytes.
fn ntlm_pdus(session_id: u64, auth: &SmbNtlm) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    const MORE: u32 = 0xC000_0016;
    let neg_req = smb::nbss(&smb::smb2_negotiate_request());
    let neg_resp = smb::nbss(&smb::smb2_negotiate_response(
        auth.dialect,
        auth.security_mode,
        auth.server_guid,
    ));
    let ss1 = smb::nbss(&with_session(
        smb::smb2_session_setup_request(&smb::ntlmssp_negotiate()),
        session_id,
    ));
    let chal = smb::nbss(&with_session(
        smb::smb2_session_setup_response(
            MORE,
            &smb::ntlmssp_challenge(auth.server_challenge, &auth.domain),
        ),
        session_id,
    ));
    let ss2 = smb::nbss(&with_session(
        smb::smb2_session_setup_request(&smb::ntlmssp_authenticate(
            &auth.domain,
            &auth.user,
            &auth.workstation,
            &auth.lm_response,
            &auth.nt_response,
        )),
        session_id,
    ));
    let ok = smb::nbss(&with_session(
        smb::smb2_session_setup_response(0, &[]),
        session_id,
    ));
    (vec![neg_req, ss1, ss2], vec![neg_resp, chal, ok])
}

/// Sets the SMB2 header `SessionId` (offset 40) of a message.
fn with_session(mut msg: Vec<u8>, session_id: u64) -> Vec<u8> {
    if let Some(slot) = msg.get_mut(40..48) {
        slot.copy_from_slice(&session_id.to_le_bytes());
    }
    msg
}

// ---- tests -------------------------------------------------------------------------------------

#[test]
fn host_announcement_becomes_a_record() {
    let mut sc = netsift_fixtures::Scenario::new();
    let ann = HostAnnouncement::default();
    sc.smb_host_announcement(hosts::file_server(), hosts::broadcast(), &ann);
    let records = run(sc.packets());
    let a = records
        .iter()
        .find_map(|r| match r {
            Record::Smb(SmbRecord::Announce(a)) => Some(a),
            _ => None,
        })
        .expect("announce");
    assert_eq!(a.server_name, "FILESRV01");
    assert_eq!(a.dst_name, "WORKGROUP<1D>");
    assert_eq!(a.os_label, "Windows 10 / Server 2016+");
    assert_eq!(a.comment, "Synthetic file server");
    assert_eq!(a.server_type, ann.server_type);
}

#[test]
fn local_master_announcement() {
    let mut sc = netsift_fixtures::Scenario::new();
    let ann = HostAnnouncement {
        kind: FxKind::LocalMaster,
        server_name: "DC01".to_owned(),
        ..HostAnnouncement::default()
    };
    sc.smb_host_announcement(hosts::file_server(), hosts::broadcast(), &ann);
    let records = run(sc.packets());
    assert!(records.iter().any(|r| matches!(
        r,
        Record::Smb(SmbRecord::Announce(a))
            if a.server_name == "DC01" && a.kind == crate::record::AnnouncementKind::LocalMaster
    )));
}

#[test]
fn ntlmv2_session_yields_credential_and_session() {
    let mut sc = netsift_fixtures::Scenario::new();
    sc.smb_ntlm(
        hosts::workstation(),
        hosts::file_server(),
        &SmbNtlm::v2("alice", "CORP"),
    );
    let records = run(sc.packets());

    let session = records.iter().find_map(|r| match r {
        Record::Smb(SmbRecord::Session(s)) => Some(s),
        _ => None,
    });
    let s = session.expect("session");
    assert_eq!(s.dialect.as_deref(), Some("SMB 3.1.1"));
    assert_eq!(s.account.as_deref(), Some("alice"));
    assert_eq!(s.ntlm_phase, Some(crate::record::NtlmPhase::Authenticate));

    let c = credential(&records).expect("credential");
    assert_eq!(c.source_protocol, "smb");
    assert_eq!(c.kind, "ntlmv2");
    assert_eq!(c.hashcat_mode, Some(5600));
    assert_eq!(c.secret_state, SecretState::Recoverable);
    assert_eq!(
        c.hashcat_line.as_deref(),
        Some(
            format!(
                "alice::CORP:1122334455667788:{}:{}",
                "ab".repeat(16),
                "cd".repeat(44)
            )
            .as_str()
        )
    );
}

#[test]
fn ntlmv1_session_yields_hashcat_5500() {
    let mut sc = netsift_fixtures::Scenario::new();
    sc.smb_ntlm(
        hosts::workstation(),
        hosts::file_server(),
        &SmbNtlm::v1("alice", "CORP"),
    );
    let c = credential(&run(sc.packets())).cloned().expect("credential");
    assert_eq!(c.hashcat_mode, Some(5500));
    assert_eq!(
        c.hashcat_line.as_deref(),
        Some(
            format!(
                "alice::CORP:{}:{}:1122334455667788",
                "aa".repeat(24),
                "bb".repeat(24)
            )
            .as_str()
        )
    );
}

#[test]
fn non_smb_traffic_is_ignored() {
    let mut sc = netsift_fixtures::Scenario::new();
    sc.http_get(
        hosts::workstation(),
        hosts::web_server(),
        &netsift_fixtures::scenario::HttpGet::default(),
    );
    assert_eq!(run(sc.packets()), Vec::<Record>::new());
}

#[test]
fn framing_is_independent_of_segmentation() {
    let auth = SmbNtlm::v2("alice", "CORP");
    let (to_server, to_client) = ntlm_pdus(0x11, &auth);

    // All at once per direction. The challenge (server -> client) precedes the authenticate.
    let mut whole = Direct::new();
    whole.feed(Direction::ToClient, 0, &to_client.concat());
    whole.feed(Direction::ToServer, 0, &to_server.concat());
    let whole = whole.finish();

    // One byte at a time, same direction order.
    let mut drip = Direct::new();
    for pdu in &to_client {
        for b in pdu {
            drip.feed(Direction::ToClient, 0, &[*b]);
        }
    }
    for pdu in &to_server {
        for b in pdu {
            drip.feed(Direction::ToServer, 0, &[*b]);
        }
    }
    let drip = drip.finish();

    let line = |rs: &[Record]| credential(rs).and_then(|c| c.hashcat_line.clone());
    assert_eq!(line(&whole), line(&drip));
    assert!(line(&whole).is_some());
}

#[test]
fn several_pdus_in_one_segment() {
    let auth = SmbNtlm::v2("bob", "CORP");
    let (to_server, to_client) = ntlm_pdus(0x22, &auth);
    let mut d = Direct::new();
    // Every PDU of a direction concatenated into a single write.
    d.feed(Direction::ToClient, 0, &to_client.concat());
    d.feed(Direction::ToServer, 0, &to_server.concat());
    let records = d.finish();
    assert_eq!(credentials(&records).len(), 1);
}

#[test]
fn keepalive_and_oversized_pdu_do_not_break_framing() {
    let auth = SmbNtlm::v2("carol", "CORP");
    let (to_server, to_client) = ntlm_pdus(0x33, &auth);
    let mut d = Direct::new();
    // Server side first (negotiate, challenge, ok).
    d.feed(Direction::ToClient, 0, &to_client.concat());
    // Client side: a keep-alive (type 0x85, len 0), then an oversized READ PDU, then the real
    // session-setup PDUs.
    let keepalive = [0x85u8, 0, 0, 0];
    let mut oversized = vec![0x00u8, 0x01, 0x10, 0x00]; // ~69 KiB declared
    oversized.extend(std::iter::repeat_n(0u8, 0x01_1000));
    d.feed(Direction::ToServer, 0, &keepalive);
    d.feed(Direction::ToServer, 0, &oversized);
    for pdu in &to_server {
        d.feed(Direction::ToServer, 0, pdu);
    }
    let records = d.finish();
    assert_eq!(
        credentials(&records).len(),
        1,
        "session setup must still be parsed"
    );
}

#[test]
fn two_authentications_on_one_flow() {
    // First exchange fails (no credential expected to differ), second succeeds; distinct session
    // ids, so each AUTHENTICATE pairs with its own challenge.
    let a1 = SmbNtlm::v1("alice", "CORP");
    let a2 = SmbNtlm::v2("bob", "CORP");
    let (s1_srv, s1_cli) = ntlm_pdus(0x100, &a1);
    let (s2_srv, s2_cli) = ntlm_pdus(0x200, &a2);
    let mut d = Direct::new();
    // Interleave: both negotiate/challenge on the wire before the authenticates.
    d.feed(Direction::ToClient, 0, &s1_cli.concat());
    d.feed(Direction::ToClient, 0, &s2_cli.concat());
    d.feed(Direction::ToServer, 0, &s1_srv.concat());
    d.feed(Direction::ToServer, 0, &s2_srv.concat());
    let records = d.finish();
    let creds = credentials(&records);
    assert_eq!(creds.len(), 2);
    let users: Vec<_> = creds.iter().filter_map(|c| c.username.clone()).collect();
    assert!(users.contains(&"alice".to_owned()));
    assert!(users.contains(&"bob".to_owned()));
}

#[test]
fn authenticate_without_challenge_resync_after_gap() {
    let auth = SmbNtlm::v2("dora", "CORP");
    let (to_server, _to_client) = ntlm_pdus(0x44, &auth);
    let mut d = Direct::new();
    // Only the client side, with a gap before the authenticate (challenge never seen): the
    // credential is metadata-only (no crackable line) but SMB still records the attempt.
    d.feed(Direction::ToServer, 1, &to_server.concat());
    let records = d.finish();
    let c = credential(&records).expect("metadata credential");
    assert_eq!(c.secret_state, SecretState::MetadataOnly);
    assert_eq!(c.hashcat_line, None);
}

#[test]
fn anonymous_logon_emits_no_credential() {
    let mut auth = SmbNtlm::v2("", "");
    auth.user = String::new();
    auth.nt_response = Vec::new();
    auth.lm_response = vec![0];
    let (to_server, to_client) = ntlm_pdus(0x55, &auth);
    let mut d = Direct::new();
    d.feed(Direction::ToClient, 0, &to_client.concat());
    d.feed(Direction::ToServer, 0, &to_server.concat());
    let records = d.finish();
    assert_eq!(credentials(&records).len(), 0);
    // The session is still recorded (reached the authenticate phase).
    assert!(
        records
            .iter()
            .any(|r| matches!(r, Record::Smb(SmbRecord::Session(_))))
    );
}

#[test]
fn ntlmssp_bytes_in_a_write_do_not_fabricate_a_credential() {
    let auth = smb::ntlmssp_authenticate("CORP", "eve", "WS", &[0; 24], &[1; 24]);
    let mut pdu = vec![0u8; 64];
    pdu[0..4].copy_from_slice(b"\xfeSMB");
    pdu[12..14].copy_from_slice(&0x0009u16.to_le_bytes()); // WRITE
    pdu.extend_from_slice(&auth);
    let mut d = Direct::new();
    d.feed(Direction::ToServer, 0, &smb::nbss(&pdu));
    let records = d.finish();
    assert_eq!(credentials(&records).len(), 0);
}
