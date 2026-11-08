//! Scenario tests: synthetic captures (`netsift-fixtures`) through the flow table and the
//! analyzer, as the engine runs them.

use std::fmt::Write as _;
use std::io::Write as _;

use netsift_dissect::Decoded;
use netsift_fixtures::Packet;
use netsift_fixtures::scenario::{Scenario, TcpOptions};
use netsift_fixtures::scenarios::{Kind, generate, hosts};
use netsift_flow::{FlowConfig, FlowSink, FlowTable, PacketCtx};

use super::*;
use crate::analyzer::BlobRef;

/// Forwards flow events to the analyzer and keeps its records.
struct Harness {
    http: HttpAnalyzer,
    records: Vec<Record>,
    blobs: bool,
}

/// Sink that pretends to store blobs (the engine does from P3.6).
struct Sink<'a> {
    records: &'a mut Vec<Record>,
    blobs: bool,
}

impl RecordSink for Sink<'_> {
    fn emit(&mut self, record: Record) {
        self.records.push(record);
    }

    fn put_blob(&mut self, data: &[u8]) -> Option<BlobRef> {
        self.blobs.then_some(BlobRef {
            sha256: [0xab; 32],
            size: data.len() as u64,
        })
    }
}

impl FlowSink for Harness {
    fn on_packet(&mut self, _ctx: &PacketCtx, _pkt: &Decoded<'_>) {}

    fn on_stream(&mut self, ctx: &StreamCtx, dir: Direction, data: &[u8]) {
        let mut sink = Sink {
            records: &mut self.records,
            blobs: self.blobs,
        };
        self.http.on_stream(ctx, dir, data, &mut sink);
    }

    fn on_flow_end(&mut self, ctx: &FlowCtx) {
        let mut sink = Sink {
            records: &mut self.records,
            blobs: self.blobs,
        };
        self.http.on_flow_end(ctx, &mut sink);
    }
}

fn run_with(packets: &[Packet], config: HttpConfig, blobs: bool) -> Vec<HttpTransaction> {
    let analyzer_config = AnalyzerConfig {
        http: config,
        ..AnalyzerConfig::default()
    };
    let mut h = Harness {
        http: HttpAnalyzer::new(&analyzer_config),
        records: Vec::new(),
        blobs,
    };
    let mut table = FlowTable::new(FlowConfig::default());
    for (i, p) in packets.iter().enumerate() {
        let wire = u32::try_from(p.data.len()).unwrap();
        table.process(p.ts_ns, 0, i as u64, p.linktype, wire, &p.data, &mut h);
    }
    table.finish(&mut h);
    let mut sink = Sink {
        records: &mut h.records,
        blobs,
    };
    h.http.finish(&mut sink);
    let mut txs: Vec<HttpTransaction> = h
        .records
        .into_iter()
        .map(|r| match r {
            Record::Http(t) => *t,
            other => panic!("unexpected record {other:?}"),
        })
        .collect();
    txs.sort_by_key(|t| (t.ts_ns(), t.flow, t.seq));
    txs
}

fn run(packets: &[Packet]) -> Vec<HttpTransaction> {
    run_with(packets, HttpConfig::default(), false)
}

fn render(txs: &[HttpTransaction]) -> String {
    let t0 = txs.first().map_or(0, HttpTransaction::ts_ns);
    let mut s = String::new();
    for t in txs {
        writeln!(
            s,
            "tx {} {}:{} -> {}:{} host={:?} path={:?} query={:?} type={:?}",
            t.seq,
            t.client.ip,
            t.client.port,
            t.server.ip,
            t.server.port,
            t.host(),
            t.path(),
            t.query(),
            t.content_type(),
        )
        .unwrap();
        if let Some(r) = &t.request {
            writeln!(
                s,
                "  > {} {} HTTP/1.{} at +{}us",
                r.method,
                r.target,
                r.minor_version,
                (r.message.ts_ns - t0) / 1000
            )
            .unwrap();
            message(&mut s, &r.message);
        }
        if let Some(r) = &t.response {
            writeln!(
                s,
                "  < HTTP/1.{} {} {} at +{}us",
                r.minor_version,
                r.status,
                r.reason,
                (r.message.ts_ns - t0) / 1000
            )
            .unwrap();
            message(&mut s, &r.message);
        }
    }
    s
}

fn message(s: &mut String, m: &HttpMessage) {
    let names: Vec<&str> = m.headers.iter().map(|h| h.name.as_str()).collect();
    writeln!(s, "    headers={names:?} head={}", m.head_len).unwrap();
    let b = &m.body;
    writeln!(
        s,
        "    body {} wire={} decoded={} chunked={} encoding={:?} magic={:?} blob={}",
        b.state.as_str(),
        b.wire_len,
        b.decoded_len,
        b.chunked,
        b.content_encoding,
        b.mime_magic,
        b.blob.is_some(),
    )
    .unwrap();
    if let Some(p) = &b.preview {
        let short: String = p.chars().take(60).collect();
        writeln!(s, "    preview {short:?}").unwrap();
    }
}

fn request(method: &str, path: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "{method} {path} HTTP/1.1\r\nHost: www.example.test\r\nUser-Agent: NetSiftTest/1.0\r\n{extra}"
    );
    if !body.is_empty() {
        write!(r, "Content-Length: {}\r\n", body.len()).unwrap();
    }
    r.push_str("\r\n");
    let mut out = r.into_bytes();
    out.extend_from_slice(body);
    out
}

fn response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\nServer: test\r\n{headers}\r\n").into_bytes();
    out.extend_from_slice(body);
    out
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn chunked(data: &[u8], size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for piece in data.chunks(size) {
        out.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        out.extend_from_slice(piece);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

fn opts(port: u16) -> TcpOptions {
    TcpOptions::new(port)
}

#[test]
fn keep_alive_three_requests() {
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(hosts::workstation(), hosts::web_server(), &opts(80));
    s.client_send(&request(
        "GET",
        "/index.html?lang=en",
        "Accept: */*\r\n",
        b"",
    ));
    s.server_send(&response(
        "200 OK",
        "Content-Type: text/html; charset=utf-8\r\nContent-Length: 26\r\n",
        b"<html><p>Hello</p></html>\n",
    ));
    s.client_send(&request(
        "POST",
        "/api/items",
        "Content-Type: application/json\r\n",
        b"{\"name\":\"x\"}",
    ));
    s.server_send(&response("201 Created", "Content-Length: 0\r\n", b""));
    s.client_send(&request("HEAD", "/big.iso", "", b""));
    s.server_send(&response(
        "200 OK",
        "Content-Length: 123456789\r\nContent-Type: application/octet-stream\r\n",
        b"",
    ));
    s.close();
    let txs = run(sc.packets());
    assert_eq!(txs.len(), 3);
    insta::assert_snapshot!(render(&txs));
}

#[test]
fn pipelined_requests_are_paired_in_order() {
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(hosts::workstation(), hosts::web_server(), &opts(80));
    let mut reqs = request("GET", "/a", "", b"");
    reqs.extend(request("GET", "/b", "", b""));
    reqs.extend(request("DELETE", "/c", "", b""));
    s.client_send(&reqs);
    let mut resps = response("200 OK", "Content-Length: 1\r\n", b"A");
    resps.extend(response("404 Not Found", "Content-Length: 1\r\n", b"B"));
    resps.extend(response("204 No Content", "", b""));
    s.server_send(&resps);
    s.close();
    let txs = run(sc.packets());
    let pairs: Vec<(String, u16)> = txs
        .iter()
        .map(|t| (t.path().unwrap(), t.response.as_ref().unwrap().status))
        .collect();
    assert_eq!(
        pairs,
        vec![("/a".into(), 200), ("/b".into(), 404), ("/c".into(), 204)]
    );
    assert_eq!(txs.iter().map(|t| t.seq).collect::<Vec<_>>(), vec![0, 1, 2]);
}

#[test]
fn chunked_gzip_response_is_decoded() {
    let page = "<!doctype html><title>t</title>".to_owned() + &"lorem ipsum ".repeat(400);
    let body = chunked(&gzip(page.as_bytes()), 100);
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(hosts::workstation(), hosts::web_server(), &opts(8080));
    s.client_send(&request("GET", "/page", "Accept-Encoding: gzip\r\n", b""));
    s.server_send(&response(
        "200 OK",
        "Content-Type: text/html\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n",
        &body,
    ));
    s.close();
    let txs = run_with(sc.packets(), HttpConfig::default(), true);
    insta::assert_snapshot!(render(&txs));
    let b = &txs[0].response.as_ref().unwrap().message.body;
    assert_eq!(b.state, BodyState::Complete);
    assert_eq!(b.decoded_len, page.len() as u64);
    assert_eq!(b.wire_len, body.len() as u64);
    assert_eq!(b.blob.map(|r| r.size), Some(page.len() as u64));
    assert_eq!(b.preview.as_ref().unwrap().len(), 4096);
}

#[test]
fn request_without_response_and_truncated_response() {
    let mut sc = Scenario::new();
    // The server never answers.
    let mut s = sc.tcp_open(hosts::workstation(), hosts::web_server(), &opts(80));
    s.client_send(&request("GET", "/no-answer", "", b""));
    s.close();
    sc.advance(1_000_000);
    // The capture stops in the middle of a response (no close).
    let mut s = sc.tcp_open(hosts::workstation(), hosts::web_server(), &opts(80));
    s.client_send(&request("GET", "/cut", "", b""));
    s.server_send(&response(
        "200 OK",
        "Content-Length: 5000\r\n",
        &[b'x'; 2000],
    ));
    let txs = run(sc.packets());
    insta::assert_snapshot!(render(&txs));
    assert!(txs[0].response.is_none());
    assert_eq!(
        txs[1].response.as_ref().unwrap().message.body.state,
        BodyState::Incomplete
    );
}

#[test]
fn response_until_close_and_head_only_body() {
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(hosts::workstation(), hosts::web_server(), &opts(80));
    s.client_send(b"GET /old HTTP/1.0\r\n\r\n");
    s.server_send(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nuntil the end");
    s.close();
    let txs = run(sc.packets());
    let b = &txs[0].response.as_ref().unwrap().message.body;
    assert_eq!(b.state, BodyState::Complete);
    assert_eq!(b.decoded_len, 13);
    assert_eq!(b.preview.as_deref(), Some("until the end"));
}

#[test]
fn interim_and_tunnel_responses() {
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(hosts::workstation(), hosts::web_server(), &opts(80));
    s.client_send(&request(
        "PUT",
        "/upload",
        "Expect: 100-continue\r\n",
        b"data",
    ));
    s.server_send(b"HTTP/1.1 100 Continue\r\n\r\n");
    s.server_send(&response("200 OK", "Content-Length: 2\r\n", b"ok"));
    s.client_send(
        b"CONNECT secure.example.test:443 HTTP/1.1\r\nHost: secure.example.test:443\r\n\r\n",
    );
    s.server_send(b"HTTP/1.1 200 Connection established\r\n\r\n");
    s.client_send(b"\x16\x03\x01\x00\x05hello");
    s.server_send(b"\x16\x03\x03\x00\x05world");
    s.close();
    let txs = run(sc.packets());
    assert_eq!(txs.len(), 2, "{}", render(&txs));
    assert_eq!(txs[0].response.as_ref().unwrap().status, 200);
    assert_eq!(txs[1].host().as_deref(), Some("secure.example.test:443"));
    assert_eq!(txs[1].path(), None);
}

#[test]
fn response_without_request_midstream() {
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(hosts::workstation(), hosts::web_server(), &opts(80));
    s.client_send(&request("GET", "/x", "", b""));
    s.server_send(&response(
        "302 Found",
        "Location: /y\r\nContent-Length: 0\r\n",
        b"",
    ));
    s.close();
    let mut packets = sc.into_packets();
    // SYN, final handshake ACK, request and its ACK lost: the capture starts with the SYN-ACK
    // (which orients the connection), then the response.
    for i in [4, 3, 2, 0] {
        packets.remove(i);
    }
    let txs = run(&packets);
    assert_eq!(txs.len(), 1);
    assert!(txs[0].request.is_none());
    assert_eq!(txs[0].response.as_ref().unwrap().status, 302);
}

#[test]
fn gap_inside_a_body_keeps_the_next_transaction() {
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(
        hosts::workstation(),
        hosts::web_server(),
        &TcpOptions {
            mss: 500,
            ..opts(80)
        },
    );
    s.client_send(&request("GET", "/big", "", b""));
    let lost = s.server_send(&response(
        "200 OK",
        "Content-Length: 3000\r\n",
        &[b'z'; 3000],
    ));
    s.client_send(&request("GET", "/next", "", b""));
    s.server_send(&response("200 OK", "Content-Length: 2\r\n", b"ok"));
    s.close();
    let mut packets = sc.into_packets();
    packets.remove(lost.start + 2);
    let txs = run(&packets);
    assert_eq!(txs.len(), 2, "{}", render(&txs));
    let big = &txs[0].response.as_ref().unwrap().message.body;
    assert_eq!(big.state, BodyState::Incomplete);
    assert_eq!(big.wire_len, 3000);
    assert_eq!(txs[1].path().as_deref(), Some("/next"));
    assert_eq!(
        txs[1].response.as_ref().unwrap().message.body.state,
        BodyState::Complete
    );
}

#[test]
fn malformed_chunked_stops_the_direction() {
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(hosts::workstation(), hosts::web_server(), &opts(80));
    s.client_send(&request("GET", "/bad", "", b""));
    s.server_send(&response(
        "200 OK",
        "Transfer-Encoding: chunked\r\n",
        b"zz\r\nnot hex\r\n0\r\n\r\n",
    ));
    s.close();
    let txs = run(sc.packets());
    assert_eq!(txs.len(), 1);
    assert_eq!(
        txs[0].response.as_ref().unwrap().message.body.state,
        BodyState::Malformed
    );
}

#[test]
fn gzip_bomb_is_truncated_at_the_bound() {
    let bomb = gzip(&vec![0u8; 32 * 1024 * 1024]);
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(hosts::workstation(), hosts::web_server(), &opts(80));
    s.client_send(&request("GET", "/bomb", "", b""));
    s.server_send(&response(
        "200 OK",
        &format!(
            "Content-Encoding: gzip\r\nContent-Length: {}\r\n",
            bomb.len()
        ),
        &bomb,
    ));
    s.close();
    let limit = HttpConfig {
        max_body_bytes: 1024 * 1024,
        max_decompression_ratio: u64::MAX,
        ..HttpConfig::default()
    };
    let txs = run_with(sc.packets(), limit, true);
    let b = &txs[0].response.as_ref().unwrap().message.body;
    assert_eq!(b.state, BodyState::Truncated);
    assert_eq!(b.decoded_len, 1024 * 1024);
    assert!(b.blob.is_none(), "a truncated body is not an object");
    let txs = run(sc.packets());
    assert_eq!(
        txs[0].response.as_ref().unwrap().message.body.state,
        BodyState::Bomb
    );
}

#[test]
fn non_http_connections_are_ignored() {
    let packets = generate(Kind::Tls, 2, 1);
    assert_eq!(run(&packets), Vec::new());
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(hosts::workstation(), hosts::ftp_server(), &opts(21));
    s.server_send(b"220 FTP ready\r\n");
    s.client_send(b"USER anonymous\r\n");
    s.close();
    assert_eq!(run(sc.packets()), Vec::new());
}

#[test]
fn demo_scenario_has_one_image_per_round() {
    let txs = run_with(&generate(Kind::Demo, 3, 7), HttpConfig::default(), true);
    assert_eq!(txs.len(), 3);
    for t in &txs {
        let b = &t.response.as_ref().unwrap().message.body;
        assert_eq!(b.mime_magic, Some("image/png"));
        assert!(b.blob.is_some());
        assert!(b.preview.is_none());
        assert_eq!(t.content_type().as_deref(), Some("image/png"));
    }
}

#[test]
fn too_many_pending_requests_are_flushed() {
    let mut sc = Scenario::new();
    let mut s = sc.tcp_open(hosts::workstation(), hosts::web_server(), &opts(80));
    let mut reqs = Vec::new();
    for i in 0..10 {
        reqs.extend(request("GET", &format!("/{i}"), "", b""));
    }
    s.client_send(&reqs);
    s.close();
    let limit = HttpConfig {
        max_pending: 3,
        ..HttpConfig::default()
    };
    let txs = run_with(sc.packets(), limit, false);
    assert_eq!(txs.len(), 10);
    assert!(txs.iter().all(|t| t.response.is_none()));
}

#[test]
fn hostile_streams_never_panic() {
    // Random-looking garbage after a valid start, oversized heads, binary noise.
    let mut seed = 0x1234_5678_u64;
    let mut noise = vec![0u8; 20_000];
    for b in &mut noise {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *b = seed.to_le_bytes()[0];
    }
    let mut huge_head = b"GET / HTTP/1.1\r\n".to_vec();
    huge_head.extend(std::iter::repeat_n(b'a', 70_000));
    let inputs: Vec<Vec<u8>> = vec![
        [b"GET / HTTP/1.1\r\n".as_slice(), &noise].concat(),
        huge_head,
        [
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n".as_slice(),
            &noise,
        ]
        .concat(),
        [
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: br\r\n\r\n"
                .as_slice(),
            &noise,
        ]
        .concat(),
    ];
    for input in inputs {
        let mut sc = Scenario::new();
        let mut s = sc.tcp_open(hosts::workstation(), hosts::web_server(), &opts(80));
        if input.starts_with(b"HTTP") {
            s.client_send(&request("GET", "/", "", b""));
            s.server_send(&input);
        } else {
            s.client_send(&input);
        }
        s.close();
        let _ = run(sc.packets());
    }
}
