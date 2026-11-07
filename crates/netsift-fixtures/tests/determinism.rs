//! Byte-for-byte determinism: SHA-256 of generated files, pinned by an insta snapshot.

use std::fmt::Write as _;

use netsift_fixtures::anomaly::{dns_across_chunks, http_request_across_chunks, mixed_encodings};
use netsift_fixtures::proto::png::png_image;
use netsift_fixtures::proto::x509::{CertSpec, self_signed_certificate};
use netsift_fixtures::scenarios::{self, Kind};
use netsift_fixtures::split::{Naming, SplitBy, SplitOptions, split};
use netsift_fixtures::writer::{Encoding, encode};
use sha2::{Digest, Sha256};

fn sha256(data: &[u8]) -> String {
    Sha256::digest(data).iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn fingerprint() -> String {
    let mut out = String::new();
    let demo = scenarios::demo().into_packets();
    for (label, enc) in [
        ("demo.pcap", Encoding::pcap()),
        ("demo.ns.pcap", Encoding::pcap_ns()),
        ("demo.pcapng", Encoding::pcapng()),
        ("demo.pcapng.gz", Encoding::pcapng().gz()),
    ] {
        let bytes = encode(&demo, &enc).unwrap();
        writeln!(
            out,
            "{label}: {} packets, {} bytes, {}",
            demo.len(),
            bytes.len(),
            sha256(&bytes)
        )
        .unwrap();
    }
    for kind in Kind::ALL {
        let packets = scenarios::generate(kind, 3, 7);
        let bytes = encode(&packets, &Encoding::pcap_ns()).unwrap();
        writeln!(
            out,
            "{}x3: {} packets, {}",
            kind.name(),
            packets.len(),
            sha256(&bytes)
        )
        .unwrap();
    }
    let opts =
        SplitOptions::new(SplitBy::Size(16_384), Naming::Dumpcap).with_encodings(mixed_encodings());
    for chunk in split(&scenarios::generate(Kind::Demo, 4, 1), &opts) {
        let bytes = chunk.encode().unwrap();
        writeln!(out, "{}: {}", chunk.file_name, sha256(&bytes)).unwrap();
    }
    for (label, case) in [
        ("dns-across", dns_across_chunks()),
        ("http-across", http_request_across_chunks()),
    ] {
        let bytes = encode(&case.packets, &Encoding::pcap()).unwrap();
        writeln!(out, "{label}: cut {}, {}", case.cut, sha256(&bytes)).unwrap();
    }
    writeln!(out, "png 128x96: {}", sha256(&png_image(128, 96))).unwrap();
    let cert = self_signed_certificate(&CertSpec::new("www.example.test"));
    writeln!(out, "cert: {} bytes, {}", cert.len(), sha256(&cert)).unwrap();
    out
}

#[test]
fn two_generations_are_identical() {
    assert_eq!(fingerprint(), fingerprint());
}

#[test]
fn generated_bytes_are_pinned() {
    insta::assert_snapshot!(fingerprint());
}
