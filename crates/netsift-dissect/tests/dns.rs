//! DNS / NBNS message parser: well-formed messages from the fixtures encoders, hostile and
//! truncated inputs, and a property test (never panics, always bounded).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use netsift_dissect::dns::{
    self, DnsError, Flavor, MAX_NAME_LEN, MAX_NAME_STEPS, MAX_QUESTIONS, MAX_RECORDS, RData,
    Section,
};
use netsift_fixtures::proto::dns::{DnsAnswer, DnsData, DnsType, encode_query, encode_response};
use netsift_fixtures::proto::netbios::{
    NetbiosName, SUFFIX_SERVER, nbns_name_query, nbns_name_query_response, nbns_name_registration,
};
use proptest::prelude::*;

fn header(id: u16, flags: u16, counts: [u16; 4]) -> Vec<u8> {
    let mut out = Vec::new();
    for v in [id, flags, counts[0], counts[1], counts[2], counts[3]] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out
}

#[test]
fn query_and_response_with_compression() {
    let q = dns::parse(
        &encode_query(0x1234, "www.example.test", DnsType::A),
        Flavor::Dns,
    )
    .unwrap();
    assert_eq!(q.header.id, 0x1234);
    assert!(!q.header.is_response());
    assert_eq!(q.header.opcode(), 0);
    assert_eq!(q.questions.len(), 1);
    assert_eq!(q.questions[0].name.name, "www.example.test");
    assert_eq!(q.questions[0].qtype, 1);
    assert!(!q.malformed);

    let answers = [
        DnsAnswer::new(
            "secure.example.test",
            3600,
            DnsData::Cname("edge.cdn.example.net".into()),
        ),
        DnsAnswer::new(
            "edge.cdn.example.net",
            60,
            DnsData::A(Ipv4Addr::new(198, 51, 100, 43)),
        ),
    ];
    let r = encode_response(7, "secure.example.test", DnsType::A, 0, &answers);
    let r = dns::parse(&r, Flavor::Dns).unwrap();
    assert!(r.header.is_response());
    assert_eq!(r.header.rcode(), 0);
    insta::assert_debug_snapshot!(r);
}

#[test]
fn record_types_are_decoded() {
    let answers = [
        DnsAnswer::new(
            "x.test",
            1,
            DnsData::Aaaa(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ),
        DnsAnswer::new(
            "x.test",
            2,
            DnsData::Mx {
                preference: 10,
                exchange: "mail.x.test".into(),
            },
        ),
        DnsAnswer::new("x.test", 3, DnsData::Txt("v=spf1 -all".into())),
        DnsAnswer::new(
            "x.test",
            4,
            DnsData::Srv {
                priority: 0,
                weight: 5,
                port: 443,
                target: "srv.x.test".into(),
            },
        ),
        DnsAnswer::new("x.test", 5, DnsData::Ptr("ptr.x.test".into())),
    ];
    let msg = dns::parse(
        &encode_response(1, "x.test", DnsType::Any, 0, &answers),
        Flavor::Dns,
    )
    .unwrap();
    let values: Vec<(String, String)> = msg
        .answers()
        .map(|r| {
            (
                dns::type_name(Flavor::Dns, r.rtype),
                dns::rdata_text(&r.data),
            )
        })
        .collect();
    assert_eq!(
        values,
        [
            ("AAAA", "2001:db8::1"),
            ("MX", "10 mail.x.test"),
            ("TXT", "v=spf1 -all"),
            ("SRV", "0 5 443 srv.x.test"),
            ("PTR", "ptr.x.test"),
        ]
        .map(|(a, b)| (a.to_owned(), b.to_owned()))
    );
}

#[test]
fn nxdomain_rcode_and_names() {
    let msg = dns::parse(
        &encode_response(9, "missing.example.test", DnsType::A, 3, &[]),
        Flavor::Dns,
    )
    .unwrap();
    assert_eq!(msg.header.rcode(), 3);
    assert_eq!(dns::rcode_name(Flavor::Dns, 3), "NXDOMAIN");
    assert_eq!(dns::rcode_name(Flavor::Dns, 12), "RCODE12");
    assert_eq!(dns::rcode_name(Flavor::Nbns, 7), "CFT_ERR");
    assert_eq!(dns::type_name(Flavor::Dns, 65), "HTTPS");
    assert_eq!(dns::type_name(Flavor::Dns, 4242), "TYPE4242");
    assert_eq!(dns::type_name(Flavor::Nbns, 33), "NBSTAT");
    assert_eq!(dns::opcode_name(Flavor::Nbns, 5), "REGISTRATION");
    assert_eq!(dns::opcode_name(Flavor::Dns, 5), "UPDATE");
}

#[test]
fn nbns_names_are_decoded() {
    let wpad = NetbiosName::new("WPAD", 0x00);
    let q = dns::parse(&nbns_name_query(0x10, &wpad), Flavor::Nbns).unwrap();
    assert_eq!(q.questions[0].name.name, "WPAD");
    assert_eq!(q.questions[0].name.suffix, Some(0));
    assert_eq!(dns::type_name(Flavor::Nbns, q.questions[0].qtype), "NB");

    let server = NetbiosName::new("FILESRV01", SUFFIX_SERVER);
    let addr = Ipv4Addr::new(192, 168, 1, 20);
    let r = dns::parse(
        &nbns_name_query_response(0x11, &server, 300, addr),
        Flavor::Nbns,
    )
    .unwrap();
    let answer = r.answers().next().unwrap();
    assert_eq!(answer.name.name, "FILESRV01");
    assert_eq!(answer.name.suffix, Some(0x20));
    let RData::Nb(addrs) = &answer.data else {
        panic!("not an NB record: {answer:?}");
    };
    assert_eq!(addrs[0].addr, addr);
    assert!(!addrs[0].group);

    // Registration: the additional record points back to the question name.
    let reg = dns::parse(
        &nbns_name_registration(0x12, &server, 300, addr, true),
        Flavor::Nbns,
    )
    .unwrap();
    assert_eq!(reg.header.opcode(), 5);
    let extra = reg.records.first().unwrap();
    assert_eq!(extra.section, Section::Additional);
    assert_eq!(extra.name.name, "FILESRV01");
    assert_eq!(dns::rdata_text(&extra.data), "192.168.1.20");
    assert!(matches!(&extra.data, RData::Nb(a) if a[0].group));

    // The same bytes read as plain DNS keep the encoded label.
    let plain = dns::parse(&nbns_name_query(0x10, &wpad), Flavor::Dns).unwrap();
    assert_eq!(plain.questions[0].name.suffix, None);
    assert_eq!(plain.questions[0].name.name.len(), 32);
}

#[test]
fn nbstat_names() {
    let mut msg = header(1, 0x8400, [0, 1, 0, 0]);
    msg.extend_from_slice(&NetbiosName::new("*", 0).encode());
    msg.extend_from_slice(&[0, 33, 0, 1, 0, 0, 0, 0]);
    let mut rdata = vec![2u8];
    for (name, suffix, flags) in [("HOST01", 0x00u8, 0x0400u16), ("WORKGROUP", 0x00, 0x8400)] {
        let mut raw = [b' '; 15];
        raw[..name.len()].copy_from_slice(name.as_bytes());
        rdata.extend_from_slice(&raw);
        rdata.push(suffix);
        rdata.extend_from_slice(&flags.to_be_bytes());
    }
    rdata.extend_from_slice(&[0; 46]);
    msg.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
    msg.extend_from_slice(&rdata);
    let parsed = dns::parse(&msg, Flavor::Nbns).unwrap();
    assert!(!parsed.malformed);
    let record = parsed.answers().next().unwrap();
    assert_eq!(record.name.name, "*");
    assert_eq!(dns::rdata_text(&record.data), "HOST01<00> WORKGROUP<00>");
}

#[test]
fn hostile_names_are_rejected_without_panic() {
    // Pointer to itself.
    let mut msg = header(1, 0, [1, 0, 0, 0]);
    msg.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
    let parsed = dns::parse(&msg, Flavor::Dns).unwrap();
    assert!(parsed.malformed);
    assert_eq!(parsed.questions.len(), 0);

    // Forward pointer.
    let mut msg = header(1, 0, [1, 0, 0, 0]);
    msg.extend_from_slice(&[0xc0, 20, 0, 1, 0, 1, 0, 0, 1, b'a', 0]);
    assert!(dns::parse(&msg, Flavor::Dns).unwrap().malformed);

    // Two pointers bouncing between each other (the second one points forward).
    let mut msg = header(1, 0, [2, 0, 0, 0]);
    msg.extend_from_slice(&[0xc0, 18, 0, 1, 0, 1, 0xc0, 12, 0, 1, 0, 1]);
    assert!(dns::parse(&msg, Flavor::Dns).unwrap().malformed);

    // Reserved label type.
    let mut msg = header(1, 0, [1, 0, 0, 0]);
    msg.extend_from_slice(&[0x80, 0, 0, 1, 0, 1]);
    assert!(dns::parse(&msg, Flavor::Dns).unwrap().malformed);

    // Name longer than 255 bytes.
    let mut msg = header(1, 0, [1, 0, 0, 0]);
    for _ in 0..5 {
        msg.push(63);
        msg.extend_from_slice(&[b'a'; 63]);
    }
    msg.extend_from_slice(&[0, 0, 1, 0, 1]);
    assert!(dns::parse(&msg, Flavor::Dns).unwrap().malformed);

    // Special characters are escaped.
    let mut msg = header(1, 0, [1, 0, 0, 0]);
    msg.extend_from_slice(&[3, b'a', b'.', 0x01, 2, 0xff, b'z', 0, 0, 1, 0, 1]);
    let parsed = dns::parse(&msg, Flavor::Dns).unwrap();
    assert_eq!(parsed.questions[0].name.name, "a\\.\\001.\\255z");
}

#[test]
fn truncated_messages_keep_what_was_read() {
    let full = encode_response(
        5,
        "www.example.test",
        DnsType::A,
        0,
        &[DnsAnswer::new(
            "www.example.test",
            300,
            DnsData::A(Ipv4Addr::new(203, 0, 113, 80)),
        )],
    );
    for len in 0..full.len() {
        let cut = &full[..len];
        match dns::parse(cut, Flavor::Dns) {
            Err(DnsError::TooShort(n)) => assert!(n < 12 && n == len),
            Err(e) => panic!("{len}: {e}"),
            Ok(msg) => {
                assert!(msg.malformed, "{len}");
                assert_eq!(msg.records.len(), 0);
            }
        }
    }
    assert!(!dns::parse(&full, Flavor::Dns).unwrap().malformed);
}

fn pointer(to: usize) -> [u8; 2] {
    let to = u16::try_from(to).unwrap();
    (0xc000 | to).to_be_bytes()
}

#[test]
fn pointer_chains_between_questions_stay_linear() {
    // 10 000 questions in 64 KiB, each name pointing to the name of the previous question.
    let n: u16 = 10_000;
    let mut msg = header(1, 0, [n, 0, 0, 0]);
    msg.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
    let mut previous = 12;
    for _ in 1..n {
        let here = msg.len();
        msg.extend_from_slice(&pointer(previous));
        msg.extend_from_slice(&[0, 1, 0, 1]);
        previous = here;
    }
    assert!(msg.len() <= 65_535);
    let started = Instant::now();
    let parsed = dns::parse(&msg, Flavor::Dns).unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    // Deeper than the jump cap: malformed, the first questions are kept.
    assert!(parsed.malformed);
    assert_eq!(parsed.questions.len(), MAX_QUESTIONS);
    assert_eq!(parsed.questions[3].name.name, "a");
}

#[test]
fn the_name_budget_of_a_message_is_bounded() {
    // Every question points to the same 127-label name: 128 steps each.
    let n: u16 = 10_000;
    let mut msg = header(1, 0, [n, 0, 0, 0]);
    for _ in 0..127 {
        msg.extend_from_slice(&[1, b'x']);
    }
    msg.extend_from_slice(&[0, 0, 1, 0, 1]);
    for _ in 1..n {
        msg.extend_from_slice(&pointer(12));
        msg.extend_from_slice(&[0, 1, 0, 1]);
    }
    assert!(msg.len() <= 65_535);
    let started = Instant::now();
    let parsed = dns::parse(&msg, Flavor::Dns).unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(
        parsed.malformed,
        "{MAX_NAME_STEPS} steps cannot read 10 000 long names"
    );
    assert_eq!(parsed.questions.len(), MAX_QUESTIONS);
}

#[test]
fn names_in_record_data_end_inside_it() {
    // CNAME whose RDLENGTH (2) is shorter than its name: not decoded.
    let mut msg = header(1, 0x8180, [0, 1, 0, 0]);
    msg.extend_from_slice(&[
        1, b'a', 0, 0, 5, 0, 1, 0, 0, 0, 1, 0, 2, 3, b'b', b'c', b'd', 0,
    ]);
    let parsed = dns::parse(&msg, Flavor::Dns).unwrap();
    assert!(matches!(parsed.records[0].data, RData::Other(2)));
}

#[test]
fn implausible_counts_are_not_dns() {
    let msg = header(1, 0, [0xffff, 0xffff, 0, 0]);
    assert_eq!(dns::parse(&msg, Flavor::Dns), Err(DnsError::Implausible));
}

#[test]
fn record_and_question_counts_are_bounded() {
    let mut msg = header(1, 0x8000, [40, 200, 0, 0]);
    for _ in 0..40 {
        msg.extend_from_slice(&[1, b'q', 0, 0, 1, 0, 1]);
    }
    for _ in 0..200 {
        msg.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 10, 0, 0, 1]);
    }
    let parsed = dns::parse(&msg, Flavor::Dns).unwrap();
    assert_eq!(parsed.questions.len(), MAX_QUESTIONS);
    assert_eq!(parsed.records.len(), MAX_RECORDS);
    assert!(!parsed.malformed);
}

fn check(data: &[u8]) {
    for flavor in [Flavor::Dns, Flavor::Nbns] {
        if let Ok(msg) = dns::parse(data, flavor) {
            assert!(msg.questions.len() <= MAX_QUESTIONS);
            assert!(msg.records.len() <= MAX_RECORDS);
            for name in msg
                .questions
                .iter()
                .map(|q| &q.name)
                .chain(msg.records.iter().map(|r| &r.name))
            {
                assert!(name.name.len() <= MAX_NAME_LEN);
            }
            for r in &msg.records {
                let _ = dns::rdata_text(&r.data);
            }
            let _ = format!("{msg:?}");
        }
    }
}

fn seeds() -> Vec<Vec<u8>> {
    vec![
        encode_query(1, "a.b.c", DnsType::Srv),
        encode_response(
            2,
            "secure.example.test",
            DnsType::A,
            0,
            &[DnsAnswer::new(
                "edge.example.net",
                1,
                DnsData::Cname("x.example.net".into()),
            )],
        ),
        nbns_name_registration(
            3,
            &NetbiosName::new("HOST", 0x20),
            1,
            Ipv4Addr::LOCALHOST,
            false,
        ),
    ]
}

proptest! {
    #[test]
    fn never_panics_on_random_bytes(data in proptest::collection::vec(any::<u8>(), 0..600)) {
        check(&data);
    }

    #[test]
    fn never_panics_on_mutated_messages(
        seed in 0usize..3,
        edits in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..8),
        cut in any::<usize>(),
    ) {
        let mut data = seeds()[seed].clone();
        for (pos, byte) in edits {
            let len = data.len();
            data[pos % len] = byte;
        }
        let len = data.len();
        data.truncate(cut % (len + 1));
        check(&data);
    }
}
