//! Translation of the `tls` analyzer's sessions into `tls_*` rows.

use netsift_analyze::tls::cert::{Certificate, hex};
use netsift_analyze::tls::hello::{ClientHello, ServerHello};
use netsift_analyze::tls::{self, CertStatus, CipherInfo, Outcome, TlsSession};
use netsift_store::tls::{
    self as store, CertificateRow, CipherNameRow, ClientHelloRow, ServerHelloRow, TlsAlertRow,
    TlsSessionRow,
};

/// Explicit mapping of the issue bits (both crates define them; this keeps them independent).
fn cert_issues(bits: u32) -> u32 {
    [
        (tls::cert_issue::EXPIRED, store::cert_issue::EXPIRED),
        (
            tls::cert_issue::NOT_YET_VALID,
            store::cert_issue::NOT_YET_VALID,
        ),
        (tls::cert_issue::SELF_SIGNED, store::cert_issue::SELF_SIGNED),
        (tls::cert_issue::WEAK_KEY, store::cert_issue::WEAK_KEY),
    ]
    .into_iter()
    .filter(|(from, _)| bits & from != 0)
    .fold(0, |acc, (_, to)| acc | to)
}

fn client_hello(ch: &ClientHello) -> ClientHelloRow {
    ClientHelloRow {
        legacy_version: ch.legacy_version,
        random: hex(&ch.random),
        legacy_session_id: hex(&ch.session_id),
        session_ticket: ch.session_ticket,
        cipher_suites: ch.cipher_suites.clone(),
        compressions: ch.compressions.clone(),
        extensions: ch.extensions.clone(),
        groups: ch.groups.clone(),
        point_formats: ch.point_formats.clone(),
        signature_algs: ch.signature_algs.clone(),
        supported_versions: ch.supported_versions.clone(),
        key_share_groups: ch.key_share_groups.clone(),
    }
}

fn server_hello(sh: &ServerHello) -> ServerHelloRow {
    ServerHelloRow {
        legacy_version: sh.legacy_version,
        random: hex(&sh.random),
        legacy_session_id: hex(&sh.session_id),
        cipher_suite: sh.cipher_suite,
        compression: sh.compression,
        extensions: sh.extensions.clone(),
        selected_version: sh.selected_version,
    }
}

fn certificate(c: Certificate) -> CertificateRow {
    let mut row = CertificateRow {
        sha256: hex(&c.sha256),
        sha1: hex(&c.sha1),
        size: c.size,
        stored: c.stored,
        parsed: c.info.is_some(),
        ..CertificateRow::default()
    };
    if let Some(i) = c.info {
        row.subject = Some(i.subject);
        row.subject_cn = i.subject_cn;
        row.issuer = Some(i.issuer);
        row.issuer_cn = i.issuer_cn;
        row.serial = Some(i.serial);
        row.not_before = Some(i.not_before_ns);
        row.not_after = Some(i.not_after_ns);
        row.san = i.san;
        row.key_algorithm = Some(i.key_algorithm);
        row.key_bits = i.key_bits;
        row.signature_algorithm = Some(i.signature_algorithm);
        row.self_signed = i.self_signed;
        row.is_ca = i.is_ca;
    }
    row
}

fn cipher_name(c: &CipherInfo) -> CipherNameRow {
    CipherNameRow {
        id: c.id,
        name: c.name.to_owned(),
        weak: c.weak.map(str::to_owned),
    }
}

/// Row of one TLS session.
pub(super) fn session_row(s: TlsSession) -> TlsSessionRow {
    TlsSessionRow {
        // Flow ids are non-negative by construction (`FlowId::derive`).
        id: s.flow.0.unsigned_abs(),
        ts: s.ts_ns,
        client_ip: s.client.ip,
        client_port: s.client.port,
        server_ip: s.server.ip,
        server_port: s.server.port,
        sni: s.sni().map(str::to_owned),
        offered_version: s.offered_version(),
        version: s.version(),
        cipher_suite: s.server_hello.as_ref().map(|sh| sh.cipher_suite),
        cipher_name: s.cipher.map(|c| c.name.to_owned()),
        cipher_weak: s.cipher.and_then(|c| c.weak).map(str::to_owned),
        alpn_offered: s
            .client_hello
            .as_ref()
            .map(|ch| ch.alpn.clone())
            .unwrap_or_default(),
        alpn: s.alpn().map(str::to_owned),
        ja3: s.ja3.as_ref().map(|j| j.text.clone()),
        ja3_hash: s.ja3.as_ref().map(|j| j.hash.clone()),
        ja4: s.ja4.clone(),
        compression: s.server_hello.as_ref().map(|sh| sh.compression),
        resumed: s.resumed,
        outcome: match s.outcome {
            Outcome::Complete => store::TlsOutcome::Complete,
            Outcome::Partial => store::TlsOutcome::Partial,
        },
        alert: s.alert.map(|a| TlsAlertRow {
            level: a.level,
            description: a.description,
            from_server: a.from_server,
        }),
        cert_status: match s.cert_status {
            CertStatus::Present => store::CertStatus::Present,
            CertStatus::Encrypted => store::CertStatus::Encrypted,
            CertStatus::None => store::CertStatus::None,
        },
        cert_issues: cert_issues(s.cert_issues),
        client_hello: s.client_hello.as_ref().map(client_hello),
        server_hello: s.server_hello.as_ref().map(server_hello),
        cipher_names: s.cipher_names.iter().map(cipher_name).collect(),
        certificates: s.certificates.into_iter().map(certificate).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_bits_map_one_to_one() {
        assert_eq!(cert_issues(0), 0);
        assert_eq!(
            cert_issues(tls::cert_issue::EXPIRED),
            store::cert_issue::EXPIRED
        );
        assert_eq!(
            cert_issues(tls::cert_issue::SELF_SIGNED | tls::cert_issue::WEAK_KEY),
            store::cert_issue::SELF_SIGNED | store::cert_issue::WEAK_KEY
        );
        assert_eq!(
            cert_issues(tls::cert_issue::NOT_YET_VALID),
            store::cert_issue::NOT_YET_VALID
        );
    }
}
