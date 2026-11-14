//! Translation of `Record::Credential` (every emitting analyzer) into `credentials` rows, with
//! the fingerprint that folds identical credentials (ADR-018).

use netsift_analyze::Credential;
use netsift_store::credentials::CredentialRow;
use sha2::{Digest, Sha256};

/// SHA-256 over the identifying fields, each length-prefixed (no separator ambiguity): protocol,
/// kind, client IP, server IP and port, user, domain, secret, hashcat line. The client port, the
/// flow and the time are left out, so repeated observations fold into one row.
fn fingerprint(c: &Credential) -> String {
    let mut h = Sha256::new();
    let mut field = |bytes: &[u8]| {
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    };
    let opt = |o: &Option<String>| o.clone().unwrap_or_default();
    field(c.source_protocol.as_bytes());
    field(c.kind.as_bytes());
    field(
        c.client
            .map(|e| e.ip.to_string())
            .unwrap_or_default()
            .as_bytes(),
    );
    field(
        c.server
            .map(|e| e.ip.to_string())
            .unwrap_or_default()
            .as_bytes(),
    );
    field(&c.server.map_or(0, |e| e.port).to_le_bytes());
    field(opt(&c.username).as_bytes());
    field(opt(&c.domain).as_bytes());
    field(opt(&c.secret).as_bytes());
    field(opt(&c.hashcat_line).as_bytes());
    super::to_hex(&h.finalize())
}

pub(super) fn credential_row(c: Credential) -> CredentialRow {
    CredentialRow {
        fingerprint: fingerprint(&c),
        protocol: c.source_protocol.to_owned(),
        kind: c.kind.to_owned(),
        secret_state: c.secret_state.as_str().to_owned(),
        // Flow ids are non-negative by construction (`FlowId::derive`).
        flow_id: c.flow_id.and_then(|f| u64::try_from(f.0).ok()),
        client_ip: c.client.map(|e| e.ip),
        client_port: c.client.map(|e| e.port),
        server_ip: c.server.map(|e| e.ip),
        server_port: c.server.map(|e| e.port),
        username: c.username,
        domain: c.domain,
        workstation: c.workstation,
        secret: c.secret,
        hashcat_mode: c.hashcat_mode,
        hashcat_line: c.hashcat_line,
        details: c.details,
        ts: c.ts,
    }
}
