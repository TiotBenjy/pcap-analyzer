//! Translation of the `sip` analyzer's records into `sip_messages` rows (dialogs and media are
//! built by the store's end-of-import step `sip`).

use netsift_analyze::dissect::sip::StartLine;
use netsift_analyze::sip::SipRecord;
use netsift_store::sip::{SipMediaDesc, SipRow};

pub(super) fn sip_row(r: SipRecord) -> SipRow {
    let m = r.message;
    let method = m.method().map(str::to_owned);
    let (kind, status, reason, request_uri) = match m.start {
        StartLine::Request { uri, .. } => ("request", None, None, Some(uri)),
        StartLine::Response { status, reason } => (
            "response",
            Some(status),
            Some(reason).filter(|r| !r.is_empty()),
            None,
        ),
    };
    let media = m
        .sdp
        .as_ref()
        .map(|sdp| {
            sdp.media
                .iter()
                .map(|x| SipMediaDesc {
                    media: x.media.clone(),
                    ip: sdp.address(x),
                    port: x.port,
                    proto: x.proto.clone(),
                    codecs: x.codecs.clone(),
                    direction: x.direction.map(|d| d.as_str().to_owned()),
                })
                .collect()
        })
        .unwrap_or_default();
    let (auth_user, auth_realm) = m.auth.map_or((None, None), |a| (a.username, a.realm));
    SipRow {
        ts: r.ts,
        src_ip: r.src.ip,
        src_port: r.src.port,
        dst_ip: r.dst.ip,
        dst_port: r.dst.port,
        transport: r.transport.as_str().to_owned(),
        // Flow ids are non-negative by construction (`FlowId::from_first_frame`).
        flow_id: r.flow_id.map(|f| f.0),
        kind: kind.to_owned(),
        method,
        status,
        reason,
        request_uri,
        call_id: m.call_id,
        from_name: m.from.name,
        from_uri: m.from.uri,
        from_tag: m.from.tag,
        to_name: m.to.name,
        to_uri: m.to.uri,
        to_tag: m.to.tag,
        cseq: m.cseq,
        user_agent: m.user_agent,
        server: m.server,
        scanner: r.scanner.map(str::to_owned),
        contact: m.contact,
        via: m.via,
        expires: m.expires,
        content_type: m.content_type,
        auth_user,
        auth_realm,
        challenge_realm: m.challenge_realm,
        media,
        size: u64::try_from(m.size).unwrap_or(u64::MAX),
        raw: m.raw,
        raw_truncated: m.raw_truncated,
    }
}
