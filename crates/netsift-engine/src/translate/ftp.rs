//! Translation of the `ftp` analyzer's records into `ftp_sessions`, `ftp_lines` and
//! `ftp_transfers` rows.

use netsift_analyze::ftp::{DataMode, FtpLine, FtpRecord, FtpSession, FtpTransfer};
use netsift_store::ftp::{FtpLineRow, FtpRow, FtpSessionRow, FtpTransferRow};

pub(super) fn ftp_row(r: FtpRecord) -> FtpRow {
    match r {
        FtpRecord::Line(l) => FtpRow::Line(line_row(l)),
        FtpRecord::Transfer(t) => FtpRow::Transfer(transfer_row(*t)),
        FtpRecord::Session(s) => FtpRow::Session(session_row(*s)),
    }
}

fn line_row(l: FtpLine) -> FtpLineRow {
    FtpLineRow {
        flow_id: l.flow_id.0,
        seq: l.seq,
        ts: l.ts,
        dir: l.kind.as_str(),
        head: l.head,
        text: l.text,
        secret: l.secret,
        truncated: l.truncated,
    }
}

fn transfer_row(t: FtpTransfer) -> FtpTransferRow {
    FtpTransferRow {
        flow_id: t.flow_id.0,
        seq: t.seq,
        ts: t.ts,
        end_ts: t.end_ts,
        command: t.command,
        path: t.path,
        direction: t.direction.as_str(),
        mode: t.mode.map(DataMode::as_str),
        data_flow_id: t.data_flow.map(|f| f.0),
        status: t.status,
        status_text: t.status_text,
        bytes: t.bytes,
        restart_offset: t.restart_offset,
        truncated: t.truncated,
        sha256: t.object.map(|b| b.to_hex()),
        mime: t.mime,
        listing: t.listing,
    }
}

fn session_row(s: FtpSession) -> FtpSessionRow {
    FtpSessionRow {
        flow_id: s.flow_id.0,
        client_ip: s.client.ip,
        client_port: s.client.port,
        server_ip: s.server.ip,
        server_port: s.server.port,
        first_ts: s.first_ts,
        last_ts: s.last_ts,
        banner: s.banner,
        username: s.username,
        login: s
            .login
            .map(|ok| if ok { "accepted" } else { "rejected" }.to_owned()),
        tls: s.tls,
        commands: s.commands,
        replies: s.replies,
        files: s.files,
        listings: s.listings,
        bytes: s.bytes,
        lines: s.lines,
        transcript_truncated: s.transcript_truncated,
        gaps: s.gaps,
    }
}
