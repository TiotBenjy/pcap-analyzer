//! Translation of the `telnet` analyzer's sessions into `telnet_sessions` rows (the store moves
//! the secrets out of the transcript).

use netsift_analyze::telnet::{Speaker, TelnetSession};
use netsift_store::telnet::{Speaker as RowSpeaker, TelnetRow, TelnetRun};

pub(super) fn telnet_row(s: TelnetSession) -> TelnetRow {
    TelnetRow {
        // Flow ids are non-negative by construction (`FlowId::from_first_frame`).
        flow_id: s.flow_id.0,
        first_ts: s.first_ts,
        last_ts: s.last_ts,
        client_ip: s.client.ip,
        client_port: s.client.port,
        server_ip: s.server.ip,
        server_port: s.server.port,
        client_bytes: s.client_bytes,
        server_bytes: s.server_bytes,
        username: s.username,
        env_user: s.env_user,
        login: s.login.map(|l| l.as_str().to_owned()),
        login_attempts: s.login_attempts,
        terminal: s.terminal,
        window: s.window,
        options: s.options,
        transcript: s
            .transcript
            .into_iter()
            .map(|r| TelnetRun {
                speaker: match r.speaker {
                    Speaker::Client => RowSpeaker::Client,
                    Speaker::Server => RowSpeaker::Server,
                    Speaker::Secret => RowSpeaker::Secret,
                },
                text: r.text,
            })
            .collect(),
        transcript_bytes: s.transcript_bytes,
        transcript_lines: s.transcript_lines,
        truncated: s.truncated,
    }
}
