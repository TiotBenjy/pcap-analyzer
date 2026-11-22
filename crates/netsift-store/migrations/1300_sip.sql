-- SIP analyzer (RFC 3261 over UDP and TCP 5060). Range 1300-1399 is reserved for sip (see schema.rs).
-- Conventions: ts columns are i64 nanoseconds since the Unix epoch (UTC); IP addresses are
-- canonical text. Text values are bounded and free of control characters (parser).

-- One row per SIP message.
CREATE TABLE sip_messages (
    id              INTEGER PRIMARY KEY,
    ts              INTEGER NOT NULL,
    src_ip          TEXT NOT NULL,
    src_port        INTEGER NOT NULL,
    dst_ip          TEXT NOT NULL,
    dst_port        INTEGER NOT NULL,
    transport       TEXT NOT NULL,                -- udp / tcp
    flow_id         INTEGER,
    kind            TEXT NOT NULL,                -- request / response
    method          TEXT,                         -- request method, else CSeq method of a response
    status          INTEGER,                      -- response status code
    reason          TEXT,                         -- response reason phrase
    request_uri     TEXT,
    call_id         TEXT,
    from_name       TEXT,
    from_uri        TEXT,
    from_tag        TEXT,
    to_name         TEXT,
    to_uri          TEXT,
    to_tag          TEXT,
    cseq            INTEGER,
    user_agent      TEXT,
    server          TEXT,
    software        TEXT,                         -- User-Agent, else Server
    scanner         TEXT,                         -- scanning tool named by the user agent
    contact         TEXT,
    via             TEXT,                         -- first Via without its parameters
    expires         INTEGER,
    content_type    TEXT,
    auth_user       TEXT,                         -- Digest username (Authorization / Proxy-Authorization)
    auth_realm      TEXT,
    challenge_realm TEXT,                         -- realm of WWW-Authenticate / Proxy-Authenticate
    media           TEXT,                         -- JSON array of SDP media: [media, ip, port, proto, codecs, direction]
    size            INTEGER NOT NULL,
    raw             TEXT NOT NULL,                -- first 4096 bytes as sanitized text
    raw_truncated   INTEGER NOT NULL DEFAULT 0
);
-- List order (keyset (ts, id)) and point range.
CREATE INDEX sip_messages_ts ON sip_messages (ts);
-- Dialog step (grouping by Call-ID) and the Call-ID filter.
CREATE INDEX sip_messages_call ON sip_messages (call_id, ts);
-- Counters and filters by kind and method, by status (covering, ending with ts).
CREATE INDEX sip_messages_method ON sip_messages (kind, method, ts);
CREATE INDEX sip_messages_status ON sip_messages (status, reason, ts);
-- User agents and scanners (covering, ending with ts).
CREATE INDEX sip_messages_software ON sip_messages (software, scanner, ts);
CREATE INDEX sip_messages_scanner ON sip_messages (scanner, src_ip, dst_ip, method, ts);
CREATE INDEX sip_messages_src ON sip_messages (src_ip, ts);

-- Dialogs: one row per Call-ID, built by the end-of-import step `sip` from sip_messages.
CREATE TABLE sip_dialogs (
    id            INTEGER PRIMARY KEY,
    call_id       TEXT NOT NULL UNIQUE,
    method        TEXT NOT NULL,                  -- INVITE when the dialog has one, else the first request method
    first_ts      INTEGER NOT NULL,
    last_ts       INTEGER NOT NULL,
    client_ip     TEXT NOT NULL,                  -- sender of the first request (else of the first message)
    client_port   INTEGER NOT NULL,
    server_ip     TEXT NOT NULL,
    server_port   INTEGER NOT NULL,
    transport     TEXT NOT NULL,
    from_name     TEXT,
    from_uri      TEXT,
    to_name       TEXT,
    to_uri        TEXT,
    contact       TEXT,
    user_agent    TEXT,                           -- first software on the client side
    server_agent  TEXT,                           -- first software on the server side
    requests      INTEGER NOT NULL,
    responses     INTEGER NOT NULL,
    invite_ts     INTEGER,
    ringing_ts    INTEGER,                        -- first 180 / 183
    answer_ts     INTEGER,                        -- first 2xx to an INVITE
    bye_ts        INTEGER,
    cancelled     INTEGER NOT NULL DEFAULT 0,     -- a CANCEL was seen
    final_status  INTEGER,
    final_reason  TEXT,
    state         TEXT NOT NULL,                  -- completed / answered / cancelled / rejected / no-answer / ok
    duration_ns   INTEGER,
    auth_user     TEXT,
    challenged    INTEGER NOT NULL DEFAULT 0,     -- a 401 / 407 was seen
    scanner       TEXT,
    media_count   INTEGER NOT NULL DEFAULT 0
);
-- List order (keyset (first_ts, id)) and overlap with a range; the list of one type.
CREATE INDEX sip_dialogs_span ON sip_dialogs (first_ts, last_ts);
CREATE INDEX sip_dialogs_method ON sip_dialogs (method, first_ts);

-- Media announced in the SDP bodies of a dialog, joined to the UDP flows of their address and port.
CREATE TABLE sip_media (
    id            INTEGER PRIMARY KEY,
    dialog_id     INTEGER NOT NULL,
    media         TEXT NOT NULL,
    ip            TEXT NOT NULL,
    port          INTEGER NOT NULL,
    proto         TEXT NOT NULL,
    codecs        TEXT NOT NULL,                  -- comma separated
    direction     TEXT,
    offered_by    TEXT NOT NULL,                  -- address of the sender of the first SDP announcing it
    offer_ts      INTEGER NOT NULL,
    flow_count    INTEGER NOT NULL DEFAULT 0,
    packets       INTEGER NOT NULL DEFAULT 0,
    bytes         INTEGER NOT NULL DEFAULT 0,
    first_flow_id INTEGER,
    UNIQUE (dialog_id, media, ip, port)
);
