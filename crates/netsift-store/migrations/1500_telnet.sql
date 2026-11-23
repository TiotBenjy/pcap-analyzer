-- Telnet analyzer (TCP 23 / 2323). Range 1500-1599 is reserved for telnet (see schema.rs).
-- Conventions: *_ts columns are i64 nanoseconds since the Unix epoch (UTC); IP addresses are
-- canonical text. Text values are bounded and free of control characters (analyzer).

-- One row per Telnet connection that carried data, written once at the end of its flow. Narrow:
-- the transcript is in `telnet_transcripts`, so that counting and listing never read it.
CREATE TABLE telnet_sessions (
    flow_id          INTEGER PRIMARY KEY,           -- flows.id
    first_ts         INTEGER NOT NULL,
    last_ts          INTEGER NOT NULL,
    client_ip        TEXT NOT NULL,
    client_port      INTEGER NOT NULL,
    server_ip        TEXT NOT NULL,
    server_port      INTEGER NOT NULL,
    client_bytes     INTEGER NOT NULL DEFAULT 0,    -- wire bytes sent by the client
    server_bytes     INTEGER NOT NULL DEFAULT 0,    -- wire bytes sent by the server
    username         TEXT,                          -- accepted login, else last attempt, else env USER
    env_user         TEXT,                          -- USER variable of NEW-ENVIRON
    login            TEXT,                          -- accepted / rejected / NULL (no result)
    login_attempts   INTEGER NOT NULL DEFAULT 0,    -- passwords typed
    terminal         TEXT,                          -- TTYPE IS
    window_cols      INTEGER,                       -- NAWS
    window_rows      INTEGER,
    options          TEXT NOT NULL DEFAULT '[]',    -- JSON array of the active option names
    transcript_bytes INTEGER NOT NULL DEFAULT 0,
    transcript_lines INTEGER NOT NULL DEFAULT 0,
    truncated        INTEGER NOT NULL DEFAULT 0
);
-- List order (keyset (first_ts, flow_id)).
CREATE INDEX telnet_sessions_first_ts ON telnet_sessions (first_ts, flow_id);
-- Overlap with a range.
CREATE INDEX telnet_sessions_span ON telnet_sessions (first_ts, last_ts);

-- Transcript of a session (same flow_id). `transcript` is a JSON array of runs `[speaker, text]`
-- (speaker `c` client, `s` server, `p` secret); a secret run never holds its text, which is in
-- `secrets` (JSON array of strings, in the order of the `p` runs). Only what the analyzer knows as
-- a password is secret: one typed at an unrecognized prompt, typed ahead, or with the prompt
-- missing stays client text here (docs/specs/telnet.md). `secrets` is sensitive: never logged,
-- served only by the detail route of the API, masked by default in the UI.
CREATE TABLE telnet_transcripts (
    flow_id    INTEGER PRIMARY KEY,                 -- telnet_sessions.flow_id
    transcript TEXT NOT NULL DEFAULT '[]',          -- JSON runs, secrets removed
    secrets    TEXT NOT NULL DEFAULT '[]'           -- JSON array (sensitive)
);
