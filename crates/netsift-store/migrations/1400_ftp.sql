-- FTP analyzer (control sessions, transcripts, transfers; docs/specs/ftp.md, ADR-032). Range
-- 1400-1499 is reserved for ftp (see schema.rs). Conventions: ts columns are i64 nanoseconds since
-- the Unix epoch (UTC); IP addresses are canonical text. Text values are bounded and free of
-- control characters (analyzer). Every row is written once by the shard of its control flow.

-- One row per control session (flow_id = control flow).
CREATE TABLE ftp_sessions (
    flow_id              INTEGER PRIMARY KEY,
    client_ip            TEXT NOT NULL,
    client_port          INTEGER NOT NULL,
    server_ip            TEXT NOT NULL,
    server_port          INTEGER NOT NULL,
    first_ts             INTEGER NOT NULL,
    last_ts              INTEGER NOT NULL,
    banner               TEXT,                         -- text of the first 220 reply
    username             TEXT,                         -- last USER argument
    login                TEXT CHECK (login IN ('accepted', 'rejected')),
    tls                  INTEGER NOT NULL DEFAULT 0,   -- AUTH TLS accepted, rest encrypted
    commands             INTEGER NOT NULL DEFAULT 0,
    replies              INTEGER NOT NULL DEFAULT 0,
    files                INTEGER NOT NULL DEFAULT 0,   -- RETR, STOR, STOU, APPE commands
    listings             INTEGER NOT NULL DEFAULT 0,   -- LIST, NLST, MLSD commands
    bytes                INTEGER NOT NULL DEFAULT 0,   -- data bytes of the transfers
    lines                INTEGER NOT NULL DEFAULT 0,   -- transcript lines stored
    transcript_truncated INTEGER NOT NULL DEFAULT 0,
    gaps                 INTEGER NOT NULL DEFAULT 0
);
-- List order (keyset (first_ts, flow_id)) and overlap with a range.
CREATE INDEX ftp_sessions_span ON ftp_sessions (first_ts, last_ts);

-- Transcript lines, in order.
CREATE TABLE ftp_lines (
    flow_id   INTEGER NOT NULL,
    seq       INTEGER NOT NULL,
    ts        INTEGER NOT NULL,
    dir       TEXT NOT NULL CHECK (dir IN ('c', 's', 'n')),  -- command, reply, note
    head      TEXT,                                          -- verb, or code and separator
    text      TEXT NOT NULL,
    secret    INTEGER NOT NULL DEFAULT 0,                    -- PASS / ACCT argument
    truncated INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (flow_id, seq)
) WITHOUT ROWID;

-- One row per transfer command (id: tie-breaker of the keyset only).
CREATE TABLE ftp_transfers (
    id             INTEGER PRIMARY KEY,
    flow_id        INTEGER NOT NULL,              -- control flow
    seq            INTEGER NOT NULL,              -- order within the session
    ts             INTEGER NOT NULL,              -- transfer command
    end_ts         INTEGER,
    command        TEXT NOT NULL,                 -- RETR, STOR, STOU, APPE, LIST, NLST, MLSD
    path           TEXT,
    direction      TEXT NOT NULL CHECK (direction IN ('download', 'upload', 'listing')),
    mode           TEXT CHECK (mode IN ('active', 'passive')),
    data_flow_id   INTEGER,                       -- flows.id of the data connection
    status         INTEGER,                       -- final reply code
    status_text    TEXT,
    bytes          INTEGER NOT NULL DEFAULT 0,
    restart_offset INTEGER,
    truncated      INTEGER NOT NULL DEFAULT 0,
    sha256         TEXT,                          -- stored content (objects)
    mime           TEXT,
    listing        TEXT,                          -- first 4 KiB of a listing
    UNIQUE (flow_id, seq)
);
-- List order (keyset (ts, id)) and point range.
CREATE INDEX ftp_transfers_ts ON ftp_transfers (ts);
-- Direction filter of the list (keyset on ts).
CREATE INDEX ftp_transfers_direction ON ftp_transfers (direction, ts);
-- Counters over a range (covering, ending with ts).
CREATE INDEX ftp_transfers_stats ON ftp_transfers (direction, status, bytes, sha256, ts);
-- Objects carried by a transfer of a range (Pictures, Documents).
CREATE INDEX ftp_transfers_sha256 ON ftp_transfers (sha256, ts);

-- Origin of an extracted object: HTTP response body or FTP transfer.
ALTER TABLE objects ADD COLUMN source TEXT NOT NULL DEFAULT 'http';
