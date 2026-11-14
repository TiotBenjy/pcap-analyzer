-- Credentials (Credentials tab, ADR-019). Range 0600-0699 is reserved for creds (see schema.rs).
-- Conventions: *_ts columns are i64 nanoseconds since the Unix epoch (UTC); IP addresses are
-- canonical text.
--
-- Every emitter (smb, http, credentials analyzers) produces the same shape. Identical credentials
-- are folded into one row by `fingerprint` (SHA-256 of protocol, kind, client IP, server IP and
-- port, identity, secret and hashcat line, computed by the engine): an SNMP poller or a Basic
-- header repeated on every request gives one row with a count, not thousands. Commutative upsert:
-- seen_count adds up, first/last ts take min/max, and the flow, ports and details of the earliest
-- observation win (ties broken on flow id), so the result does not depend on shard order.
--
-- `fingerprint` derives from the secret without a key: it never leaves the database (a dictionary
-- would find a weak secret from it). Entries are named outside by `id`, random (16 bytes), set by
-- the first insert and never updated.
--
-- `secret` and `hashcat_line` are sensitive: never logged, served only by the detail and export
-- routes of the API, masked by default in the UI.
CREATE TABLE credentials (
    fingerprint   TEXT PRIMARY KEY,                -- lower-case hex SHA-256 (folding key, internal)
    id            TEXT NOT NULL DEFAULT (lower(hex(randomblob(16)))), -- public entry id
    protocol      TEXT NOT NULL,                   -- smb / http / ftp / smtp / pop3 / imap / ldap / snmp
    kind          TEXT NOT NULL,                   -- ntlmv1 / ntlmv2 / ntlm / http-basic / http-form / ftp / mail / ldap / snmp
    secret_state  TEXT NOT NULL,                   -- plaintext / recoverable / metadata-only
    flow_id       INTEGER,                         -- flows.id of the earliest observation
    client_ip     TEXT,
    client_port   INTEGER,
    server_ip     TEXT,
    server_port   INTEGER,
    username      TEXT,
    domain        TEXT,
    workstation   TEXT,
    secret        TEXT,                            -- plain-text secret (sensitive)
    hashcat_mode  INTEGER,                         -- 5500 / 5600 / 16400...
    hashcat_line  TEXT,                            -- offline-recovery line (sensitive)
    details       TEXT NOT NULL DEFAULT '[]',      -- JSON array of [key, value] pairs (non-secret)
    seen_count    INTEGER NOT NULL DEFAULT 1,
    first_ts      INTEGER NOT NULL,
    last_ts       INTEGER NOT NULL
) WITHOUT ROWID;
CREATE UNIQUE INDEX credentials_id ON credentials (id);
-- Keyset order of the list (first seen, then id) and its filters.
CREATE INDEX credentials_first_ts ON credentials (first_ts, id);
CREATE INDEX credentials_protocol ON credentials (protocol, first_ts);
CREATE INDEX credentials_state ON credentials (secret_state, first_ts);
CREATE INDEX credentials_hashcat ON credentials (hashcat_mode) WHERE hashcat_mode IS NOT NULL;
