-- SMB / NetBIOS analyzer. Range 0500-0599 is reserved for smb (see schema.rs).
-- Conventions: *_ts columns are i64 nanoseconds since the Unix epoch (UTC); IP addresses are
-- canonical text; server_guid is lower-case hex.

-- NetBIOS browser announcements (UDP 138, \MAILSLOT\BROWSE), folded to one row per announcing
-- host, address and NetBIOS destination (hosts re-announce periodically). Commutative upsert:
-- announce_count adds up, first/last ts take min/max, and the OS/comment of the latest
-- observation win (deterministic by last_ts).
CREATE TABLE smb_announces (
    src_ip         TEXT NOT NULL,                     -- address that announced
    server_name    TEXT NOT NULL,                     -- announced computer name
    dst_name       TEXT NOT NULL,                     -- NetBIOS destination (workgroup<suffix>)
    kind           TEXT NOT NULL DEFAULT 'host',      -- host / local_master / domain
    os_major       INTEGER NOT NULL DEFAULT 0,
    os_minor       INTEGER NOT NULL DEFAULT 0,
    os_label       TEXT NOT NULL DEFAULT '',          -- readable OS version
    server_type    INTEGER NOT NULL DEFAULT 0,        -- SV_TYPE_* role bit field
    comment        TEXT NOT NULL DEFAULT '',
    announce_count INTEGER NOT NULL DEFAULT 1,
    first_ts       INTEGER NOT NULL,
    last_ts        INTEGER NOT NULL,
    PRIMARY KEY (src_ip, server_name, dst_name)
);
CREATE INDEX smb_announces_last_ts ON smb_announces (last_ts, src_ip);
-- Covering index of the OS distribution donut (kind = 'host', count DISTINCT server_name).
CREATE INDEX smb_announces_os ON smb_announces (kind, os_label, server_name);

-- SMB sessions over TCP (139/445), one per flow. Non-secret metadata only; the NTLM secret
-- material is not persisted here (the Credentials tab, task P3.7, owns it). Commutative upsert by
-- flow id (a flow is handled by a single shard, so it is written once).
CREATE TABLE smb_sessions (
    flow_id     INTEGER PRIMARY KEY,                 -- flows.id
    client_ip   TEXT NOT NULL,
    client_port INTEGER NOT NULL DEFAULT 0,
    server_ip   TEXT NOT NULL,
    server_port INTEGER NOT NULL DEFAULT 0,
    first_ts    INTEGER NOT NULL,
    last_ts     INTEGER NOT NULL,
    protocol    TEXT NOT NULL DEFAULT 'smb2',        -- smb1 / smb2
    dialect     TEXT,                                -- negotiated dialect label
    signing     TEXT NOT NULL DEFAULT 'unknown',     -- disabled / enabled / required / unknown
    server_guid TEXT,                                -- lower-case hex of the SMB2 server GUID
    domain      TEXT,                                -- NTLM account domain
    account     TEXT,                                -- NTLM account name
    workstation TEXT,                                -- NTLM workstation name
    ntlm_phase  TEXT                                 -- negotiate / challenge / authenticate
);
CREATE INDEX smb_sessions_first_ts ON smb_sessions (first_ts, flow_id);
CREATE INDEX smb_sessions_server_ip ON smb_sessions (server_ip);
CREATE INDEX smb_sessions_account ON smb_sessions (account);
CREATE INDEX smb_sessions_ntlm_phase ON smb_sessions (ntlm_phase);

-- Count-only view backing the Overview module card: announced hosts plus SMB sessions.
CREATE VIEW smb_items (kind) AS
    SELECT 'announce' FROM smb_announces
    UNION ALL
    SELECT 'session' FROM smb_sessions;
