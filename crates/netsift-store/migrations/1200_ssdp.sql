-- SSDP analyzer (UPnP discovery, UDP 1900). Range 1200-1299 is reserved for ssdp (see schema.rs).
-- Conventions: ts columns are i64 nanoseconds since the Unix epoch (UTC); IP addresses are
-- canonical text. Text values are bounded and free of control characters (analyzer).

-- One row per datagram from or to UDP 1900.
CREATE TABLE ssdp_messages (
    id            INTEGER PRIMARY KEY,
    ts            INTEGER NOT NULL,
    src_ip        TEXT NOT NULL,
    src_port      INTEGER NOT NULL,
    dst_ip        TEXT NOT NULL,
    dst_port      INTEGER NOT NULL,
    multicast     INTEGER NOT NULL DEFAULT 0,   -- destination is a multicast group
    kind          TEXT NOT NULL,                -- notify / search / response / invalid
    nts           TEXT,                         -- notify: alive / byebye / update / other value
    status        INTEGER,                      -- response: status code
    target        TEXT,                         -- NT (notify) or ST (search, response)
    usn           TEXT,
    uuid          TEXT,                         -- device id from the USN, lower case
    server        TEXT,                         -- SERVER
    user_agent    TEXT,                         -- USER-AGENT
    software      TEXT,                         -- SERVER, else USER-AGENT (rankings)
    location      TEXT,                         -- LOCATION (extracted URL, never fetched)
    max_age       INTEGER,                      -- CACHE-CONTROL max-age, seconds
    mx            INTEGER,                      -- MX, seconds
    size          INTEGER NOT NULL,             -- datagram bytes
    raw           TEXT NOT NULL,                -- first 2048 bytes as sanitized text
    raw_truncated INTEGER NOT NULL DEFAULT 0
);
-- List order (keyset (ts, id)) and point range.
CREATE INDEX ssdp_messages_ts ON ssdp_messages (ts);
-- Type filter of the list, and counters by type over a range (covering, ending with ts).
CREATE INDEX ssdp_messages_kind ON ssdp_messages (kind, ts);
CREATE INDEX ssdp_messages_kind_nts ON ssdp_messages (kind, nts, ts);
-- Rankings over a range (covering, ending with ts).
CREATE INDEX ssdp_messages_target ON ssdp_messages (target, ts);
CREATE INDEX ssdp_messages_software ON ssdp_messages (software, ts);
CREATE INDEX ssdp_messages_src ON ssdp_messages (src_ip, ts);
-- Messages and targets of one device.
CREATE INDEX ssdp_messages_device ON ssdp_messages (uuid, src_ip, ts);
CREATE INDEX ssdp_messages_device_target ON ssdp_messages (uuid, src_ip, target);

-- UPnP devices, folded per (uuid, announcing address) by the upsert of each message that carries
-- a USN. Commutative: counters add up, first/last ts take min/max, and each text value is the
-- latest non-empty one (its own timestamp, ties broken by the value).
CREATE TABLE ssdp_devices (
    uuid           TEXT NOT NULL,
    ip             TEXT NOT NULL,
    device_type    TEXT NOT NULL DEFAULT '',
    device_type_ts INTEGER NOT NULL DEFAULT 0,
    server         TEXT NOT NULL DEFAULT '',
    server_ts      INTEGER NOT NULL DEFAULT 0,
    location       TEXT NOT NULL DEFAULT '',
    location_ts    INTEGER NOT NULL DEFAULT 0,
    message_count  INTEGER NOT NULL DEFAULT 0,
    alive_count    INTEGER NOT NULL DEFAULT 0,
    byebye_count   INTEGER NOT NULL DEFAULT 0,
    response_count INTEGER NOT NULL DEFAULT 0,
    first_ts       INTEGER NOT NULL,
    last_ts        INTEGER NOT NULL,
    PRIMARY KEY (uuid, ip)
);
-- List order (keyset (message_count DESC, rowid)).
CREATE INDEX ssdp_devices_count ON ssdp_devices (message_count);
-- Overlap with a range.
CREATE INDEX ssdp_devices_span ON ssdp_devices (first_ts, last_ts);
