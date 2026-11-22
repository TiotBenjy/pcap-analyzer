-- ARP analyzer (docs/specs/arp.md). Range 1000-1099 is reserved for arp (see schema.rs).
-- Conventions: ts columns are i64 nanoseconds since the Unix epoch (UTC); IP addresses are
-- canonical text; MAC addresses are lower-case colon-separated text.

-- One ARP packet per row.
CREATE TABLE arp_messages (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    frame       INTEGER NOT NULL,                  -- global frame index of the packet
    operation   INTEGER NOT NULL,                  -- 1 request, 2 reply, 3/4 RARP...
    kind        TEXT NOT NULL,                     -- request / reply / gratuitous / probe / other
    sender_mac  TEXT,
    sender_ip   TEXT,                              -- NULL unless IPv4
    target_mac  TEXT,
    target_ip   TEXT,
    unsolicited INTEGER NOT NULL DEFAULT 0,        -- reply that no recent request preceded
    binds       INTEGER NOT NULL DEFAULT 0         -- counted in arp_bindings
);
-- List in time order (keyset (ts, id)).
CREATE INDEX arp_messages_ts ON arp_messages (ts);
-- Counters per type under a time range (index alone) and type filter of the list.
CREATE INDEX arp_messages_kind ON arp_messages (kind, unsolicited, ts);
-- Address filters of the list.
CREATE INDEX arp_messages_sender_ip ON arp_messages (sender_ip, ts);
CREATE INDEX arp_messages_target_ip ON arp_messages (target_ip, ts);
CREATE INDEX arp_messages_sender_mac ON arp_messages (sender_mac, ts);
-- Most active senders under a time range (index alone).
CREATE INDEX arp_messages_senders ON arp_messages (binds, sender_ip, sender_mac, ts);

-- One row per (IP, MAC) pair announced by a binding message. Commutative upsert written with each
-- message: counters add up, first/last ts take min/max.
CREATE TABLE arp_bindings (
    ip          TEXT NOT NULL,
    mac         TEXT NOT NULL,
    first_ts    INTEGER NOT NULL,
    last_ts     INTEGER NOT NULL,
    messages    INTEGER NOT NULL DEFAULT 0,
    requests    INTEGER NOT NULL DEFAULT 0,
    replies     INTEGER NOT NULL DEFAULT 0,
    gratuitous  INTEGER NOT NULL DEFAULT 0,
    unsolicited INTEGER NOT NULL DEFAULT 0,
    UNIQUE (ip, mac)
);
CREATE INDEX arp_bindings_first_ts ON arp_bindings (first_ts);
-- Other addresses claimed by the MAC addresses of a conflict.
CREATE INDEX arp_bindings_mac ON arp_bindings (mac, ip);
