-- Connections and open ports (analyzers `connections` and `ports`). Range 0400-0499.
-- Conventions of 0001_core.sql: *_ts in nanoseconds, IP addresses as canonical text.

-- Flows folded per (client, server): the client is the initiator of the flows. Additive
-- upserts (see connections.rs); the rowid is only a pagination tie-breaker.
CREATE TABLE conversations (
    id            INTEGER PRIMARY KEY,
    src_ip        TEXT NOT NULL,                    -- client (initiator)
    dst_ip        TEXT NOT NULL,                    -- server
    first_ts      INTEGER NOT NULL,
    last_ts       INTEGER NOT NULL,
    bytes_fwd     INTEGER NOT NULL DEFAULT 0,       -- src -> dst
    bytes_rev     INTEGER NOT NULL DEFAULT 0,       -- dst -> src
    packets_fwd   INTEGER NOT NULL DEFAULT 0,
    packets_rev   INTEGER NOT NULL DEFAULT 0,
    flows         INTEGER NOT NULL DEFAULT 0,
    dns_bytes_fwd INTEGER NOT NULL DEFAULT 0,       -- part of bytes_fwd carried by DNS flows
    dns_bytes_rev INTEGER NOT NULL DEFAULT 0,       -- part of bytes_rev carried by DNS flows
    dns_flows     INTEGER NOT NULL DEFAULT 0,
    protocols     TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(protocols)),  -- sorted labels
    bytes_total   INTEGER GENERATED ALWAYS AS (bytes_fwd + bytes_rev) VIRTUAL,
    packets_total INTEGER GENERATED ALWAYS AS (packets_fwd + packets_rev) VIRTUAL,
    UNIQUE (src_ip, dst_ip)
);
-- Sort keys of the conversations table (keyset: sort value, then id).
CREATE INDEX conversations_bytes ON conversations (bytes_total);
CREATE INDEX conversations_packets ON conversations (packets_total);
CREATE INDEX conversations_flows ON conversations (flows);
CREATE INDEX conversations_first_ts ON conversations (first_ts);
CREATE INDEX conversations_last_ts ON conversations (last_ts);
-- Top N of the chord diagram without DNS.
CREATE INDEX conversations_bytes_no_dns ON conversations (bytes_fwd + bytes_rev - dns_bytes_fwd - dns_bytes_rev);
-- "To" filter (the "From" filter uses the UNIQUE index).
CREATE INDEX conversations_dst_ip ON conversations (dst_ip);

-- Traffic sent and received per host (additive upserts): source and destination countries.
CREATE TABLE host_traffic (
    ip               TEXT PRIMARY KEY NOT NULL,
    bytes_sent       INTEGER NOT NULL DEFAULT 0,
    bytes_received   INTEGER NOT NULL DEFAULT 0,
    packets_sent     INTEGER NOT NULL DEFAULT 0,
    packets_received INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;

-- Ports seen answering (commutative merging upserts, see ports.rs).
CREATE TABLE open_ports (
    ip        TEXT NOT NULL,
    transport INTEGER NOT NULL,                     -- 6 TCP, 17 UDP
    port      INTEGER NOT NULL,
    evidence  TEXT NOT NULL CHECK (evidence IN ('server_data', 'syn_ack', 'udp_reply')),
    service   TEXT,                                 -- IANA service name of the port
    detected  TEXT,                                 -- service identified by content
    banner    TEXT,                                 -- first line of a greeting, <= 256 bytes
    first_ts  INTEGER NOT NULL,
    last_ts   INTEGER NOT NULL,
    PRIMARY KEY (ip, transport, port)
) WITHOUT ROWID;
CREATE INDEX open_ports_port ON open_ports (port, transport);

-- Clients of a service, counted at read time from the flows (open ports view).
CREATE INDEX flows_service ON flows (dst_ip, dst_port, transport, src_ip);
