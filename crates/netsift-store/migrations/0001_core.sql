-- Core session schema. Range 0001-0099 is reserved for the core (netsift-store).
-- Conventions: every *_ts column is an i64 count of nanoseconds since the Unix epoch (UTC);
-- IP addresses are stored as canonical text (Rust `IpAddr` Display, RFC 5952 for IPv6);
-- JSON columns are validated with json_valid().

-- Free-form key/value metadata: import options, global statistics, tool version.
CREATE TABLE meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) WITHOUT ROWID;

-- One row per capture file of the session, in chunk-set order (see docs/CHUNKED_CAPTURES.md).
CREATE TABLE chunks (
    id         INTEGER PRIMARY KEY,                 -- index in the ordered set (RawPacket.chunk_id)
    seq        INTEGER,                             -- sequence number parsed from the file name
    path       TEXT NOT NULL,
    format     TEXT CHECK (format IN ('pcap', 'pcapng')),
    compressed INTEGER NOT NULL DEFAULT 0 CHECK (compressed IN (0, 1)),
    linktypes  TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(linktypes)),
    snaplen    INTEGER,
    first_ts   INTEGER,
    last_ts    INTEGER,
    packets    INTEGER NOT NULL DEFAULT 0,
    bytes      INTEGER NOT NULL DEFAULT 0,          -- captured packet bytes
    file_size  INTEGER NOT NULL DEFAULT 0,          -- size of the file on disk
    mtime_ns   INTEGER,
    head_hash  TEXT,                                -- hex digest of the first 64 KiB
    status     TEXT NOT NULL DEFAULT 'ok'
               CHECK (status IN ('ok', 'truncated', 'duplicate', 'ignored'))
);
CREATE INDEX chunks_seq ON chunks (seq);
CREATE INDEX chunks_first_ts ON chunks (first_ts);
CREATE INDEX chunks_status ON chunks (status);

-- Continuity and reading anomalies (missing sequence numbers, gaps, overlaps, truncation...).
CREATE TABLE anomalies (
    id       INTEGER PRIMARY KEY,
    kind     TEXT NOT NULL,
    chunk_id INTEGER,                               -- chunks.id, NULL when not tied to a file
    ts       INTEGER,
    detail   TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail))
);
CREATE INDEX anomalies_kind ON anomalies (kind);
CREATE INDEX anomalies_chunk_id ON anomalies (chunk_id);
-- Keyset sort key of list_anomalies (anomalies without timestamp last).
CREATE INDEX anomalies_ts ON anomalies (coalesce(ts, 9223372036854775807), id);

-- Traffic per one-second bucket and application protocol (additive upserts).
CREATE TABLE timeseries (
    bucket_s INTEGER NOT NULL,                      -- seconds since the Unix epoch
    proto    TEXT NOT NULL,
    bytes    INTEGER NOT NULL DEFAULT 0,
    packets  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_s, proto)
) WITHOUT ROWID;
CREATE INDEX timeseries_proto ON timeseries (proto, bucket_s);

-- Hosts seen in the capture (commutative merging upserts, see records.rs).
-- No surrogate id: it would depend on the (non-deterministic) arrival order.
CREATE TABLE hosts (
    ip       TEXT PRIMARY KEY NOT NULL,
    macs     TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(macs)),   -- sorted JSON array
    names    TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(names)),  -- sorted JSON array
    country  TEXT,
    category TEXT,
    first_ts INTEGER NOT NULL,
    last_ts  INTEGER NOT NULL
);
CREATE INDEX hosts_country ON hosts (country);
CREATE INDEX hosts_category ON hosts (category);
CREATE INDEX hosts_first_ts ON hosts (first_ts);
CREATE INDEX hosts_last_ts ON hosts (last_ts);

-- Flows; the id is assigned by the engine so analyzer rows can reference a flow early.
-- Upserts are commutative (min/max), the 5-tuple is an invariant of the id.
-- "fwd" is the initiator -> responder direction (src -> dst), "rev" the opposite.
CREATE TABLE flows (
    id            INTEGER PRIMARY KEY,
    transport     INTEGER NOT NULL,                 -- IP protocol number (6 TCP, 17 UDP, 1 ICMP...)
    src_ip        TEXT NOT NULL,
    src_port      INTEGER NOT NULL DEFAULT 0,       -- 0 when the transport has no ports
    dst_ip        TEXT NOT NULL,
    dst_port      INTEGER NOT NULL DEFAULT 0,
    first_ts      INTEGER NOT NULL,
    last_ts       INTEGER NOT NULL,
    bytes_fwd     INTEGER NOT NULL DEFAULT 0,
    bytes_rev     INTEGER NOT NULL DEFAULT 0,
    packets_fwd   INTEGER NOT NULL DEFAULT 0,
    packets_rev   INTEGER NOT NULL DEFAULT 0,
    bytes_total   INTEGER GENERATED ALWAYS AS (bytes_fwd + bytes_rev) VIRTUAL,
    packets_total INTEGER GENERATED ALWAYS AS (packets_fwd + packets_rev) VIRTUAL,
    app_proto     TEXT,
    tcp_state     TEXT
);
CREATE INDEX flows_first_ts ON flows (first_ts);
CREATE INDEX flows_last_ts ON flows (last_ts);
CREATE INDEX flows_src_ip ON flows (src_ip);
CREATE INDEX flows_dst_ip ON flows (dst_ip);
CREATE INDEX flows_dst_port ON flows (dst_port);
CREATE INDEX flows_app_proto ON flows (app_proto);
CREATE INDEX flows_bytes_total ON flows (bytes_total);
CREATE INDEX flows_packets_total ON flows (packets_total);
