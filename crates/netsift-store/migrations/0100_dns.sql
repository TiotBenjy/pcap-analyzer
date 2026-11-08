-- DNS, mDNS, LLMNR and NBNS transactions (`dns` analyzer). Range 0100-0199 is reserved for dns.
-- One row per query/response pair; either side may be missing (see netsift-analyze, dns.rs).
-- `pair_id`, `dns_pairs` and `dns_fts` are filled at the end of the import (store, dns.rs).
CREATE TABLE dns_messages (
    id           INTEGER PRIMARY KEY,
    ts           INTEGER NOT NULL,                  -- query time, or response time without query
    flow_id      INTEGER,                           -- flows.id
    transport    INTEGER NOT NULL,                  -- 6 TCP, 17 UDP
    proto        TEXT NOT NULL CHECK (proto IN ('dns', 'mdns', 'llmnr', 'nbns')),
    client_ip    TEXT NOT NULL,
    client_port  INTEGER NOT NULL,
    server_ip    TEXT NOT NULL,                     -- query destination (possibly a group address)
    server_port  INTEGER NOT NULL,
    responder_ip TEXT,                              -- sender of the response when not server_ip
    txid         INTEGER NOT NULL,
    opcode       TEXT NOT NULL,
    qname        TEXT NOT NULL DEFAULT '',
    qtype        TEXT NOT NULL DEFAULT '',
    nb_suffix    INTEGER,                           -- NetBIOS name suffix (NBNS)
    flags        INTEGER NOT NULL DEFAULT 0,
    rcode        TEXT,                              -- NOERROR, NXDOMAIN..., 'timeout', NULL: none expected
    latency_ns   INTEGER,
    answers      TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(answers)), -- [{n, t, v, ttl}]
    answers_text TEXT NOT NULL DEFAULT '',          -- owner names and values, space separated (search)
    has_query    INTEGER NOT NULL CHECK (has_query IN (0, 1)),
    has_response INTEGER NOT NULL CHECK (has_response IN (0, 1)),
    pending      INTEGER NOT NULL DEFAULT 0 CHECK (pending IN (0, 1)),
    pair_id      INTEGER,                           -- dns_pairs.id
    is_error     INTEGER GENERATED ALWAYS AS (rcode IS NOT NULL AND rcode <> 'NOERROR') VIRTUAL
);
-- Detail of a pair (expanded row), in time order.
CREATE INDEX dns_messages_pair_ts ON dns_messages (pair_id, ts);
CREATE INDEX dns_messages_ts ON dns_messages (ts);
-- Statistics by protocol, outcome and type; end-of-import pairing of group queries.
CREATE INDEX dns_messages_proto_error ON dns_messages (proto, is_error);
CREATE INDEX dns_messages_rcode ON dns_messages (rcode);
CREATE INDEX dns_messages_qtype ON dns_messages (qtype, has_query);
CREATE INDEX dns_messages_latency ON dns_messages (latency_ns) WHERE latency_ns IS NOT NULL;
CREATE INDEX dns_messages_pending ON dns_messages (ts) WHERE pending = 1;
CREATE INDEX dns_messages_pairing ON dns_messages (client_ip, client_port, txid, proto, transport, ts);

-- Client -> server pairs of the grouped table, built at the end of the import.
CREATE TABLE dns_pairs (
    id         INTEGER PRIMARY KEY,                 -- deterministic: order of (proto, client, server)
    proto      TEXT NOT NULL,
    client_ip  TEXT NOT NULL,
    server_ip  TEXT NOT NULL,
    messages   INTEGER NOT NULL,
    errors     INTEGER NOT NULL,
    names      INTEGER NOT NULL,                    -- distinct query names
    top_names  TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(top_names)), -- 5 most frequent names
    first_ts   INTEGER NOT NULL,
    last_ts    INTEGER NOT NULL,
    UNIQUE (proto, client_ip, server_ip)
);
CREATE INDEX dns_pairs_messages ON dns_pairs (messages, id);
CREATE INDEX dns_pairs_proto_messages ON dns_pairs (proto, messages, id);
CREATE INDEX dns_pairs_server ON dns_pairs (server_ip);

-- Substring search on names, addresses and answers (trigram: case-insensitive, >= 3 characters).
-- Answers are indexed through `answers_text`, never their JSON (keys would match).
CREATE VIRTUAL TABLE dns_fts USING fts5 (
    qname, client_ip, server_ip, responder_ip, answers_text,
    content = 'dns_messages', content_rowid = 'id', tokenize = 'trigram'
);
