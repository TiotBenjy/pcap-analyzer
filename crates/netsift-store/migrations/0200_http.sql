-- HTTP/1.x transactions and headers (`http` analyzer). Range 0200-0299 is reserved for http.
-- A transaction is a request and its response, or one of them alone. "req_*" columns are NULL
-- for a response whose request was not captured, "resp_*" columns for a request without
-- response. Body states: none, complete, incomplete, truncated, bomb, decode_error,
-- not_decoded, malformed.

CREATE TABLE http_transactions (
    id              INTEGER PRIMARY KEY,
    flow_id         INTEGER NOT NULL,                   -- flows.id
    seq             INTEGER NOT NULL,                   -- order in the connection
    client_ip       TEXT NOT NULL,
    client_port     INTEGER NOT NULL,
    server_ip       TEXT NOT NULL,
    server_port     INTEGER NOT NULL,
    ts              INTEGER NOT NULL,                   -- request time, else response time
    end_ts          INTEGER NOT NULL,                   -- last byte of the transaction
    method          TEXT,
    method_group    TEXT NOT NULL,                      -- GET...CONNECT, else 'other'
    uri             TEXT,                               -- request target as sent
    host            TEXT,
    path            TEXT,
    query           TEXT,
    version         TEXT,                               -- 'HTTP/1.1', request else response
    status          INTEGER,
    status_class    TEXT NOT NULL,                      -- '1xx'..'5xx', 'other', 'none'
    reason          TEXT,
    content_type    TEXT,                               -- response media type
    user_agent      TEXT,
    referer         TEXT,
    req_ts          INTEGER,
    req_frame       INTEGER,
    req_head_len    INTEGER,
    req_body_wire   INTEGER,
    req_body_len    INTEGER,
    req_body_state  TEXT,
    req_chunked     INTEGER CHECK (req_chunked IN (0, 1)),
    req_encoding    TEXT,
    req_content_type TEXT,
    req_mime_magic  TEXT,
    req_sha256      TEXT,
    req_preview     TEXT,
    resp_ts         INTEGER,
    resp_frame      INTEGER,
    resp_head_len   INTEGER,
    resp_body_wire  INTEGER,
    resp_body_len   INTEGER NOT NULL DEFAULT 0,         -- 0 without response (sort key)
    resp_body_state TEXT,
    resp_chunked    INTEGER CHECK (resp_chunked IN (0, 1)),
    resp_encoding   TEXT,
    resp_mime_magic TEXT,
    resp_sha256     TEXT,
    resp_preview    TEXT,
    UNIQUE (flow_id, seq)
);
-- Keyset sort keys of the transaction list (rowid is the tie-breaker of every index).
CREATE INDEX http_transactions_ts ON http_transactions (ts);
CREATE INDEX http_transactions_size ON http_transactions (resp_body_len);
CREATE INDEX http_transactions_status ON http_transactions (coalesce(status, -1));
-- Filters and the aggregates of /http/stats.
CREATE INDEX http_transactions_method_group ON http_transactions (method_group);
CREATE INDEX http_transactions_status_class ON http_transactions (status_class);
CREATE INDEX http_transactions_host ON http_transactions (host);
CREATE INDEX http_transactions_content_type ON http_transactions (content_type);
CREATE INDEX http_transactions_user_agent ON http_transactions (user_agent);
CREATE INDEX http_transactions_resp_sha256 ON http_transactions (resp_sha256);

-- Text search on the transaction list (host, target, user agent): trigram, so that any
-- substring of three characters or more matches.
CREATE VIRTUAL TABLE http_transactions_fts USING fts5 (
    host, uri, user_agent,
    content = 'http_transactions', content_rowid = 'id', tokenize = 'trigram'
);
CREATE TRIGGER http_transactions_fts_insert AFTER INSERT ON http_transactions BEGIN
    INSERT INTO http_transactions_fts (rowid, host, uri, user_agent)
    VALUES (new.id, new.host, new.uri, new.user_agent);
END;

-- Header lines of both messages, in their order.
CREATE TABLE http_headers (
    id             INTEGER PRIMARY KEY,
    transaction_id INTEGER NOT NULL REFERENCES http_transactions (id),
    direction      TEXT NOT NULL CHECK (direction IN ('request', 'response')),
    idx            INTEGER NOT NULL,
    name           TEXT NOT NULL,                       -- as sent
    name_lc        TEXT NOT NULL,                       -- lower case, for filters and counts
    value          TEXT NOT NULL
);
CREATE INDEX http_headers_transaction ON http_headers (transaction_id, direction, idx);
CREATE INDEX http_headers_name ON http_headers (name_lc, transaction_id);

-- Text search on header names and values (trigram: cookie or token fragments).
CREATE VIRTUAL TABLE http_headers_fts USING fts5 (
    name, value,
    content = 'http_headers', content_rowid = 'id', tokenize = 'trigram'
);
CREATE TRIGGER http_headers_fts_insert AFTER INSERT ON http_headers BEGIN
    INSERT INTO http_headers_fts (rowid, name, value) VALUES (new.id, new.name, new.value);
END;
