-- Extracted objects (task P3.6). Range 0700-0799 is reserved for objects.
-- One row per distinct content (SHA-256 of the file under blobs/). Built at the end of the
-- import from the transactions that carry a stored body (end-of-import step `objects`,
-- ADR-014), so it never depends on the arrival order of the records nor on the shard count.
-- `id` follows the order of first appearance: (first_ts, flow_id, seq).
-- Thumbnails: `pending` (not generated yet), `ready` (thumbs/<aa>/<sha256>.png exists),
-- `none` (never rasterized: SVG), `failed` (not decodable within the limits).

CREATE TABLE objects (
    id            INTEGER PRIMARY KEY,
    sha256        TEXT NOT NULL UNIQUE,              -- lower-case hex, file name of the blob
    size          INTEGER NOT NULL,
    mime          TEXT NOT NULL,                     -- detected from the content (magic)
    declared_type TEXT,                              -- Content-Type of the first response
    width         INTEGER,                           -- once decoded (thumbnail step)
    height        INTEGER,
    thumb         TEXT NOT NULL DEFAULT 'pending'
                  CHECK (thumb IN ('pending', 'ready', 'none', 'failed')),
    occurrences   INTEGER NOT NULL,                  -- transactions that carried it
    first_ts      INTEGER NOT NULL,                  -- first response carrying it
    last_ts       INTEGER NOT NULL,
    flow_id       INTEGER NOT NULL,                  -- first transaction: http_transactions
    seq           INTEGER NOT NULL,                  -- (flow_id, seq)
    client_ip     TEXT NOT NULL,
    server_ip     TEXT NOT NULL,
    server_port   INTEGER NOT NULL,
    host          TEXT,
    uri           TEXT                               -- request target as sent
);
-- Keyset sort keys (id is the tie-breaker) and filters of the Pictures view.
CREATE INDEX objects_size ON objects (size, id);
CREATE INDEX objects_mime ON objects (mime, id);
CREATE INDEX objects_host ON objects (host, id);
CREATE INDEX objects_thumb ON objects (thumb, id);

-- What the Pictures view lists (and the overview counts): images, SVG included.
CREATE VIEW pictures AS SELECT * FROM objects WHERE mime LIKE 'image/%';
