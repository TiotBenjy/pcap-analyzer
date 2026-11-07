-- Catalog of sessions (catalog.db at the root of the data directory).
-- Dates are wall-clock nanoseconds since the Unix epoch (UTC).
CREATE TABLE sessions (
    id            TEXT PRIMARY KEY NOT NULL,        -- ULID: sortable by creation time
    name          TEXT NOT NULL,
    sources       TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(sources)),  -- JSON array of paths
    state         TEXT NOT NULL DEFAULT 'importing'
                  CHECK (state IN ('importing', 'ready', 'incomplete', 'failed')),
    state_detail  TEXT,                             -- e.g. error message of a failed import
    created_ns    INTEGER NOT NULL,
    updated_ns    INTEGER NOT NULL,
    source_bytes  INTEGER NOT NULL DEFAULT 0,       -- total size of the source capture files
    session_bytes INTEGER NOT NULL DEFAULT 0        -- disk usage of sessions/<id>/
) WITHOUT ROWID;
CREATE INDEX sessions_created_ns ON sessions (created_ns);
CREATE INDEX sessions_state ON sessions (state);
