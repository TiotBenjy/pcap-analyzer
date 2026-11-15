-- Traffic per minute and per hour (finalizer `timeseries`, P4.2). Range 0001-0099 (core).
-- Folded at the end of the import from `timeseries` (one-second buckets): the overview reads
-- the coarsest table whose width divides its bucket width, so a week-long chart reads about
-- 10 000 minute rows per label instead of 600 000 one-second rows. Same columns and units as
-- `timeseries`; a session imported before this migration fills them at its first opening.
CREATE TABLE timeseries_minute (
    bucket_s INTEGER NOT NULL,                      -- multiple of 60, seconds since the epoch
    proto    TEXT NOT NULL,
    bytes    INTEGER NOT NULL DEFAULT 0,
    packets  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_s, proto)
) WITHOUT ROWID;

CREATE TABLE timeseries_hour (
    bucket_s INTEGER NOT NULL,                      -- multiple of 3600
    proto    TEXT NOT NULL,
    bytes    INTEGER NOT NULL DEFAULT 0,
    packets  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_s, proto)
) WITHOUT ROWID;
