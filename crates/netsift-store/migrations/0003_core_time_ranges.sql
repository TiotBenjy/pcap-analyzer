-- Indexes of the global time filter (P5.2, ADR-030, docs/specs/time-filter.md). Range 0001-0099 (core).
-- Active flows and hosts are those whose [first_ts, last_ts] overlaps the range: with the end in
-- the index, counting them reads the index alone. Flows are found in two branches: started at
-- most one hour before the range (first index), or longer than an hour (partial index, rare).
DROP INDEX IF EXISTS flows_first_ts;
CREATE INDEX flows_first_ts ON flows (first_ts, last_ts);
CREATE INDEX flows_long ON flows (last_ts, first_ts) WHERE last_ts - first_ts > 3600000000000;
DROP INDEX IF EXISTS hosts_first_ts;
CREATE INDEX hosts_first_ts ON hosts (first_ts, last_ts);
