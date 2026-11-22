-- Global time filter (P5.2, ADR-030). Range 0200-0299 (http).
-- Header lines carry the time of their transaction (written by the writer; filled here on a
-- session imported before this migration), so that header counts under a range read one index
-- instead of joining every header to its transaction (811 ms -> 120 ms on a six-day range).
ALTER TABLE http_headers ADD COLUMN ts INTEGER;
UPDATE http_headers SET ts = (SELECT t.ts FROM http_transactions t WHERE t.id = http_headers.transaction_id);
DROP INDEX IF EXISTS http_headers_name;
CREATE INDEX http_headers_name ON http_headers (name_lc, transaction_id, ts);
-- Aggregates of /http/stats under a range: dimension indexes end with `ts`. The keyset sort
-- indexes (ts, resp_body_len, status_key) are unchanged: their tie-breaker is the rowid.
DROP INDEX IF EXISTS http_transactions_method_group;
CREATE INDEX http_transactions_method_group ON http_transactions (method_group, ts);
DROP INDEX IF EXISTS http_transactions_status_class;
CREATE INDEX http_transactions_status_class ON http_transactions (status_class, ts);
DROP INDEX IF EXISTS http_transactions_content_type;
CREATE INDEX http_transactions_content_type ON http_transactions (content_type, ts);
DROP INDEX IF EXISTS http_transactions_host;
CREATE INDEX http_transactions_host ON http_transactions (host, ts);
DROP INDEX IF EXISTS http_transactions_user_agent;
CREATE INDEX http_transactions_user_agent ON http_transactions (user_agent, ts);
CREATE INDEX http_transactions_status_ts ON http_transactions (status_key, ts);
-- Objects carried by the transactions of a range (Pictures).
DROP INDEX IF EXISTS http_transactions_resp_sha256;
CREATE INDEX http_transactions_resp_sha256 ON http_transactions (resp_sha256, ts);
