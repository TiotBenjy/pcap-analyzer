-- Indexes of the global time filter (P5.2, ADR-030). Range 0100-0199 (dns).
-- Every aggregate of /dns/stats and of the grouped tables under a time range reads one covering
-- index that ends with `ts` (index alone, never the rows and their JSON answers): on the bench,
-- 745 ms -> 53 ms for the counters of a six-day range.
DROP INDEX IF EXISTS dns_messages_proto_error;
CREATE INDEX dns_messages_proto_error ON dns_messages (proto, is_error, has_query, has_response, ts);
DROP INDEX IF EXISTS dns_messages_rcode;
CREATE INDEX dns_messages_rcode ON dns_messages (rcode, ts);
DROP INDEX IF EXISTS dns_messages_qtype;
CREATE INDEX dns_messages_qtype ON dns_messages (qtype, has_query, ts);
DROP INDEX IF EXISTS dns_messages_latency;
CREATE INDEX dns_messages_latency ON dns_messages (latency_ns, ts) WHERE latency_ns IS NOT NULL;
-- Pairs and servers regrouped over a range: counts, errors and names of each pair, from the
-- index alone (`dns_messages_pair_ts` keeps serving the messages of a pair in time order).
CREATE INDEX dns_messages_pair_cover ON dns_messages (pair_id, ts, is_error, qname);
