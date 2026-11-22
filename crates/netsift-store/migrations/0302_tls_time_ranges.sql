-- Indexes of the global time filter (P5.2, ADR-030). Range 0300-0399 (tls).
-- The covering indexes of /tls/stats end with `ts`, so that its aggregates under a time range
-- read the index alone.
DROP INDEX IF EXISTS tls_sessions_suite_version;
CREATE INDEX tls_sessions_suite_version ON tls_sessions (cipher_suite, version, cipher_name, cipher_weak, ts);
DROP INDEX IF EXISTS tls_sessions_cert_status;
CREATE INDEX tls_sessions_cert_status ON tls_sessions (cert_status, cert_issues, ts);
DROP INDEX IF EXISTS tls_sessions_sni;
CREATE INDEX tls_sessions_sni ON tls_sessions (sni, ts);
