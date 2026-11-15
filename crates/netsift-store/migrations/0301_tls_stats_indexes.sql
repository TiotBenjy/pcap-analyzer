-- Covering indexes of the aggregates of the TLS view (P4.2). Range 0300-0399.
-- Without them, /tls/stats read every session row three times (counters, suites with their
-- names, version x suite matrix): 400 ms on a session of 170 000 TLS sessions.
CREATE INDEX tls_sessions_suite_version ON tls_sessions (cipher_suite, version, cipher_name, cipher_weak);
CREATE INDEX tls_sessions_cert_status ON tls_sessions (cert_status, cert_issues);
