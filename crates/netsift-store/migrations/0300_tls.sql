-- TLS analyzer (range 0300-0399, owner: tls). One TLS session per TCP flow (its first
-- handshake); certificates are deduplicated by SHA-256, their DER content is a blob of the session
-- (`blobs/<aa>/<sha256>`). Timestamps are nanoseconds (UTC), IP addresses canonical text.
-- TLS versions and cipher suites are their IANA 16-bit values (0x0303 = 771 = TLS 1.2).

CREATE TABLE tls_sessions (
    id              INTEGER PRIMARY KEY,            -- flows.id of the TCP flow
    ts              INTEGER NOT NULL,               -- packet time of the first handshake message
    client_ip       TEXT NOT NULL,
    client_port     INTEGER NOT NULL,
    server_ip       TEXT NOT NULL,
    server_port     INTEGER NOT NULL,
    sni             TEXT,
    offered_version INTEGER,                        -- highest version offered (supported_versions included)
    version         INTEGER,                        -- negotiated version, NULL without ServerHello
    cipher_suite    INTEGER,                        -- negotiated suite, NULL without ServerHello
    cipher_name     TEXT,
    cipher_weak     TEXT,                           -- weakness of the suite (rc4, 3des, null...), NULL if none
    alpn_offered    TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(alpn_offered)),
    alpn            TEXT,                           -- protocol selected by the server
    ja3             TEXT,
    ja3_hash        TEXT,
    ja4             TEXT,
    compression     INTEGER,                        -- compression method selected by the server
    resumed         INTEGER NOT NULL DEFAULT 0 CHECK (resumed IN (0, 1)),
    outcome         TEXT NOT NULL CHECK (outcome IN ('complete', 'partial')),
    alert_level     INTEGER,                        -- first plaintext alert, if any
    alert_desc      INTEGER,
    alert_from      TEXT CHECK (alert_from IN ('client', 'server')),
    cert_status     TEXT NOT NULL CHECK (cert_status IN ('present', 'encrypted', 'none')),
    cert_count      INTEGER NOT NULL DEFAULT 0,
    leaf_sha256     TEXT,                           -- tls_certificates.sha256 of the leaf
    cert_issues     INTEGER NOT NULL DEFAULT 0      -- bit set over the chain, see netsift-store tls.rs
);
CREATE INDEX tls_sessions_ts ON tls_sessions (ts, id);
CREATE INDEX tls_sessions_version ON tls_sessions (version, ts);
CREATE INDEX tls_sessions_cipher_suite ON tls_sessions (cipher_suite, ts);
CREATE INDEX tls_sessions_sni ON tls_sessions (sni);
CREATE INDEX tls_sessions_server_ip ON tls_sessions (server_ip);
CREATE INDEX tls_sessions_weak ON tls_sessions (ts, id) WHERE cipher_weak IS NOT NULL;
CREATE INDEX tls_sessions_cert_issues ON tls_sessions (ts, id) WHERE cert_issues != 0;
CREATE INDEX tls_sessions_leaf ON tls_sessions (leaf_sha256);

-- Decoded ClientHello of a session. Lists are JSON arrays of integers in wire order, GREASE
-- values included (fingerprints exclude them).
CREATE TABLE tls_client_hellos (
    session_id         INTEGER PRIMARY KEY,         -- tls_sessions.id
    legacy_version     INTEGER NOT NULL,
    random             TEXT NOT NULL,               -- hex
    session_ticket     INTEGER NOT NULL DEFAULT 0 CHECK (session_ticket IN (0, 1)),
    legacy_session_id  TEXT NOT NULL DEFAULT '',    -- hex
    cipher_suites      TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(cipher_suites)),
    compressions       TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(compressions)),
    extensions         TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(extensions)),
    groups             TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(groups)),
    point_formats      TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(point_formats)),
    signature_algs     TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(signature_algs)),
    supported_versions TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(supported_versions)),
    key_share_groups   TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(key_share_groups))
);

-- Decoded ServerHello of a session.
CREATE TABLE tls_server_hellos (
    session_id        INTEGER PRIMARY KEY,          -- tls_sessions.id
    legacy_version    INTEGER NOT NULL,
    random            TEXT NOT NULL,                -- hex
    legacy_session_id TEXT NOT NULL DEFAULT '',     -- hex
    cipher_suite      INTEGER NOT NULL,
    compression       INTEGER NOT NULL,
    extensions        TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(extensions)),
    selected_version  INTEGER                       -- supported_versions extension (TLS 1.3)
);

-- X.509 certificates seen in clear (TLS 1.2 and earlier), deduplicated by SHA-256 of the DER.
-- Every column is derived from the DER alone: identical whichever session inserts it first.
CREATE TABLE tls_certificates (
    sha256          TEXT PRIMARY KEY NOT NULL,      -- hex, name of the blob
    sha1            TEXT NOT NULL,
    size            INTEGER NOT NULL,
    stored          INTEGER NOT NULL DEFAULT 0 CHECK (stored IN (0, 1)), -- DER blob written
    parsed          INTEGER NOT NULL DEFAULT 1 CHECK (parsed IN (0, 1)),
    subject         TEXT,
    subject_cn      TEXT,
    issuer          TEXT,
    issuer_cn       TEXT,
    serial          TEXT,                           -- hex
    not_before      INTEGER,                        -- ns
    not_after       INTEGER,                        -- ns
    san             TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(san)),
    key_algorithm   TEXT,
    key_bits        INTEGER,
    signature_algorithm TEXT,
    self_signed     INTEGER NOT NULL DEFAULT 0 CHECK (self_signed IN (0, 1)),
    is_ca           INTEGER NOT NULL DEFAULT 0 CHECK (is_ca IN (0, 1))
) WITHOUT ROWID;
CREATE INDEX tls_certificates_subject_cn ON tls_certificates (lower(coalesce(subject_cn, '')), sha256);
CREATE INDEX tls_certificates_not_after ON tls_certificates (not_after);

-- Certificate chain of each session, leaf first (position 0).
CREATE TABLE tls_session_certificates (
    session_id INTEGER NOT NULL,                    -- tls_sessions.id
    position   INTEGER NOT NULL,
    sha256     TEXT NOT NULL,                       -- tls_certificates.sha256
    PRIMARY KEY (session_id, position)
) WITHOUT ROWID;
CREATE INDEX tls_session_certificates_sha256 ON tls_session_certificates (sha256, session_id);

-- Names of the cipher suites seen (offered or selected), for display.
CREATE TABLE tls_cipher_suites (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    weak TEXT
);
