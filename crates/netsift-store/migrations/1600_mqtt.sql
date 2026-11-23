-- MQTT analyzer (TCP 1883 and CONNECT detected on any port). Range 1600-1699 is reserved for mqtt
-- (see schema.rs). Conventions: *_ts columns are i64 nanoseconds since the Unix epoch (UTC); IP
-- addresses are canonical text. Text values are bounded and free of control characters
-- (analyzer). Every row is written once by the shard of its TCP connection (ON CONFLICT DO NOTHING).

-- One row per MQTT connection, written at the end of its flow. Narrow enough for the lists: the
-- transcript is in `mqtt_packets`, the password in `mqtt_connect_secrets`.
CREATE TABLE mqtt_connections (
    flow_id            INTEGER PRIMARY KEY,         -- flows.id
    first_ts           INTEGER NOT NULL,
    last_ts            INTEGER NOT NULL,
    client_ip          TEXT NOT NULL,
    client_port        INTEGER NOT NULL,
    server_ip          TEXT NOT NULL,               -- the broker
    server_port        INTEGER NOT NULL,
    transport          TEXT NOT NULL CHECK (transport IN ('tcp', 'ws')),
    ws_path            TEXT,                        -- WebSocket (P5.15b)
    ws_host            TEXT,
    ws_subprotocol     TEXT,
    ws_close_code      INTEGER,
    ws_compressed      INTEGER NOT NULL DEFAULT 0,
    version            INTEGER,                     -- protocol level 3, 4, 5; NULL: unknown
    bridge             INTEGER NOT NULL DEFAULT 0,  -- bit 7 of the level set
    partial            INTEGER NOT NULL DEFAULT 0,  -- picked up in the middle (no CONNECT)
    protocol_name      TEXT,                        -- MQTT / MQIsdp
    client_id          TEXT,
    assigned_client_id TEXT,                        -- 5.0 CONNACK
    clean_start        INTEGER,
    keep_alive         INTEGER,
    server_keep_alive  INTEGER,
    session_expiry     INTEGER,
    username           TEXT,
    has_password       INTEGER NOT NULL DEFAULT 0,
    password_len       INTEGER,
    auth_method        TEXT,                        -- 5.0 enhanced authentication
    auth               TEXT CHECK (auth IN ('none', 'username', 'password', 'enhanced')),
    will_topic         TEXT,
    will_qos           INTEGER,
    will_retain        INTEGER,
    will_payload_len   INTEGER,
    will_payload       BLOB,                        -- first 512 bytes
    connect_props      TEXT NOT NULL DEFAULT '[]',  -- JSON array of [name, value]
    connack_ts         INTEGER,
    connack_code       INTEGER,
    session_present    INTEGER,
    connack_props      TEXT NOT NULL DEFAULT '[]',
    login              TEXT CHECK (login IN ('accepted', 'rejected')),
    end_kind           TEXT NOT NULL,               -- disconnect / close / reset / timeout / capture
    disconnect_ts      INTEGER,
    disconnect_by      TEXT,                        -- c (client) / b (broker)
    disconnect_reason  INTEGER,
    broker_software    TEXT,                        -- $SYS/broker/version
    packets_c2s        INTEGER NOT NULL DEFAULT 0,
    packets_s2c        INTEGER NOT NULL DEFAULT 0,
    publish_c2s        INTEGER NOT NULL DEFAULT 0,
    publish_s2c        INTEGER NOT NULL DEFAULT 0,
    payload_bytes_c2s  INTEGER NOT NULL DEFAULT 0,
    payload_bytes_s2c  INTEGER NOT NULL DEFAULT 0,
    subscribe_count    INTEGER NOT NULL DEFAULT 0,
    pings              INTEGER NOT NULL DEFAULT 0,
    last_ping_ts       INTEGER,
    bytes_c2s          INTEGER NOT NULL DEFAULT 0,  -- wire bytes
    bytes_s2c          INTEGER NOT NULL DEFAULT 0,
    stored_packets     INTEGER NOT NULL DEFAULT 0,
    packets_truncated  INTEGER NOT NULL DEFAULT 0,
    malformed          INTEGER NOT NULL DEFAULT 0,
    protocol_errors    INTEGER NOT NULL DEFAULT 0,
    gaps               INTEGER NOT NULL DEFAULT 0,
    state_dropped      INTEGER NOT NULL DEFAULT 0   -- topics, aliases, subscriptions not kept (memory budget)
);
-- List order (keyset (first_ts, flow_id)), overlap with a range.
CREATE INDEX mqtt_connections_first_ts ON mqtt_connections (first_ts, flow_id);
CREATE INDEX mqtt_connections_span ON mqtt_connections (first_ts, last_ts);
-- Brokers, clients, signals and repeated failures.
CREATE INDEX mqtt_connections_broker ON mqtt_connections (server_ip, server_port, transport);
CREATE INDEX mqtt_connections_client ON mqtt_connections (client_id, first_ts);
CREATE INDEX mqtt_connections_login ON mqtt_connections (login, auth, first_ts);
CREATE INDEX mqtt_connections_pair ON mqtt_connections (client_ip, server_ip, server_port, login);

-- Password of a CONNECT (UTF-8 text, else `hex:` and hexadecimal). Sensitive: never logged,
-- served only by the detail route of a connection, masked by default in the UI.
CREATE TABLE mqtt_connect_secrets (
    flow_id  INTEGER PRIMARY KEY,                   -- mqtt_connections.flow_id
    password TEXT NOT NULL
);

-- Stored control packets (at most 10 000 per connection). Acknowledgements are merged into the
-- packet they acknowledge (`ack_*`, `filters[].granted`); PINGREQ / PINGRESP are only counted.
CREATE TABLE mqtt_packets (
    id             INTEGER PRIMARY KEY,
    flow_id        INTEGER NOT NULL,
    seq            INTEGER NOT NULL,                -- order of arrival in the connection
    ts             INTEGER NOT NULL,
    dir            TEXT NOT NULL CHECK (dir IN ('c', 'b')),
    ptype          INTEGER NOT NULL,                -- 1 CONNECT ... 15 AUTH
    flags          INTEGER NOT NULL DEFAULT 0,
    packet_id      INTEGER,
    qos            INTEGER,
    retain         INTEGER NOT NULL DEFAULT 0,
    dup            INTEGER NOT NULL DEFAULT 0,
    topic          TEXT,
    topic_alias    INTEGER,
    topic_source   TEXT,                            -- name / alias / unresolved
    size           INTEGER NOT NULL,
    payload_len    INTEGER,
    payload        BLOB,                            -- first 512 bytes
    payload_format INTEGER,
    content_type   TEXT,
    reason_code    INTEGER,
    reason_string  TEXT,
    ack_state      TEXT,                            -- none / acked / received / missing / error
    ack_reason     INTEGER,
    ack_ns         INTEGER,
    filters        TEXT NOT NULL DEFAULT '[]',      -- JSON [filter, options, granted]
    props          TEXT NOT NULL DEFAULT '[]',      -- JSON [name, value]
    malformed      INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX mqtt_packets_seq ON mqtt_packets (flow_id, seq);
-- Messages (PUBLISH) by time and by topic.
CREATE INDEX mqtt_packets_publish_ts ON mqtt_packets (ts, id) WHERE ptype = 3;
CREATE INDEX mqtt_packets_publish_topic ON mqtt_packets (topic, ts) WHERE ptype = 3;

-- Messages of one topic in one direction of a connection (every PUBLISH, stored or not). The
-- empty topic is the bucket of the topics beyond the bound and of unresolved aliases.
CREATE TABLE mqtt_topic_flows (
    flow_id       INTEGER NOT NULL,
    dir           TEXT NOT NULL CHECK (dir IN ('c', 'b')),
    topic         TEXT NOT NULL,
    messages      INTEGER NOT NULL,
    payload_bytes INTEGER NOT NULL,
    first_ts      INTEGER NOT NULL,
    last_ts       INTEGER NOT NULL,
    qos0          INTEGER NOT NULL DEFAULT 0,
    qos1          INTEGER NOT NULL DEFAULT 0,
    qos2          INTEGER NOT NULL DEFAULT 0,
    retained      INTEGER NOT NULL DEFAULT 0,
    max_payload   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (flow_id, dir, topic)
) WITHOUT ROWID;
CREATE INDEX mqtt_topic_flows_topic ON mqtt_topic_flows (topic, dir);
CREATE INDEX mqtt_topic_flows_span ON mqtt_topic_flows (first_ts, last_ts);

-- Filters subscribed (at most 1 024 per connection).
CREATE TABLE mqtt_subscriptions (
    flow_id         INTEGER NOT NULL,
    seq             INTEGER NOT NULL,               -- seq of the SUBSCRIBE
    idx             INTEGER NOT NULL,               -- filter index in it
    ts              INTEGER NOT NULL,
    filter          TEXT NOT NULL,
    qos             INTEGER NOT NULL,
    options         INTEGER NOT NULL,
    granted         INTEGER,                        -- SUBACK code
    shared_group    TEXT,
    wildcard        INTEGER NOT NULL DEFAULT 0,     -- #, +/#, $SYS/#
    unsubscribed_ts INTEGER,
    PRIMARY KEY (flow_id, seq, idx)
) WITHOUT ROWID;
CREATE INDEX mqtt_subscriptions_filter ON mqtt_subscriptions (filter);
CREATE INDEX mqtt_subscriptions_wildcard ON mqtt_subscriptions (flow_id) WHERE wildcard = 1;

-- Topic tree (end-of-import step `mqtt`): one node per level of the published topics, with the
-- totals of its subtree. `parent` is NULL for the first level.
CREATE TABLE mqtt_topics (
    path          TEXT PRIMARY KEY,
    parent        TEXT,
    name          TEXT NOT NULL,
    depth         INTEGER NOT NULL,
    is_topic      INTEGER NOT NULL DEFAULT 0,       -- this exact path was published
    children      INTEGER NOT NULL DEFAULT 0,
    topics        INTEGER NOT NULL DEFAULT 0,       -- topics of the subtree, itself included
    messages_pub  INTEGER NOT NULL DEFAULT 0,       -- client to broker
    messages_del  INTEGER NOT NULL DEFAULT 0,       -- broker to client
    payload_bytes INTEGER NOT NULL DEFAULT 0,
    retained      INTEGER NOT NULL DEFAULT 0,
    first_ts      INTEGER NOT NULL,
    last_ts       INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX mqtt_topics_parent ON mqtt_topics (parent, name);

