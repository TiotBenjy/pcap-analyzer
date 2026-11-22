-- Ethernet analyzer (link layer). Range 1100-1199 is reserved for ethernet (see schema.rs).
-- Conventions of 0001_core.sql: *_ts in nanoseconds. MAC addresses are lower-case text
-- `aa:bb:cc:dd:ee:ff`. Every table is folded (additive upserts, see ethernet.rs), never one row
-- per frame; counters are those of the session (docs/specs/ethernet.md, time filter).

-- MAC addresses seen as source or destination of a frame.
CREATE TABLE eth_macs (
    mac             TEXT PRIMARY KEY NOT NULL,
    vendor          TEXT,                           -- IEEE organization (universally administered)
    registry        TEXT,                           -- ma-l / ma-m / ma-s
    kind            TEXT NOT NULL CHECK (kind IN ('unicast', 'multicast', 'broadcast')),
    local           INTEGER NOT NULL DEFAULT 0,     -- U/L bit: locally administered
    grp             TEXT,                           -- well-known group (ipv4_multicast...)
    frames_sent     INTEGER NOT NULL DEFAULT 0,
    bytes_sent      INTEGER NOT NULL DEFAULT 0,
    frames_received INTEGER NOT NULL DEFAULT 0,
    bytes_received  INTEGER NOT NULL DEFAULT 0,
    first_ts        INTEGER NOT NULL,
    last_ts         INTEGER NOT NULL,
    vlans           TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(vlans)),  -- sorted VLAN stacks
    frames_total    INTEGER GENERATED ALWAYS AS (frames_sent + frames_received) VIRTUAL,
    bytes_total     INTEGER GENERATED ALWAYS AS (bytes_sent + bytes_received) VIRTUAL
) WITHOUT ROWID;
-- Sort keys of the address list (keyset: sort value, then mac).
CREATE INDEX eth_macs_frames ON eth_macs (frames_total);
CREATE INDEX eth_macs_bytes ON eth_macs (bytes_total);
CREATE INDEX eth_macs_first_ts ON eth_macs (first_ts, last_ts);
CREATE INDEX eth_macs_last_ts ON eth_macs (last_ts);
-- Vendor bars and the vendor filter (unicast addresses, by vendor).
CREATE INDEX eth_macs_vendor ON eth_macs (kind, local, vendor, first_ts, last_ts);

-- Frames from one address to another (directional).
CREATE TABLE eth_pairs (
    id         INTEGER PRIMARY KEY,
    src_mac    TEXT NOT NULL,
    dst_mac    TEXT NOT NULL,
    frames     INTEGER NOT NULL DEFAULT 0,
    bytes      INTEGER NOT NULL DEFAULT 0,
    first_ts   INTEGER NOT NULL,
    last_ts    INTEGER NOT NULL,
    ethertypes TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(ethertypes)),  -- sorted EtherType keys
    vlans      TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(vlans)),       -- sorted VLAN stacks
    UNIQUE (src_mac, dst_mac)
);
CREATE INDEX eth_pairs_frames ON eth_pairs (frames);
CREATE INDEX eth_pairs_bytes ON eth_pairs (bytes);
CREATE INDEX eth_pairs_first_ts ON eth_pairs (first_ts, last_ts);
CREATE INDEX eth_pairs_last_ts ON eth_pairs (last_ts);
-- Pairs of one address as destination (as source: the UNIQUE index).
CREATE INDEX eth_pairs_dst_mac ON eth_pairs (dst_mac);

-- Frames per EtherType: 0x0600-0xffff an EtherType, 0-255 the DSAP of an 802.2 LLC header
-- without EtherType (802.3 framing), -1 a truncated link header.
CREATE TABLE eth_types (
    ethertype INTEGER PRIMARY KEY,
    frames    INTEGER NOT NULL DEFAULT 0,
    bytes     INTEGER NOT NULL DEFAULT 0,
    first_ts  INTEGER NOT NULL,
    last_ts   INTEGER NOT NULL
);

-- Frames per VLAN stack (`100` or `100.20`, outermost tag first); untagged frames are absent.
CREATE TABLE eth_vlans (
    stack      TEXT PRIMARY KEY NOT NULL,
    outer_id   INTEGER NOT NULL,
    inner_id   INTEGER NOT NULL,
    depth      INTEGER NOT NULL,                    -- number of tags
    outer_tpid INTEGER NOT NULL,                    -- 0x8100, 0x88a8 or 0x9100
    frames     INTEGER NOT NULL DEFAULT 0,
    bytes      INTEGER NOT NULL DEFAULT 0,
    first_ts   INTEGER NOT NULL,
    last_ts    INTEGER NOT NULL
) WITHOUT ROWID;
