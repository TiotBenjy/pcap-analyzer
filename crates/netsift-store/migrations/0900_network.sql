-- Communication graph of the Network view (ADR-018). Range 0900-0999.
-- Derived tables, filled at the end of the import by the `network` step (finalize.rs, ADR-014)
-- from `conversations`, `hosts` and `host_traffic`; never written by an analyzer.
-- `mask`: bits of the protocol groups of the conversations (netsift_store::network::ProtocolGroup,
-- bit i = ProtocolGroup::ALL[i]). Node keys: 'h:<ip>' for the keyed hosts (the 150 largest, and
-- the 150 largest having each protocol group), 'k:<cc>' for the other public hosts of a country,
-- 'other' for the rest; country keys: 'c:<cc>', 'local', 'unknown'. Sums are clamped to i64::MAX.

-- Every host of the session (hosts table and conversation ends).
CREATE TABLE network_hosts (
    ip       TEXT PRIMARY KEY NOT NULL,
    country  TEXT,
    category TEXT NOT NULL,                         -- '' when unknown
    v6       INTEGER NOT NULL CHECK (v6 IN (0, 1)),
    mask     INTEGER NOT NULL,                      -- union of the groups of its conversations
    bytes    INTEGER NOT NULL,                      -- bytes of its conversations
    traffic  INTEGER NOT NULL,                      -- host_traffic sent + received (orphan order)
    rank     INTEGER,                               -- 1 = most bytes; NULL without conversation
    crank    INTEGER,                               -- rank within its country
    keyed    INTEGER NOT NULL CHECK (keyed IN (0, 1)),  -- node = 'h:<ip>'
    node     TEXT NOT NULL,
    cnode    TEXT NOT NULL
) WITHOUT ROWID;
CREATE INDEX network_hosts_keyed ON network_hosts (rank) WHERE keyed = 1;
CREATE INDEX network_hosts_crank ON network_hosts (country, crank) WHERE crank IS NOT NULL;
CREATE INDEX network_hosts_traffic ON network_hosts (traffic, ip);

-- Conversations folded per (client node, server node, groups, categories, IPv6).
CREATE TABLE network_edges (
    a             TEXT NOT NULL,
    b             TEXT NOT NULL,
    mask          INTEGER NOT NULL,
    cat_a         TEXT NOT NULL,
    cat_b         TEXT NOT NULL,
    v6            INTEGER NOT NULL,
    bytes_fwd     INTEGER NOT NULL,                 -- a -> b
    bytes_rev     INTEGER NOT NULL,
    packets       INTEGER NOT NULL,
    flows         INTEGER NOT NULL,
    conversations INTEGER NOT NULL,
    protocols     TEXT NOT NULL CHECK (json_valid(protocols))  -- sorted labels
);

-- Same with country keys (country mode).
CREATE TABLE network_country_edges (
    a             TEXT NOT NULL,
    b             TEXT NOT NULL,
    mask          INTEGER NOT NULL,
    cat_a         TEXT NOT NULL,
    cat_b         TEXT NOT NULL,
    v6            INTEGER NOT NULL,
    bytes_fwd     INTEGER NOT NULL,
    bytes_rev     INTEGER NOT NULL,
    packets       INTEGER NOT NULL,
    flows         INTEGER NOT NULL,
    conversations INTEGER NOT NULL,
    protocols     TEXT NOT NULL CHECK (json_valid(protocols))
);

-- Conversations of the expandable hosts (the 30 largest of a country, when not keyed), folded
-- per (host, side, other node, other expandable host, groups, categories, IPv6).
CREATE TABLE network_expand (
    country       TEXT NOT NULL,                    -- country of `x`
    x             TEXT NOT NULL,                    -- the expandable host
    x_is_src      INTEGER NOT NULL CHECK (x_is_src IN (0, 1)),
    other_node    TEXT NOT NULL,                    -- node key of the other end
    other_ip      TEXT NOT NULL,                    -- the other end when expandable too, else ''
    mask          INTEGER NOT NULL,
    cat_x         TEXT NOT NULL,
    cat_other     TEXT NOT NULL,
    v6            INTEGER NOT NULL,
    bytes_fwd     INTEGER NOT NULL,                 -- client -> server
    bytes_rev     INTEGER NOT NULL,
    packets       INTEGER NOT NULL,
    flows         INTEGER NOT NULL,
    conversations INTEGER NOT NULL,
    protocols     TEXT NOT NULL CHECK (json_valid(protocols))
);
CREATE INDEX network_expand_country ON network_expand (country);

-- Hosts per (node, country key, category, IPv6, groups); node 'keyed' for the keyed hosts.
CREATE TABLE network_host_counts (
    node     TEXT NOT NULL,
    cnode    TEXT NOT NULL,
    category TEXT NOT NULL,
    v6       INTEGER NOT NULL,
    mask     INTEGER NOT NULL,
    hosts    INTEGER NOT NULL
);

-- Conversations carrying a label of each protocol group (counters of the filter toggles).
CREATE TABLE network_protocols (
    grp           TEXT PRIMARY KEY NOT NULL,
    conversations INTEGER NOT NULL
) WITHOUT ROWID;
