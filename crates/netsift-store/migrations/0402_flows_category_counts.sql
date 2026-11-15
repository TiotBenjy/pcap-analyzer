-- Counts by address category, computed at the end of the import (P4.8). Range 0400-0499.
-- The category filters of the Connections and Open Ports views counted their rows at every read,
-- probing `hosts` once or twice per conversation (677 000 conversations, about 330 ms on a 9 M
-- packet session) or per open port, and the Open Ports list grouped every open port by host
-- before keeping one page. A category belongs to a host, so these counts only change with the
-- import: the finalizers `connections` and `ports` store them here. Until they run (session
-- served read-only before its steps, failed step), the views count at read time (ADR-023).

-- Conversations per pair of categories of their ends (`hosts.category`; '' for an end absent
-- from `hosts`, which no category filter matches). At most a few dozen rows.
CREATE TABLE conversation_categories (
    src_category  TEXT NOT NULL,
    dst_category  TEXT NOT NULL,
    conversations INTEGER NOT NULL,
    PRIMARY KEY (src_category, dst_category)
) WITHOUT ROWID;

-- Hosts with open ports: number of open ports and category ('' when absent from `hosts`).
CREATE TABLE open_port_hosts (
    ip       TEXT PRIMARY KEY NOT NULL,
    ports    INTEGER NOT NULL,
    category TEXT NOT NULL
) WITHOUT ROWID;
-- Keyset order of the Open Ports list (most ports first, then address), category covered.
CREATE INDEX open_port_hosts_rank ON open_port_hosts (ports, ip, category);
CREATE INDEX open_port_hosts_category ON open_port_hosts (category);
