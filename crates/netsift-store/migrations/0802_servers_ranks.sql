-- Server ranks per role, computed at the end of the import (finalizer `servers`, version 3, P4.8).
-- Range 0800-0899.
-- Without a category filter, the Servers view ranked every row of `server_evidence` at each read
-- (window functions over about 200 000 servers on a 9 M packet session: about 600 ms). The rank
-- of a server in its role (decreasing sum of its evidence counts, then address text) and the
-- number of servers of the role are stored here; the view reads the `limit` first ranks of every
-- role by the rank index (of one role by primary key). With a category filter the ranks change, and the view still ranks at read
-- time. A session imported before this migration fills the table at its first opening (ADR-014);
-- until then, or when served read-only, the view ranks at read time (ADR-023).
CREATE TABLE server_ranks (
    role    TEXT NOT NULL,
    rank    INTEGER NOT NULL,
    ip      TEXT NOT NULL,
    servers INTEGER NOT NULL,
    PRIMARY KEY (role, rank)
) WITHOUT ROWID;
-- First ranks of every role, whatever the roles (no list to keep in step with the source views).
CREATE INDEX server_ranks_rank ON server_ranks (rank);
