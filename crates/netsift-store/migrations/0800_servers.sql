-- Servers (analyzer `servers` and the Servers view). Range 0800-0899 is reserved for servers.
-- Conventions of 0001_core.sql: *_ts in nanoseconds, IP addresses as canonical text.
--
-- Only what no other table holds is stored here: DHCP messages, NTP responses and KDC replies.
-- The roles themselves are derived at read time by the `server_evidence` view, from these tables
-- and from those of the DNS, ports, SMB and HTTP analyzers (ADR-017).

-- DHCP / BOOTP messages, one row per message (plain inserts: the set of rows does not depend on
-- the arrival order). Unset addresses are NULL. Host names (option 12) are paired with the
-- leased address at the end of the import (finalizer `servers`, ADR-014) to feed hosts.names.
CREATE TABLE dhcp_messages (
    id           INTEGER PRIMARY KEY,
    ts           INTEGER NOT NULL,
    src_ip       TEXT NOT NULL,
    dst_ip       TEXT NOT NULL,
    op           INTEGER NOT NULL CHECK (op IN (1, 2)),   -- 1 request, 2 reply
    msg_type     TEXT,                                    -- discover, offer, request, ack...; NULL: BOOTP
    xid          INTEGER NOT NULL,
    client_mac   TEXT,                                    -- aa:bb:cc:dd:ee:ff (Ethernet only)
    ciaddr       TEXT,
    yiaddr       TEXT,                                    -- address offered / leased
    siaddr       TEXT,
    giaddr       TEXT,                                    -- relay agent
    server_id    TEXT,                                    -- option 54
    requested_ip TEXT,                                    -- option 50
    subnet_mask  TEXT,                                    -- option 1
    routers      TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(routers)),     -- option 3
    dns_servers  TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(dns_servers)), -- option 6
    lease_s      INTEGER,                                 -- option 51
    hostname     TEXT,                                    -- option 12
    -- The DHCP server: its identifier when announced, else the sender.
    server_ip    TEXT GENERATED ALWAYS AS (coalesce(server_id, src_ip)) VIRTUAL
);
CREATE INDEX dhcp_messages_server ON dhcp_messages (op, msg_type, server_ip, ts);
CREATE INDEX dhcp_messages_xid ON dhcp_messages (xid, client_mac);
CREATE INDEX dhcp_messages_ts ON dhcp_messages (ts);

-- NTP server responses (mode 4), folded per server and client (commutative upserts: counts add
-- up, first/last ts take min/max, the version, stratum and reference of the latest response win,
-- ties broken by the greatest values).
CREATE TABLE ntp_responses (
    server_ip TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    responses INTEGER NOT NULL DEFAULT 0,
    version   INTEGER NOT NULL,
    stratum   INTEGER NOT NULL,
    reference TEXT NOT NULL DEFAULT '',
    first_ts  INTEGER NOT NULL,
    last_ts   INTEGER NOT NULL,
    PRIMARY KEY (server_ip, client_ip)
) WITHOUT ROWID;
CREATE INDEX ntp_responses_last_ts ON ntp_responses (server_ip, last_ts);

-- KDC replies (AS-REP, TGS-REP, KRB-ERROR) folded per server, client and kind (same merge rules
-- as ntp_responses for realm and error code).
CREATE TABLE kerberos_replies (
    server_ip  TEXT NOT NULL,
    client_ip  TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('as_rep', 'tgs_rep', 'error')),
    replies    INTEGER NOT NULL DEFAULT 0,
    realm      TEXT,
    error_code INTEGER,
    first_ts   INTEGER NOT NULL,
    last_ts    INTEGER NOT NULL,
    PRIMARY KEY (server_ip, client_ip, kind)
) WITHOUT ROWID;
CREATE INDEX kerberos_replies_last_ts ON kerberos_replies (server_ip, kind, last_ts);

-- Covering indexes of the derived roles on the tables of other analyzers.
CREATE INDEX dns_messages_responder ON dns_messages
    (proto, has_response, coalesce(responder_ip, server_ip), client_ip, ts, latency_ns);
CREATE INDEX http_transactions_server ON http_transactions (server_ip, client_ip, resp_ts)
    WHERE resp_ts IS NOT NULL;

-- One row per (role, server, kind of evidence): what was observed, how many times, by how many
-- distinct clients (NULL when not applicable), when, and a representative value.
CREATE VIEW server_evidence (role, ip, kind, count, clients, first_ts, last_ts, example) AS
WITH srv AS (
    -- SRV answers that locate LDAP, global catalog and Kerberos services: owner and target
    -- (the last word of the value `priority weight port target`).
    SELECT owner, lower(substr(v, length(rtrim(v, replace(v, ' ', ''))) + 1)) AS target, ts
    FROM (SELECT lower(json_extract(a.value, '$.n')) AS owner, json_extract(a.value, '$.v') AS v,
                 m.ts + coalesce(m.latency_ns, 0) AS ts
          FROM dns_messages m, json_each(m.answers) a
          WHERE m.qtype = 'SRV' AND m.has_response = 1 AND json_extract(a.value, '$.t') = 'SRV')
    WHERE owner LIKE '\_ldap.\_tcp.%' ESCAPE '\' OR owner LIKE '\_gc.\_tcp.%' ESCAPE '\'
       OR owner LIKE '\_kerberos.\_tcp.%' ESCAPE '\' OR owner LIKE '\_kerberos.\_udp.%' ESCAPE '\'
),
named AS (
    -- Hosts whose learned names include an SRV target.
    SELECT h.ip, lower(n.value) AS name
    FROM hosts h, json_each(h.names) n
    WHERE h.names <> '[]' AND lower(n.value) IN (SELECT target FROM srv)
)
-- DNS: unicast DNS responses sent (the responder of a query, else its destination).
SELECT 'dns', coalesce(responder_ip, server_ip), 'dns_response', count(*),
       count(DISTINCT client_ip), min(ts + coalesce(latency_ns, 0)),
       max(ts + coalesce(latency_ns, 0)), NULL
FROM dns_messages
WHERE proto = 'dns' AND has_response = 1
GROUP BY coalesce(responder_ip, server_ip)
UNION ALL
-- Services of the roles seen answering on their well-known ports (open_ports), with the flows
-- that reached them.
SELECT CASE o.port WHEN 53 THEN 'dns' WHEN 67 THEN 'dhcp' WHEN 88 THEN 'kerberos'
                   WHEN 123 THEN 'ntp' WHEN 139 THEN 'smb' WHEN 445 THEN 'smb' ELSE 'ldap' END,
       o.ip, 'open_port',
       (SELECT count(*) FROM flows f
        WHERE f.dst_ip = o.ip AND f.dst_port = o.port AND f.transport = o.transport),
       (SELECT count(DISTINCT f.src_ip) FROM flows f
        WHERE f.dst_ip = o.ip AND f.dst_port = o.port AND f.transport = o.transport),
       o.first_ts, o.last_ts,
       o.port || '/' || CASE o.transport WHEN 6 THEN 'tcp' WHEN 17 THEN 'udp'
                                         ELSE o.transport END
FROM open_ports o
WHERE o.port IN (53, 67, 88, 123, 139, 389, 445, 636, 3268, 3269)
UNION ALL
-- DHCP: OFFER, ACK and NAK sent; the example is the address of the latest one. A relayed reply
-- seen on both legs (server -> relay, then relay -> client, sent from giaddr) counts once: the
-- relay leg is dropped when the server leg of the same transaction was captured.
SELECT 'dhcp', d.server_ip, 'dhcp_' || d.msg_type, count(*), count(DISTINCT d.client_mac),
       min(d.ts), max(d.ts),
       (SELECT x.yiaddr FROM dhcp_messages x
        WHERE x.op = 2 AND x.msg_type = d.msg_type AND x.server_ip = d.server_ip
        ORDER BY x.ts DESC, x.yiaddr DESC LIMIT 1)
FROM dhcp_messages d
WHERE d.op = 2 AND d.msg_type IN ('offer', 'ack', 'nak')
  AND NOT (d.src_ip IS d.giaddr AND EXISTS (
      SELECT 1 FROM dhcp_messages s
      WHERE s.xid = d.xid AND s.client_mac IS d.client_mac AND s.op = 2
        AND s.msg_type = d.msg_type AND s.src_ip IS NOT d.giaddr))
GROUP BY d.server_ip, d.msg_type
UNION ALL
-- LDAP and Kerberos located by DNS SRV records (target name learned by a host).
SELECT CASE WHEN s.owner LIKE '\_kerberos.%' ESCAPE '\' THEN 'kerberos' ELSE 'ldap' END,
       n.ip, 'dns_srv', count(*), NULL, min(s.ts), max(s.ts), min(s.owner)
FROM srv s JOIN named n ON n.name = s.target
GROUP BY 1, n.ip
UNION ALL
-- NTP: server responses; the example is the reference of the latest one.
SELECT 'ntp', t.server_ip, 'ntp_response', sum(t.responses), count(*), min(t.first_ts),
       max(t.last_ts),
       (SELECT 'stratum ' || x.stratum || coalesce(nullif(', ' || x.reference, ', '), '')
        FROM ntp_responses x WHERE x.server_ip = t.server_ip
        ORDER BY x.last_ts DESC, x.stratum DESC, x.reference DESC LIMIT 1)
FROM ntp_responses t
GROUP BY t.server_ip
UNION ALL
-- Kerberos: KDC replies; the example is the realm of the latest one.
SELECT 'kerberos', k.server_ip, 'kdc_' || k.kind, sum(k.replies), count(*), min(k.first_ts),
       max(k.last_ts),
       (SELECT x.realm FROM kerberos_replies x
        WHERE x.server_ip = k.server_ip AND x.kind = k.kind AND x.realm IS NOT NULL
        ORDER BY x.last_ts DESC, x.realm DESC LIMIT 1)
FROM kerberos_replies k
GROUP BY k.server_ip, k.kind
UNION ALL
-- SMB: sessions served (example: highest dialect label).
SELECT 'smb', server_ip, 'smb_session', count(*), count(DISTINCT client_ip), min(first_ts),
       max(last_ts), max(dialect)
FROM smb_sessions
GROUP BY server_ip
UNION ALL
-- SMB: browser announcements of the server service, domain controllers apart
-- (SV_TYPE_SERVER 0x2, SV_TYPE_DOMAIN_CTRL 0x8, SV_TYPE_DOMAIN_BAKCTRL 0x10).
SELECT 'smb', src_ip, CASE WHEN server_type & 24 <> 0 THEN 'browser_dc' ELSE 'browser_server' END,
       sum(announce_count), NULL, min(first_ts), max(last_ts), min(server_name)
FROM smb_announces
WHERE server_type & 26 <> 0
GROUP BY src_ip, 3
UNION ALL
-- HTTP: responses sent.
SELECT 'http', server_ip, 'http_response', count(*), count(DISTINCT client_ip), min(resp_ts),
       max(resp_ts), NULL
FROM http_transactions
WHERE resp_ts IS NOT NULL
GROUP BY server_ip;

-- One row per (role, server): backs the Overview module card, read on every session summary.
-- Same sources and conditions as server_evidence (a test checks that both agree), without the
-- aggregates nor the examples: plain distinct scans of the covering indexes.
CREATE VIEW server_roles (role, ip) AS
WITH srv AS (
    SELECT owner, lower(substr(v, length(rtrim(v, replace(v, ' ', ''))) + 1)) AS target
    FROM (SELECT lower(json_extract(a.value, '$.n')) AS owner, json_extract(a.value, '$.v') AS v
          FROM dns_messages m, json_each(m.answers) a
          WHERE m.qtype = 'SRV' AND m.has_response = 1 AND json_extract(a.value, '$.t') = 'SRV')
    WHERE owner LIKE '\_ldap.\_tcp.%' ESCAPE '\' OR owner LIKE '\_gc.\_tcp.%' ESCAPE '\'
       OR owner LIKE '\_kerberos.\_tcp.%' ESCAPE '\' OR owner LIKE '\_kerberos.\_udp.%' ESCAPE '\'
),
named AS (
    SELECT h.ip, lower(n.value) AS name
    FROM hosts h, json_each(h.names) n
    WHERE h.names <> '[]' AND lower(n.value) IN (SELECT target FROM srv)
)
SELECT 'dns', coalesce(responder_ip, server_ip) FROM dns_messages
WHERE proto = 'dns' AND has_response = 1
UNION
SELECT CASE port WHEN 53 THEN 'dns' WHEN 67 THEN 'dhcp' WHEN 88 THEN 'kerberos'
                 WHEN 123 THEN 'ntp' WHEN 139 THEN 'smb' WHEN 445 THEN 'smb' ELSE 'ldap' END, ip
FROM open_ports WHERE port IN (53, 67, 88, 123, 139, 389, 445, 636, 3268, 3269)
UNION
SELECT 'dhcp', server_ip FROM dhcp_messages
WHERE op = 2 AND msg_type IN ('offer', 'ack', 'nak')
UNION
SELECT CASE WHEN s.owner LIKE '\_kerberos.%' ESCAPE '\' THEN 'kerberos' ELSE 'ldap' END, n.ip
FROM srv s JOIN named n ON n.name = s.target
UNION
SELECT 'ntp', server_ip FROM ntp_responses
UNION
SELECT 'kerberos', server_ip FROM kerberos_replies
UNION
SELECT 'smb', server_ip FROM smb_sessions
UNION
SELECT 'smb', src_ip FROM smb_announces WHERE server_type & 26 <> 0
UNION
SELECT 'http', server_ip FROM http_transactions WHERE resp_ts IS NOT NULL;
