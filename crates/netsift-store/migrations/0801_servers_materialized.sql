-- Server roles materialized at the end of the import (finalizer `servers`, version 2, P4.2).
-- Range 0800-0899.
-- The views of 0800 derived the roles at every read: about 1.1 s for the Servers view, 250 ms for
-- the roles of the Network graph and most of the session summary on a 9 M packet session. Their
-- SQL is unchanged under new names (`*_source`); the finalizer copies them into tables with the
-- former names, so every reader keeps its queries. A session imported before this migration fills
-- them at its first opening (ADR-014); until then they are listed as added after the import
-- (ADR-013) and the Servers module shows as not analyzed.
DROP VIEW server_evidence;
DROP VIEW server_roles;

CREATE VIEW server_evidence_source (role, ip, kind, count, clients, first_ts, last_ts, example) AS
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

CREATE VIEW server_roles_source (role, ip) AS
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

CREATE TABLE server_evidence (
    role     TEXT,
    ip       TEXT,
    kind     TEXT,
    count    INTEGER,
    clients  INTEGER,
    first_ts INTEGER,
    last_ts  INTEGER,
    example  TEXT
);
CREATE INDEX server_evidence_role_ip ON server_evidence (role, ip);

CREATE TABLE server_roles (
    role TEXT,
    ip   TEXT
);
CREATE INDEX server_roles_ip ON server_roles (ip, role);
CREATE INDEX server_roles_role ON server_roles (role, ip);
