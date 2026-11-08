//! Rows and read queries of the SMB analyzer (`smb_announces`, `smb_sessions`).

use std::net::IpAddr;

use rusqlite::{Connection, params};

use crate::connections::EndpointInfo;
use crate::error::Result;
use crate::query::{Keyset, Page, PageRequest, keyset_page};
use crate::records::conversion;

/// Saturating `u64` to `i64`.
fn sat(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn ip(raw: &str, col: usize) -> rusqlite::Result<IpAddr> {
    raw.parse().map_err(|e| conversion(col, e))
}

fn json_strings(raw: Option<String>, col: usize) -> rusqlite::Result<Vec<String>> {
    match raw {
        None => Ok(Vec::new()),
        Some(raw) => serde_json::from_str(&raw).map_err(|e| conversion(col, e)),
    }
}

/// Stable role labels for the set bits of an `smb_announces.server_type` field (`SV_TYPE_*`,
/// MS-BRWS), in a fixed order. Lives next to the stored column; the SMB view renders them.
pub fn server_roles(server_type: u32) -> Vec<&'static str> {
    const TABLE: &[(u32, &str)] = &[
        (0x0000_0001, "workstation"),
        (0x0000_0002, "server"),
        (0x0000_0004, "sql_server"),
        (0x0000_0008, "domain_controller"),
        (0x0000_0010, "backup_domain_controller"),
        (0x0000_0020, "time_source"),
        (0x0000_0040, "apple"),
        (0x0000_0080, "novell"),
        (0x0000_0100, "domain_member"),
        (0x0000_0200, "print_server"),
        (0x0000_0400, "dialin_server"),
        (0x0000_0800, "xenix_server"),
        (0x0000_1000, "nt"),
        (0x0000_2000, "windows_for_workgroups"),
        (0x0000_8000, "nt_server"),
        (0x0001_0000, "potential_browser"),
        (0x0002_0000, "backup_browser"),
        (0x0004_0000, "master_browser"),
        (0x0008_0000, "domain_master_browser"),
    ];
    TABLE
        .iter()
        .filter(|(bit, _)| server_type & bit != 0)
        .map(|(_, label)| *label)
        .collect()
}

/// One browser announcement observation emitted by the analyzer; folded into the aggregate table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbAnnounceRow {
    pub ts: i64,
    pub src_ip: IpAddr,
    pub kind: String,
    pub server_name: String,
    pub dst_name: String,
    pub os_major: u8,
    pub os_minor: u8,
    pub os_label: String,
    pub server_type: u32,
    pub comment: String,
}

/// The incoming observation wins over the stored one: more recent, or same `last_ts` but a
/// greater `(os_label, comment)` (a deterministic tie-break, so the merge is order independent).
const ANNOUNCE_NEWER: &str = "(excluded.last_ts > smb_announces.last_ts OR (excluded.last_ts = \
    smb_announces.last_ts AND (excluded.os_label, excluded.comment) > (smb_announces.os_label, \
    smb_announces.comment)))";

impl SmbAnnounceRow {
    pub(crate) fn insert(&self, conn: &Connection) -> Result<()> {
        let n = ANNOUNCE_NEWER;
        conn.prepare_cached(&format!(
            "INSERT INTO smb_announces \
             (src_ip, server_name, dst_name, kind, os_major, os_minor, os_label, server_type, \
              comment, announce_count, first_ts, last_ts) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?10) \
             ON CONFLICT (src_ip, server_name, dst_name) DO UPDATE SET \
             announce_count = announce_count + 1, \
             first_ts = min(smb_announces.first_ts, excluded.first_ts), \
             last_ts = max(smb_announces.last_ts, excluded.last_ts), \
             kind = iif({n}, excluded.kind, smb_announces.kind), \
             os_major = iif({n}, excluded.os_major, smb_announces.os_major), \
             os_minor = iif({n}, excluded.os_minor, smb_announces.os_minor), \
             os_label = iif({n}, excluded.os_label, smb_announces.os_label), \
             server_type = iif({n}, excluded.server_type, smb_announces.server_type), \
             comment = iif({n}, excluded.comment, smb_announces.comment)",
        ))?
        .execute(params![
            self.src_ip.to_string(),
            self.server_name,
            self.dst_name,
            self.kind,
            self.os_major,
            self.os_minor,
            self.os_label,
            i64::from(self.server_type),
            self.comment,
            self.ts,
        ])?;
        Ok(())
    }
}

/// One aggregated announcement row with what the session knows about the announcing address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbAnnounceEntry {
    pub src_ip: IpAddr,
    pub server_name: String,
    pub dst_name: String,
    pub kind: String,
    pub os_major: u8,
    pub os_minor: u8,
    pub os_label: String,
    pub server_type: u32,
    pub comment: String,
    pub announce_count: u64,
    pub first_ts: i64,
    pub last_ts: i64,
    pub source: EndpointInfo,
}

const ANNOUNCE_FROM: &str = "smb_announces a LEFT JOIN hosts h ON h.ip = a.src_ip";
const ANNOUNCE_SELECT: &str = "a.src_ip, a.server_name, a.dst_name, a.kind, a.os_major, \
    a.os_minor, a.os_label, a.server_type, a.comment, a.announce_count, a.first_ts, a.last_ts, \
    h.names, h.category, h.country";

fn announce_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<SmbAnnounceEntry> {
    let src: String = r.get(0)?;
    let server_type: i64 = r.get(7)?;
    Ok(SmbAnnounceEntry {
        src_ip: ip(&src, 0)?,
        server_name: r.get(1)?,
        dst_name: r.get(2)?,
        kind: r.get(3)?,
        os_major: r.get(4)?,
        os_minor: r.get(5)?,
        os_label: r.get(6)?,
        server_type: u32::try_from(server_type).unwrap_or(0),
        comment: r.get(8)?,
        announce_count: r.get::<_, i64>(9)?.max(0).unsigned_abs(),
        first_ts: r.get(10)?,
        last_ts: r.get(11)?,
        source: EndpointInfo {
            names: json_strings(r.get(12)?, 12)?,
            category: r.get(13)?,
            country: r.get(14)?,
        },
    })
}

/// One page of announcements, newest activity last.
pub fn announces_page(conn: &Connection, request: &PageRequest) -> Result<Page<SmbAnnounceEntry>> {
    let query = Keyset {
        from: ANNOUNCE_FROM,
        select: ANNOUNCE_SELECT,
        sort: "a.last_ts",
        tiebreak: "a.rowid",
        descending: false,
        filter: None,
    };
    keyset_page(conn, &query, &[], request, announce_entry)
}

/// One SMB session over TCP emitted by the analyzer (`smb_sessions`). No NTLM secret here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbSessionRow {
    pub flow_id: u64,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub first_ts: i64,
    pub last_ts: i64,
    pub protocol: String,
    pub dialect: Option<String>,
    pub signing: String,
    pub server_guid: Option<String>,
    pub domain: Option<String>,
    pub account: Option<String>,
    pub workstation: Option<String>,
    pub ntlm_phase: Option<String>,
}

impl SmbSessionRow {
    pub(crate) fn insert(&self, conn: &Connection) -> Result<()> {
        conn.prepare_cached(
            "INSERT INTO smb_sessions \
             (flow_id, client_ip, client_port, server_ip, server_port, first_ts, last_ts, \
              protocol, dialect, signing, server_guid, domain, account, workstation, ntlm_phase) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15) \
             ON CONFLICT (flow_id) DO UPDATE SET \
             first_ts = min(smb_sessions.first_ts, excluded.first_ts), \
             last_ts = max(smb_sessions.last_ts, excluded.last_ts), \
             protocol = excluded.protocol, \
             dialect = coalesce(excluded.dialect, smb_sessions.dialect), \
             signing = CASE WHEN excluded.signing = 'unknown' THEN smb_sessions.signing \
                            ELSE excluded.signing END, \
             server_guid = coalesce(excluded.server_guid, smb_sessions.server_guid), \
             domain = coalesce(excluded.domain, smb_sessions.domain), \
             account = coalesce(excluded.account, smb_sessions.account), \
             workstation = coalesce(excluded.workstation, smb_sessions.workstation), \
             ntlm_phase = coalesce(excluded.ntlm_phase, smb_sessions.ntlm_phase)",
        )?
        .execute(params![
            sat(self.flow_id),
            self.client_ip.to_string(),
            self.client_port,
            self.server_ip.to_string(),
            self.server_port,
            self.first_ts,
            self.last_ts,
            self.protocol,
            self.dialect,
            self.signing,
            self.server_guid,
            self.domain,
            self.account,
            self.workstation,
            self.ntlm_phase,
        ])?;
        Ok(())
    }
}

/// One SMB session with what the session knows about both ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbSessionEntry {
    pub flow_id: u64,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub first_ts: i64,
    pub last_ts: i64,
    pub protocol: String,
    pub dialect: Option<String>,
    pub signing: String,
    pub server_guid: Option<String>,
    pub domain: Option<String>,
    pub account: Option<String>,
    pub workstation: Option<String>,
    pub ntlm_phase: Option<String>,
    pub client: EndpointInfo,
    pub server: EndpointInfo,
}

const SESSION_FROM: &str = "smb_sessions s \
    LEFT JOIN hosts hc ON hc.ip = s.client_ip LEFT JOIN hosts hv ON hv.ip = s.server_ip";
const SESSION_SELECT: &str = "s.flow_id, s.client_ip, s.client_port, s.server_ip, s.server_port, \
    s.first_ts, s.last_ts, s.protocol, s.dialect, s.signing, s.server_guid, s.domain, s.account, \
    s.workstation, s.ntlm_phase, hc.names, hc.category, hc.country, hv.names, hv.category, \
    hv.country";

fn session_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<SmbSessionEntry> {
    let flow_id: i64 = r.get(0)?;
    let client: String = r.get(1)?;
    let server: String = r.get(3)?;
    Ok(SmbSessionEntry {
        flow_id: u64::try_from(flow_id).unwrap_or(0),
        client_ip: ip(&client, 1)?,
        client_port: r.get(2)?,
        server_ip: ip(&server, 3)?,
        server_port: r.get(4)?,
        first_ts: r.get(5)?,
        last_ts: r.get(6)?,
        protocol: r.get(7)?,
        dialect: r.get(8)?,
        signing: r.get(9)?,
        server_guid: r.get(10)?,
        domain: r.get(11)?,
        account: r.get(12)?,
        workstation: r.get(13)?,
        ntlm_phase: r.get(14)?,
        client: EndpointInfo {
            names: json_strings(r.get(15)?, 15)?,
            category: r.get(16)?,
            country: r.get(17)?,
        },
        server: EndpointInfo {
            names: json_strings(r.get(18)?, 18)?,
            category: r.get(19)?,
            country: r.get(20)?,
        },
    })
}

/// One page of SMB sessions, by start time. `auth_only` keeps only sessions that carried NTLM.
pub fn sessions_page(
    conn: &Connection,
    auth_only: bool,
    request: &PageRequest,
) -> Result<Page<SmbSessionEntry>> {
    let query = Keyset {
        from: SESSION_FROM,
        select: SESSION_SELECT,
        sort: "s.first_ts",
        tiebreak: "s.flow_id",
        descending: false,
        filter: auth_only.then_some("s.ntlm_phase IS NOT NULL"),
    };
    keyset_page(conn, &query, &[], request, session_entry)
}

/// OS distribution of host announcements (`os_label` -> distinct announced servers), for the
/// donut of the SMB view. Bounded to the most common labels.
pub fn os_distribution(conn: &Connection, limit: u32) -> Result<Vec<(String, u64)>> {
    let mut stmt = conn.prepare(
        "SELECT os_label, count(DISTINCT server_name) AS n FROM smb_announces \
         WHERE kind = 'host' GROUP BY os_label ORDER BY n DESC, os_label LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (label, n) = row?;
        out.push((label, u64::try_from(n).unwrap_or(0)));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::migrate;
    use crate::schema::SESSION_SCHEMA;
    use std::net::Ipv4Addr;

    fn db() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn, &SESSION_SCHEMA).unwrap();
        conn
    }

    fn announce(ts: i64, ip_last: u8, server: &str, os: &str, kind: &str) -> SmbAnnounceRow {
        SmbAnnounceRow {
            ts,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, ip_last)),
            kind: kind.to_owned(),
            server_name: server.to_owned(),
            dst_name: "WORKGROUP<1D>".to_owned(),
            os_major: 10,
            os_minor: 0,
            os_label: os.to_owned(),
            server_type: 0x0003,
            comment: String::new(),
        }
    }

    #[test]
    fn roles_decode_in_fixed_order() {
        assert_eq!(
            server_roles(0x0003 | 0x0004_0000),
            vec!["workstation", "server", "master_browser"]
        );
        assert_eq!(server_roles(0), Vec::<&str>::new());
    }

    #[test]
    fn announcements_fold_and_count() {
        let conn = db();
        // The same host announces three times; a second host once.
        announce(10, 1, "FILESRV", "Windows 10 / Server 2016+", "host")
            .insert(&conn)
            .unwrap();
        announce(20, 1, "FILESRV", "Windows 10 / Server 2016+", "host")
            .insert(&conn)
            .unwrap();
        announce(30, 1, "FILESRV", "Windows 10 / Server 2016+", "host")
            .insert(&conn)
            .unwrap();
        announce(15, 2, "LEGACY", "Windows XP", "host")
            .insert(&conn)
            .unwrap();
        let page = announces_page(&conn, &PageRequest::first(10)).unwrap();
        assert_eq!(page.items.len(), 2);
        let srv = page
            .items
            .iter()
            .find(|a| a.server_name == "FILESRV")
            .unwrap();
        assert_eq!(srv.announce_count, 3);
        assert_eq!((srv.first_ts, srv.last_ts), (10, 30));

        let dist = os_distribution(&conn, 10).unwrap();
        assert_eq!(
            dist,
            vec![
                ("Windows 10 / Server 2016+".to_owned(), 1),
                ("Windows XP".to_owned(), 1),
            ]
        );
    }

    #[test]
    fn smb_items_view_counts_announces_and_sessions() {
        let conn = db();
        announce(1, 1, "A", "Windows 10 / Server 2016+", "host")
            .insert(&conn)
            .unwrap();
        session(42).insert(&conn).unwrap();
        let n = crate::traffic::count_rows(&conn, "smb_items").unwrap();
        assert_eq!(n, Some(2));
    }

    fn session(flow_id: u64) -> SmbSessionRow {
        SmbSessionRow {
            flow_id,
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            client_port: 50_000,
            server_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            server_port: 445,
            first_ts: 100,
            last_ts: 100,
            protocol: "smb2".to_owned(),
            dialect: Some("SMB 3.1.1".to_owned()),
            signing: "required".to_owned(),
            server_guid: Some("00".repeat(16)),
            domain: None,
            account: None,
            workstation: None,
            ntlm_phase: None,
        }
    }

    #[test]
    fn sessions_merge_and_filter_auth() {
        let conn = db();
        session(42).insert(&conn).unwrap();
        let update = SmbSessionRow {
            first_ts: 120,
            last_ts: 200,
            dialect: None,
            signing: "unknown".to_owned(),
            server_guid: None,
            domain: Some("CORP".to_owned()),
            account: Some("alice".to_owned()),
            ntlm_phase: Some("authenticate".to_owned()),
            ..session(42)
        };
        update.insert(&conn).unwrap();

        let all = sessions_page(&conn, false, &PageRequest::first(10)).unwrap();
        assert_eq!(all.items.len(), 1);
        let s = &all.items[0];
        assert_eq!((s.first_ts, s.last_ts), (100, 200));
        assert_eq!(s.dialect.as_deref(), Some("SMB 3.1.1"));
        assert_eq!(s.signing, "required");
        assert_eq!(s.account.as_deref(), Some("alice"));
        assert_eq!(s.ntlm_phase.as_deref(), Some("authenticate"));

        let auth = sessions_page(&conn, true, &PageRequest::first(10)).unwrap();
        assert_eq!(auth.items.len(), 1);
    }
}
