//! Rows, end-of-import step and read queries of the SIP analyzer (`sip_messages`,
//! `sip_dialogs`, `sip_media`).
//!
//! Messages are written as they come. Dialogs (one per Call-ID) and their media are built by the
//! step `sip` ([`finalize`]) once every message is stored: the messages of one Call-ID cross flows
//! and shards. The step reads them in a total order (`call_id`, `ts`, source, `CSeq`, kind, raw
//! text), so the result does not depend on arrival order nor on the shard count.
//!
//! Under a time range (ADR-030, `docs/specs/sip.md`): messages are point records (`ts`),
//! dialogs are folded rows (overlap of `first_ts` / `last_ts`, counters of the session).

use std::net::IpAddr;

use rusqlite::types::Value;
use rusqlite::{Connection, params};

use crate::connections::EndpointInfo;
use crate::error::Result;
use crate::query::{Conditions, Keyset, Page, PageRequest, keyset_page};
use crate::range::{PointSql, TimeRange, query_ranged, query_row_ranged, where_overlap};
use crate::records::conversion;

/// Media kept per dialog.
pub const MAX_DIALOG_MEDIA: usize = 16;
/// RTP flows may outlive the dialog's last message by this much (ns) and still be joined.
pub const RTP_GRACE_NS: i64 = 10_000_000_000;
/// A joined flow starts at most this long (ns) before the offer of its media: the UDP flow
/// timeout, so an older flow on the same address and port belongs to an earlier exchange.
pub const RTP_LEAD_NS: i64 = 60_000_000_000;
/// Distinct methods listed per scanner.
const MAX_SCANNER_METHODS: u32 = 16;
/// Distinct senders whose first software is remembered per dialog.
const MAX_AGENTS: usize = 8;

fn ip(raw: &str, col: usize) -> rusqlite::Result<IpAddr> {
    raw.parse().map_err(|e| conversion(col, e))
}

fn json_strings(raw: Option<String>, col: usize) -> rusqlite::Result<Vec<String>> {
    match raw {
        None => Ok(Vec::new()),
        Some(raw) => serde_json::from_str(&raw).map_err(|e| conversion(col, e)),
    }
}

fn unsigned(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn signed(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// `%q%` with LIKE wildcards escaped; `None` for an empty search.
fn like_pattern(q: Option<&str>) -> Option<String> {
    let q = q.map(str::trim).filter(|q| !q.is_empty())?;
    let mut out = String::with_capacity(q.len() + 2);
    out.push('%');
    for c in q.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    Some(out)
}

/// One media description of an SDP body, as stored in `sip_messages.media`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipMediaDesc {
    /// `audio`, `video`...
    pub media: String,
    /// Media address (its own `c=`, else the session's), when known.
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub proto: String,
    pub codecs: Vec<String>,
    pub direction: Option<String>,
}

/// One SIP message emitted by the analyzer. `Debug` never prints the raw text.
#[derive(Clone, PartialEq, Eq)]
pub struct SipRow {
    pub ts: i64,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    /// `udp` or `tcp`.
    pub transport: String,
    pub flow_id: Option<i64>,
    /// `request` or `response`.
    pub kind: String,
    pub method: Option<String>,
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub request_uri: Option<String>,
    pub call_id: Option<String>,
    pub from_name: Option<String>,
    pub from_uri: Option<String>,
    pub from_tag: Option<String>,
    pub to_name: Option<String>,
    pub to_uri: Option<String>,
    pub to_tag: Option<String>,
    pub cseq: Option<u32>,
    pub user_agent: Option<String>,
    pub server: Option<String>,
    pub scanner: Option<String>,
    pub contact: Option<String>,
    pub via: Option<String>,
    pub expires: Option<u32>,
    pub content_type: Option<String>,
    pub auth_user: Option<String>,
    pub auth_realm: Option<String>,
    pub challenge_realm: Option<String>,
    pub media: Vec<SipMediaDesc>,
    pub size: u64,
    pub raw: String,
    pub raw_truncated: bool,
}

impl std::fmt::Debug for SipRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SipRow")
            .field("ts", &self.ts)
            .field("src", &(self.src_ip, self.src_port))
            .field("dst", &(self.dst_ip, self.dst_port))
            .field("kind", &self.kind)
            .field("method", &self.method)
            .field("status", &self.status)
            .field("call_id", &self.call_id)
            .field("size", &self.size)
            .field("raw", &format_args!("<{} bytes>", self.raw.len()))
            .finish_non_exhaustive()
    }
}

impl SipMediaDesc {
    /// `[media, ip, port, proto, [codecs], direction]`.
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!([
            self.media,
            self.ip.map(|ip| ip.to_string()),
            self.port,
            self.proto,
            self.codecs,
            self.direction
        ])
    }

    /// Inverse of [`Self::to_json`]; `None` for anything else.
    fn from_json(v: &serde_json::Value) -> Option<Self> {
        let a = v.as_array()?;
        let text = |i: usize| a.get(i).and_then(|v| v.as_str()).map(str::to_owned);
        Some(Self {
            media: text(0)?,
            ip: text(1).and_then(|ip| ip.parse().ok()),
            port: u16::try_from(a.get(2)?.as_u64()?).ok()?,
            proto: text(3)?,
            codecs: a
                .get(4)?
                .as_array()?
                .iter()
                .filter_map(|c| c.as_str().map(str::to_owned))
                .collect(),
            direction: text(5),
        })
    }

    /// The media of a stored `sip_messages.media` value.
    fn parse_list(raw: &str) -> Vec<Self> {
        serde_json::from_str::<serde_json::Value>(raw)
            .ok()
            .and_then(|v| {
                v.as_array()
                    .map(|a| a.iter().filter_map(Self::from_json).collect())
            })
            .unwrap_or_default()
    }
}

impl SipRow {
    pub(crate) fn insert(&self, conn: &Connection) -> Result<()> {
        let media = if self.media.is_empty() {
            None
        } else {
            let list: Vec<serde_json::Value> =
                self.media.iter().map(SipMediaDesc::to_json).collect();
            Some(serde_json::Value::Array(list).to_string())
        };
        conn.prepare_cached(
            "INSERT INTO sip_messages \
             (ts, src_ip, src_port, dst_ip, dst_port, transport, flow_id, kind, method, status, \
              reason, request_uri, call_id, from_name, from_uri, from_tag, to_name, to_uri, \
              to_tag, cseq, user_agent, server, software, scanner, contact, via, expires, \
              content_type, auth_user, auth_realm, challenge_realm, media, size, raw, \
              raw_truncated) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
                     ?18, ?19, ?20, ?21, ?22, coalesce(?21, ?22), ?23, ?24, ?25, ?26, ?27, ?28, \
                     ?29, ?30, ?31, ?32, ?33, ?34)",
        )?
        .execute(params![
            self.ts,
            self.src_ip.to_string(),
            self.src_port,
            self.dst_ip.to_string(),
            self.dst_port,
            self.transport,
            self.flow_id,
            self.kind,
            self.method,
            self.status,
            self.reason,
            self.request_uri,
            self.call_id,
            self.from_name,
            self.from_uri,
            self.from_tag,
            self.to_name,
            self.to_uri,
            self.to_tag,
            self.cseq,
            self.user_agent,
            self.server,
            self.scanner,
            self.contact,
            self.via,
            self.expires,
            self.content_type,
            self.auth_user,
            self.auth_realm,
            self.challenge_realm,
            media,
            signed(self.size),
            self.raw,
            self.raw_truncated,
        ])?;
        Ok(())
    }

    /// Rough heap size, for the writer's batch accounting.
    pub fn approx_size(&self) -> usize {
        let opt = |v: &Option<String>| v.as_ref().map_or(0, String::len);
        240 + self.raw.len()
            + opt(&self.method)
            + opt(&self.reason)
            + opt(&self.request_uri)
            + opt(&self.call_id)
            + opt(&self.from_name)
            + opt(&self.from_uri)
            + opt(&self.from_tag)
            + opt(&self.to_name)
            + opt(&self.to_uri)
            + opt(&self.to_tag)
            + opt(&self.user_agent)
            + opt(&self.server)
            + opt(&self.contact)
            + opt(&self.via)
            + opt(&self.content_type)
            + opt(&self.auth_user)
            + opt(&self.auth_realm)
            + opt(&self.challenge_realm)
            + self.media.len() * 96
    }
}

// ---- end-of-import step ------------------------------------------------------------------------

/// What the step reads of one message.
struct Msg {
    ts: i64,
    src_ip: String,
    src_port: i64,
    dst_ip: String,
    dst_port: i64,
    transport: String,
    request: bool,
    method: Option<String>,
    status: Option<i64>,
    reason: Option<String>,
    from_name: Option<String>,
    from_uri: Option<String>,
    to_name: Option<String>,
    to_uri: Option<String>,
    contact: Option<String>,
    software: Option<String>,
    scanner: Option<String>,
    auth_user: Option<String>,
    media: Option<String>,
}

/// One dialog being folded.
#[allow(clippy::struct_excessive_bools)] // Flags of a fold, set once each.
#[derive(Default)]
struct Dialog {
    call_id: String,
    first_ts: i64,
    last_ts: i64,
    /// First request (else first message): defines client and server.
    first: Option<Msg>,
    first_is_request: bool,
    has_invite: bool,
    first_method: Option<String>,
    requests: i64,
    responses: i64,
    invite_ts: Option<i64>,
    ringing_ts: Option<i64>,
    answer: Option<(i64, i64, Option<String>)>,
    bye_ts: Option<i64>,
    cancelled: bool,
    /// Last final response to an INVITE, and to any method.
    invite_final: Option<(i64, Option<String>)>,
    last_final: Option<(i64, Option<String>)>,
    agents: Vec<(String, String)>,
    auth_user: Option<String>,
    challenged: bool,
    scanner: Option<String>,
    media: Vec<(SipMediaDesc, String, i64)>,
}

/// Result of a folded dialog.
struct Outcome {
    method: String,
    state: &'static str,
    /// Final status code and reason.
    final_: Option<(i64, Option<String>)>,
    duration: Option<i64>,
}

impl Outcome {
    fn new(
        method: String,
        state: &'static str,
        final_: Option<(i64, Option<String>)>,
        duration: Option<i64>,
    ) -> Self {
        Self {
            method,
            state,
            final_,
            duration,
        }
    }
}

impl Dialog {
    fn add(&mut self, m: Msg) {
        if self.first.is_none() {
            self.first_ts = m.ts;
        }
        self.last_ts = self.last_ts.max(m.ts);
        let method = m.method.as_deref().unwrap_or_default();
        if m.request {
            self.requests += 1;
            if self.first_method.is_none() {
                self.first_method.clone_from(&m.method);
            }
            match method {
                "INVITE" => {
                    self.has_invite = true;
                    self.invite_ts.get_or_insert(m.ts);
                }
                "BYE" => {
                    self.bye_ts.get_or_insert(m.ts);
                }
                "CANCEL" => self.cancelled = true,
                _ => {}
            }
            if self.auth_user.is_none() {
                self.auth_user.clone_from(&m.auth_user);
            }
        } else {
            self.responses += 1;
            let status = m.status.unwrap_or_default();
            let invite = method == "INVITE";
            if invite && (status == 180 || status == 183) {
                self.ringing_ts.get_or_insert(m.ts);
            }
            if invite && (200..300).contains(&status) && self.answer.is_none() {
                self.answer = Some((m.ts, status, m.reason.clone()));
            }
            if status == 401 || status == 407 {
                self.challenged = true;
            }
            if status >= 200 {
                if invite {
                    self.invite_final = Some((status, m.reason.clone()));
                }
                self.last_final = Some((status, m.reason.clone()));
            }
        }
        if let Some(sw) = &m.software
            && self.agents.len() < MAX_AGENTS
            && !self.agents.iter().any(|(ip, _)| *ip == m.src_ip)
        {
            self.agents.push((m.src_ip.clone(), sw.clone()));
        }
        if let Some(s) = &m.scanner
            && self.scanner.as_ref().is_none_or(|cur| s > cur)
        {
            self.scanner = Some(s.clone());
        }
        if let Some(raw) = &m.media {
            for d in SipMediaDesc::parse_list(raw) {
                if self.media.len() >= MAX_DIALOG_MEDIA {
                    break;
                }
                if d.ip.is_none() {
                    continue;
                }
                let known = self
                    .media
                    .iter()
                    .any(|(x, _, _)| x.media == d.media && x.ip == d.ip && x.port == d.port);
                if !known {
                    self.media.push((d, m.src_ip.clone(), m.ts));
                }
            }
        }
        // The first request wins over a first response (a dialog seen from its middle).
        if self.first.is_none() || (m.request && !self.first_is_request) {
            self.first_is_request = m.request;
            self.first = Some(m);
        }
    }

    /// Method, state, final status and duration of the folded dialog.
    fn outcome(&self) -> Outcome {
        if self.has_invite {
            let method = "INVITE".to_owned();
            if let Some((ts, status, reason)) = &self.answer {
                let final_ = Some((*status, reason.clone()));
                return match self.bye_ts.filter(|b| b >= ts) {
                    Some(bye) => Outcome::new(method, "completed", final_, Some(bye - ts)),
                    None => Outcome::new(method, "answered", final_, Some(self.last_ts - ts)),
                };
            }
            let final_ = self.invite_final.clone();
            let state = match final_.as_ref().map(|(s, _)| *s) {
                _ if self.cancelled => "cancelled",
                Some(487) => "cancelled",
                Some(s) if s >= 300 => "rejected",
                _ => "no-answer",
            };
            return Outcome::new(method, state, final_, None);
        }
        let method = self
            .first_method
            .clone()
            .unwrap_or_else(|| "UNKNOWN".to_owned());
        let final_ = self.last_final.clone();
        let state = match final_.as_ref().map(|(s, _)| *s) {
            Some(s) if (200..300).contains(&s) => "ok",
            Some(_) => "rejected",
            None => "no-answer",
        };
        Outcome::new(method, state, final_, None)
    }

    fn write(self, conn: &Connection) -> Result<()> {
        let Some(first) = &self.first else {
            return Ok(());
        };
        let Outcome {
            method,
            state,
            final_,
            duration,
        } = self.outcome();
        let agent_of = |client: bool| {
            self.agents
                .iter()
                .find(|(ip, _)| (*ip == first.src_ip) == client)
                .map(|(_, sw)| sw.clone())
        };
        conn.prepare_cached(
            "INSERT INTO sip_dialogs \
             (call_id, method, first_ts, last_ts, client_ip, client_port, server_ip, server_port, \
              transport, from_name, from_uri, to_name, to_uri, contact, user_agent, server_agent, \
              requests, responses, invite_ts, ringing_ts, answer_ts, bye_ts, cancelled, \
              final_status, final_reason, state, duration_ns, auth_user, challenged, scanner, \
              media_count) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
                     ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31)",
        )?
        .execute(params![
            self.call_id,
            method,
            self.first_ts,
            self.last_ts,
            first.src_ip,
            first.src_port,
            first.dst_ip,
            first.dst_port,
            first.transport,
            first.from_name,
            first.from_uri,
            first.to_name,
            first.to_uri,
            first.contact,
            agent_of(true),
            agent_of(false),
            self.requests,
            self.responses,
            self.invite_ts,
            self.ringing_ts,
            self.answer.as_ref().map(|(ts, _, _)| *ts),
            self.bye_ts,
            self.cancelled,
            final_.as_ref().map(|(s, _)| *s),
            final_.and_then(|(_, r)| r),
            state,
            duration,
            self.auth_user,
            self.challenged,
            self.scanner,
            i64::try_from(self.media.len()).unwrap_or(0),
        ])?;
        let dialog = conn.last_insert_rowid();
        let mut insert = conn.prepare_cached(
            "INSERT INTO sip_media \
             (dialog_id, media, ip, port, proto, codecs, direction, offered_by, offer_ts) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) ON CONFLICT DO NOTHING",
        )?;
        for (d, by, ts) in &self.media {
            let Some(addr) = d.ip else { continue };
            insert.execute(params![
                dialog,
                d.media,
                addr.to_string(),
                d.port,
                d.proto,
                d.codecs.join(","),
                d.direction,
                by,
                ts,
            ])?;
        }
        Ok(())
    }
}

/// End-of-import step `sip` ([`crate::finalize::SESSION_FINALIZERS`]): rebuilds `sip_dialogs` and
/// `sip_media` from `sip_messages`, then joins each media to the UDP flows of its address and
/// port. One pass over the messages by the index `(call_id, ts)`, memory bounded by one dialog.
pub(crate) fn finalize(conn: &Connection) -> Result<()> {
    conn.execute_batch("DELETE FROM sip_media; DELETE FROM sip_dialogs;")?;
    let mut stmt = conn.prepare(
        "SELECT call_id, ts, src_ip, src_port, dst_ip, dst_port, transport, kind = 'request', \
         method, status, reason, from_name, from_uri, to_name, to_uri, contact, software, \
         scanner, auth_user, media FROM sip_messages WHERE call_id IS NOT NULL \
         ORDER BY call_id, ts, src_ip, src_port, dst_ip, dst_port, transport, cseq, kind, raw",
    )?;
    let mut rows = stmt.query([])?;
    let mut current: Option<Dialog> = None;
    while let Some(r) = rows.next()? {
        let call_id: String = r.get(0)?;
        let msg = Msg {
            ts: r.get(1)?,
            src_ip: r.get(2)?,
            src_port: r.get(3)?,
            dst_ip: r.get(4)?,
            dst_port: r.get(5)?,
            transport: r.get(6)?,
            request: r.get(7)?,
            method: r.get(8)?,
            status: r.get(9)?,
            reason: r.get(10)?,
            from_name: r.get(11)?,
            from_uri: r.get(12)?,
            to_name: r.get(13)?,
            to_uri: r.get(14)?,
            contact: r.get(15)?,
            software: r.get(16)?,
            scanner: r.get(17)?,
            auth_user: r.get(18)?,
            media: r.get(19)?,
        };
        if current.as_ref().is_some_and(|d| d.call_id != call_id)
            && let Some(done) = current.take()
        {
            done.write(conn)?;
        }
        current
            .get_or_insert_with(|| Dialog {
                call_id,
                ..Dialog::default()
            })
            .add(msg);
    }
    if let Some(done) = current {
        done.write(conn)?;
    }
    join_media_flows(conn)?;
    Ok(())
}

/// Joins each media of `sip_media` to the UDP flows of its address and port that overlap
/// `[offer, end of the dialog + RTP_GRACE_NS]` and started at most `RTP_LEAD_NS` before the offer.
///
/// Linear in the flows: the distinct media ends go to a temporary table keyed by `(ip, port)`;
/// the flows that reach an end as destination are found through `flows_service`
/// (`(dst_ip, dst_port, transport)`, exact), those that leave from one by a single pass over the
/// flows with a key lookup in that table (`flows` has no `(src_ip, src_port)` index, and a media
/// gateway may send hundreds of thousands of flows from one address). The candidates, indexed by
/// `(ip, port, first_ts)`, are then aggregated per media with bounded range reads.
pub(crate) fn join_media_flows(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "DROP TABLE IF EXISTS temp.sip_media_ends; \
         DROP TABLE IF EXISTS temp.sip_media_flows; \
         CREATE TEMP TABLE sip_media_ends (ip TEXT NOT NULL, port INTEGER NOT NULL, \
             PRIMARY KEY (ip, port)) WITHOUT ROWID; \
         INSERT OR IGNORE INTO temp.sip_media_ends SELECT ip, port FROM sip_media WHERE port > 0; \
         CREATE TEMP TABLE sip_media_flows (ip TEXT NOT NULL, port INTEGER NOT NULL, \
             flow_id INTEGER NOT NULL, first_ts INTEGER NOT NULL, last_ts INTEGER NOT NULL, \
             packets INTEGER NOT NULL, bytes INTEGER NOT NULL); \
         INSERT INTO temp.sip_media_flows \
             SELECT e.ip, e.port, f.id, f.first_ts, f.last_ts, f.packets_fwd + f.packets_rev, \
                    f.bytes_fwd + f.bytes_rev \
             FROM temp.sip_media_ends e JOIN flows f \
                 ON f.dst_ip = e.ip AND f.dst_port = e.port AND f.transport = 17; \
         INSERT INTO temp.sip_media_flows \
             SELECT e.ip, e.port, f.id, f.first_ts, f.last_ts, f.packets_fwd + f.packets_rev, \
                    f.bytes_fwd + f.bytes_rev \
             FROM flows f CROSS JOIN temp.sip_media_ends e \
                 ON e.ip = f.src_ip AND e.port = f.src_port \
             WHERE f.transport = 17 AND NOT (f.dst_ip = f.src_ip AND f.dst_port = f.src_port); \
         CREATE INDEX temp.sip_media_flows_end ON sip_media_flows (ip, port, first_ts);",
    )?;
    conn.execute(
        "UPDATE sip_media SET (flow_count, packets, bytes, first_flow_id) = \
         (SELECT count(*), coalesce(sum(c.packets), 0), coalesce(sum(c.bytes), 0), min(c.flow_id) \
          FROM temp.sip_media_flows c, sip_dialogs d \
          WHERE d.id = sip_media.dialog_id AND c.ip = sip_media.ip AND c.port = sip_media.port \
          AND c.first_ts >= sip_media.offer_ts - ?2 AND c.first_ts <= d.last_ts + ?1 \
          AND c.last_ts >= sip_media.offer_ts) \
         WHERE port > 0",
        [RTP_GRACE_NS, RTP_LEAD_NS],
    )?;
    conn.execute_batch("DROP TABLE temp.sip_media_flows; DROP TABLE temp.sip_media_ends;")?;
    Ok(())
}

// ---- messages ----------------------------------------------------------------------------------

/// Filters of the message list (all optional, combined with AND).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SipMessageFilter {
    /// `request` or `response`.
    pub kind: Option<String>,
    /// Method (of the request, or of the `CSeq` of a response).
    pub method: Option<String>,
    pub call_id: Option<String>,
    /// Sending address.
    pub src: Option<IpAddr>,
    /// Exact user agent (`User-Agent`, else `Server`).
    pub software: Option<String>,
    /// Only the messages of scanners.
    pub scanner: bool,
    /// Text in the Call-ID, From, To, request URI or user agent.
    pub q: Option<String>,
    /// Messages whose `ts` is within this range.
    pub range: Option<TimeRange>,
}

/// One stored message with what the session knows about both ends. `Debug` never prints the raw
/// text.
#[derive(Clone, PartialEq, Eq)]
pub struct SipMessageEntry {
    pub id: i64,
    pub ts: i64,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub transport: String,
    pub kind: String,
    pub method: Option<String>,
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub request_uri: Option<String>,
    pub call_id: Option<String>,
    pub from_uri: Option<String>,
    pub to_uri: Option<String>,
    pub cseq: Option<u32>,
    pub software: Option<String>,
    pub scanner: Option<String>,
    pub auth_user: Option<String>,
    pub size: u64,
    pub raw: String,
    pub raw_truncated: bool,
    pub source: EndpointInfo,
    pub destination: EndpointInfo,
}

impl std::fmt::Debug for SipMessageEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SipMessageEntry")
            .field("id", &self.id)
            .field("ts", &self.ts)
            .field("src", &(self.src_ip, self.src_port))
            .field("dst", &(self.dst_ip, self.dst_port))
            .field("kind", &self.kind)
            .field("method", &self.method)
            .field("status", &self.status)
            .field("call_id", &self.call_id)
            .field("size", &self.size)
            .field("raw", &format_args!("<{} bytes>", self.raw.len()))
            .finish_non_exhaustive()
    }
}

const MESSAGE_FROM: &str = "sip_messages m \
    LEFT JOIN hosts hs ON hs.ip = m.src_ip LEFT JOIN hosts hd ON hd.ip = m.dst_ip";
const MESSAGE_SELECT: &str = "m.id, m.ts, m.src_ip, m.src_port, m.dst_ip, m.dst_port, \
    m.transport, m.kind, m.method, m.status, m.reason, m.request_uri, m.call_id, m.from_uri, \
    m.to_uri, m.cseq, m.software, m.scanner, m.auth_user, m.size, m.raw, m.raw_truncated, \
    hs.names, hs.category, hs.country, hd.names, hd.category, hd.country";

fn message_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<SipMessageEntry> {
    let src: String = r.get(2)?;
    let dst: String = r.get(4)?;
    Ok(SipMessageEntry {
        id: r.get(0)?,
        ts: r.get(1)?,
        src_ip: ip(&src, 2)?,
        src_port: r.get(3)?,
        dst_ip: ip(&dst, 4)?,
        dst_port: r.get(5)?,
        transport: r.get(6)?,
        kind: r.get(7)?,
        method: r.get(8)?,
        status: r.get(9)?,
        reason: r.get(10)?,
        request_uri: r.get(11)?,
        call_id: r.get(12)?,
        from_uri: r.get(13)?,
        to_uri: r.get(14)?,
        cseq: r.get(15)?,
        software: r.get(16)?,
        scanner: r.get(17)?,
        auth_user: r.get(18)?,
        size: unsigned(r.get(19)?),
        raw: r.get(20)?,
        raw_truncated: r.get(21)?,
        source: EndpointInfo {
            names: json_strings(r.get(22)?, 22)?,
            category: r.get(23)?,
            country: r.get(24)?,
        },
        destination: EndpointInfo {
            names: json_strings(r.get(25)?, 25)?,
            category: r.get(26)?,
            country: r.get(27)?,
        },
    })
}

fn message_conditions(filter: &SipMessageFilter) -> Conditions {
    let mut c = Conditions::new();
    if let Some(k) = &filter.kind {
        c.push("m.kind = ?", [Value::Text(k.clone())]);
    }
    if let Some(v) = &filter.method {
        c.push("m.method = ?", [Value::Text(v.clone())]);
    }
    if let Some(v) = &filter.call_id {
        c.push("m.call_id = ?", [Value::Text(v.clone())]);
    }
    if let Some(s) = filter.src {
        c.push("m.src_ip = ?", [Value::Text(s.to_string())]);
    }
    if let Some(v) = &filter.software {
        c.push("m.software = ?", [Value::Text(v.clone())]);
    }
    if filter.scanner {
        c.push("m.scanner IS NOT NULL", []);
    }
    if let Some(p) = like_pattern(filter.q.as_deref()) {
        c.push(
            "m.call_id LIKE ? ESCAPE '\\' OR m.from_uri LIKE ? ESCAPE '\\' \
             OR m.to_uri LIKE ? ESCAPE '\\' OR m.request_uri LIKE ? ESCAPE '\\' \
             OR m.software LIKE ? ESCAPE '\\'",
            std::iter::repeat_n(Value::Text(p), 5),
        );
    }
    if let Some(r) = filter.range {
        r.push_point(&mut c, "m.ts");
    }
    c
}

/// One page of messages, by time then id (ascending).
pub fn messages_page(
    conn: &Connection,
    filter: &SipMessageFilter,
    request: &PageRequest,
) -> Result<Page<SipMessageEntry>> {
    let c = message_conditions(filter);
    let where_sql = c.sql();
    let query = Keyset {
        from: MESSAGE_FROM,
        select: MESSAGE_SELECT,
        sort: "m.ts",
        tiebreak: "m.id",
        descending: false,
        filter: where_sql.as_deref(),
    };
    keyset_page(conn, &query, &c.params(), request, message_entry)
}

/// Number of messages matching `filter`.
pub fn count_messages(conn: &Connection, filter: &SipMessageFilter) -> Result<u64> {
    let c = message_conditions(filter);
    let sql = match c.sql() {
        Some(w) => format!("SELECT count(*) FROM sip_messages m WHERE {w}"),
        None => "SELECT count(*) FROM sip_messages m".to_owned(),
    };
    let n: i64 = conn.query_row(&sql, c.params().as_slice(), |r| r.get(0))?;
    Ok(unsigned(n))
}

// ---- dialogs -----------------------------------------------------------------------------------

/// Type of dialog listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogType {
    /// INVITE dialogs.
    Call,
    /// REGISTER dialogs.
    Register,
    /// Every other method (OPTIONS, MESSAGE, SUBSCRIBE...).
    Other,
}

/// Filters of the dialog list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SipDialogFilter {
    pub kind: Option<DialogType>,
    /// `completed`, `answered`, `cancelled`, `rejected`, `no-answer`, `ok`.
    pub state: Option<String>,
    /// Text in the Call-ID, From, To, user agents or user name.
    pub q: Option<String>,
    /// Dialogs whose span overlaps this range.
    pub range: Option<TimeRange>,
}

/// One media of a dialog with its joined flows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipMediaEntry {
    pub media: String,
    pub ip: IpAddr,
    pub port: u16,
    pub proto: String,
    pub codecs: Vec<String>,
    pub direction: Option<String>,
    pub offered_by: IpAddr,
    pub offer_ts: i64,
    pub flow_count: u64,
    pub packets: u64,
    pub bytes: u64,
    pub first_flow_id: Option<u64>,
    pub address: EndpointInfo,
}

/// One dialog with what the session knows about both ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipDialogEntry {
    pub id: i64,
    pub call_id: String,
    pub method: String,
    pub first_ts: i64,
    pub last_ts: i64,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub transport: String,
    pub from_name: Option<String>,
    pub from_uri: Option<String>,
    pub to_name: Option<String>,
    pub to_uri: Option<String>,
    pub contact: Option<String>,
    pub user_agent: Option<String>,
    pub server_agent: Option<String>,
    pub requests: u64,
    pub responses: u64,
    pub invite_ts: Option<i64>,
    pub ringing_ts: Option<i64>,
    pub answer_ts: Option<i64>,
    pub bye_ts: Option<i64>,
    pub cancelled: bool,
    pub final_status: Option<u16>,
    pub final_reason: Option<String>,
    pub state: String,
    pub duration_ns: Option<i64>,
    pub auth_user: Option<String>,
    pub challenged: bool,
    pub scanner: Option<String>,
    pub media: Vec<SipMediaEntry>,
    pub client: EndpointInfo,
    pub server: EndpointInfo,
}

const DIALOG_FROM: &str = "sip_dialogs d \
    LEFT JOIN hosts hc ON hc.ip = d.client_ip LEFT JOIN hosts hv ON hv.ip = d.server_ip";
const DIALOG_SELECT: &str = "d.id, d.call_id, d.method, d.first_ts, d.last_ts, d.client_ip, \
    d.client_port, d.server_ip, d.server_port, d.transport, d.from_name, d.from_uri, d.to_name, \
    d.to_uri, d.contact, d.user_agent, d.server_agent, d.requests, d.responses, d.invite_ts, \
    d.ringing_ts, d.answer_ts, d.bye_ts, d.cancelled, d.final_status, d.final_reason, d.state, \
    d.duration_ns, d.auth_user, d.challenged, d.scanner, hc.names, hc.category, hc.country, \
    hv.names, hv.category, hv.country";

fn dialog_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<SipDialogEntry> {
    let client: String = r.get(5)?;
    let server: String = r.get(7)?;
    Ok(SipDialogEntry {
        id: r.get(0)?,
        call_id: r.get(1)?,
        method: r.get(2)?,
        first_ts: r.get(3)?,
        last_ts: r.get(4)?,
        client_ip: ip(&client, 5)?,
        client_port: r.get(6)?,
        server_ip: ip(&server, 7)?,
        server_port: r.get(8)?,
        transport: r.get(9)?,
        from_name: r.get(10)?,
        from_uri: r.get(11)?,
        to_name: r.get(12)?,
        to_uri: r.get(13)?,
        contact: r.get(14)?,
        user_agent: r.get(15)?,
        server_agent: r.get(16)?,
        requests: unsigned(r.get(17)?),
        responses: unsigned(r.get(18)?),
        invite_ts: r.get(19)?,
        ringing_ts: r.get(20)?,
        answer_ts: r.get(21)?,
        bye_ts: r.get(22)?,
        cancelled: r.get(23)?,
        final_status: r.get(24)?,
        final_reason: r.get(25)?,
        state: r.get(26)?,
        duration_ns: r.get(27)?,
        auth_user: r.get(28)?,
        challenged: r.get(29)?,
        scanner: r.get(30)?,
        media: Vec::new(),
        client: EndpointInfo {
            names: json_strings(r.get(31)?, 31)?,
            category: r.get(32)?,
            country: r.get(33)?,
        },
        server: EndpointInfo {
            names: json_strings(r.get(34)?, 34)?,
            category: r.get(35)?,
            country: r.get(36)?,
        },
    })
}

fn dialog_conditions(filter: &SipDialogFilter) -> Conditions {
    let mut c = Conditions::new();
    match filter.kind {
        Some(DialogType::Call) => c.push("d.method = 'INVITE'", []),
        Some(DialogType::Register) => c.push("d.method = 'REGISTER'", []),
        Some(DialogType::Other) => c.push("d.method NOT IN ('INVITE', 'REGISTER')", []),
        None => {}
    }
    if let Some(s) = &filter.state {
        c.push("d.state = ?", [Value::Text(s.clone())]);
    }
    if let Some(p) = like_pattern(filter.q.as_deref()) {
        c.push(
            "d.call_id LIKE ? ESCAPE '\\' OR d.from_uri LIKE ? ESCAPE '\\' \
             OR d.to_uri LIKE ? ESCAPE '\\' OR d.from_name LIKE ? ESCAPE '\\' \
             OR d.to_name LIKE ? ESCAPE '\\' OR d.user_agent LIKE ? ESCAPE '\\' \
             OR d.server_agent LIKE ? ESCAPE '\\' OR d.auth_user LIKE ? ESCAPE '\\'",
            std::iter::repeat_n(Value::Text(p), 8),
        );
    }
    if let Some(r) = filter.range {
        r.push_overlap(&mut c, "d.first_ts", "d.last_ts");
    }
    c
}

/// One page of dialogs, by start then id (ascending), with their media (one query per page).
pub fn dialogs_page(
    conn: &Connection,
    filter: &SipDialogFilter,
    request: &PageRequest,
) -> Result<Page<SipDialogEntry>> {
    let c = dialog_conditions(filter);
    let where_sql = c.sql();
    let query = Keyset {
        from: DIALOG_FROM,
        select: DIALOG_SELECT,
        sort: "d.first_ts",
        tiebreak: "d.id",
        descending: false,
        filter: where_sql.as_deref(),
    };
    let mut page = keyset_page(conn, &query, &c.params(), request, dialog_entry)?;
    if page.items.is_empty() {
        return Ok(page);
    }
    let ids: Vec<String> = page.items.iter().map(|d| d.id.to_string()).collect();
    // Integer ids only: safe to inline.
    let sql = format!(
        "SELECT s.dialog_id, s.media, s.ip, s.port, s.proto, s.codecs, s.direction, \
         s.offered_by, s.offer_ts, s.flow_count, s.packets, s.bytes, s.first_flow_id, \
         h.names, h.category, h.country FROM sip_media s LEFT JOIN hosts h ON h.ip = s.ip \
         WHERE s.dialog_id IN ({}) ORDER BY s.dialog_id, s.offer_ts, s.id",
        ids.join(",")
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |r| {
        let addr: String = r.get(2)?;
        let by: String = r.get(7)?;
        let codecs: String = r.get(5)?;
        Ok((
            r.get::<_, i64>(0)?,
            SipMediaEntry {
                media: r.get(1)?,
                ip: ip(&addr, 2)?,
                port: r.get(3)?,
                proto: r.get(4)?,
                codecs: codecs
                    .split(',')
                    .filter(|c| !c.is_empty())
                    .map(str::to_owned)
                    .collect(),
                direction: r.get(6)?,
                offered_by: ip(&by, 7)?,
                offer_ts: r.get(8)?,
                flow_count: unsigned(r.get(9)?),
                packets: unsigned(r.get(10)?),
                bytes: unsigned(r.get(11)?),
                first_flow_id: r.get::<_, Option<i64>>(12)?.map(unsigned),
                address: EndpointInfo {
                    names: json_strings(r.get(13)?, 13)?,
                    category: r.get(14)?,
                    country: r.get(15)?,
                },
            },
        ))
    })?;
    for row in rows {
        let (dialog, media) = row?;
        if let Some(d) = page.items.iter_mut().find(|d| d.id == dialog) {
            d.media.push(media);
        }
    }
    Ok(page)
}

/// Number of dialogs matching `filter`.
pub fn count_dialogs(conn: &Connection, filter: &SipDialogFilter) -> Result<u64> {
    let c = dialog_conditions(filter);
    let sql = match c.sql() {
        Some(w) => format!("SELECT count(*) FROM sip_dialogs d WHERE {w}"),
        None => "SELECT count(*) FROM sip_dialogs d".to_owned(),
    };
    let n: i64 = conn.query_row(&sql, c.params().as_slice(), |r| r.get(0))?;
    Ok(unsigned(n))
}

// ---- statistics --------------------------------------------------------------------------------

/// Aggregates of the SIP view.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SipStatsRows {
    pub messages: u64,
    pub requests: u64,
    pub responses: u64,
    /// Messages of scanners.
    pub scanner_messages: u64,
    /// Distinct sending addresses.
    pub senders: u64,
    /// Distinct user agents.
    pub agents: u64,
    /// Dialogs overlapping the range (all without range).
    pub dialogs: u64,
    pub calls: u64,
    /// Calls by state: `(state, dialogs)`, sorted by state.
    pub call_states: Vec<(String, u64)>,
    pub registrations: u64,
    /// Total duration of the completed calls (ns).
    pub call_duration_ns: i64,
    /// `(method, requests)`, most frequent first.
    pub methods: Vec<(String, u64)>,
    /// `(status, one reason phrase (the smallest), responses)`, most frequent first.
    pub statuses: Vec<(u16, String, u64)>,
    /// `(user agent, scanner tool, messages)`, most frequent first.
    pub top_agents: Vec<(String, Option<String>, u64)>,
}

/// Aggregates for the view, bounded to `limit` entries per ranking. Message aggregates read the
/// covering indexes ending with `ts` (migration 1300); dialog ones read the overlap index.
pub fn stats(conn: &Connection, limit: u32, range: Option<TimeRange>) -> Result<SipStatsRows> {
    let plan = PointSql::new(conn, "sip_messages", "ts", range)?;
    let where_ts = plan.where_();
    let and_ts = plan.and();
    let mut out = SipStatsRows::default();
    let kinds: Vec<(String, Option<String>, i64)> = query_ranged(
        conn,
        &format!("SELECT kind, method, count(*) FROM sip_messages{where_ts} GROUP BY kind, method"),
        &[],
        range,
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    for (kind, method, n) in kinds {
        let n = unsigned(n);
        out.messages += n;
        if kind == "request" {
            out.requests += n;
            out.methods.push((method.unwrap_or_default(), n));
        } else {
            out.responses += n;
        }
    }
    out.methods
        .sort_by(|x, y| y.1.cmp(&x.1).then_with(|| x.0.cmp(&y.0)));
    out.methods.truncate(limit as usize);

    // Top statuses in SQL, each with one of its reason phrases (the smallest: reasons are the
    // standard phrase in practice), in one pass over the covering index.
    out.statuses = query_ranged(
        conn,
        &format!(
            "SELECT status, min(reason), count(*) AS n FROM sip_messages \
             WHERE status IS NOT NULL{and_ts} GROUP BY status ORDER BY n DESC, status LIMIT ?1"
        ),
        &[&limit],
        range,
        |r| {
            Ok((
                r.get(0)?,
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                unsigned(r.get(2)?),
            ))
        },
    )?;

    out.scanner_messages = unsigned(query_row_ranged(
        conn,
        &format!("SELECT count(*) FROM sip_messages WHERE scanner IS NOT NULL{and_ts}"),
        &[],
        range,
        |r| r.get(0),
    )?);
    out.senders = unsigned(query_row_ranged(
        conn,
        &format!("SELECT count(DISTINCT src_ip) FROM sip_messages{where_ts}"),
        &[],
        range,
        |r| r.get(0),
    )?);
    // Top user agents in SQL, with the number of distinct ones in the same pass (the scanner tool
    // is a function of the user agent: one group per user agent).
    let agents: Vec<(String, Option<String>, u64, i64)> = query_ranged(
        conn,
        &format!(
            "SELECT software, scanner, n, count(*) OVER () FROM \
             (SELECT software, scanner, count(*) AS n FROM sip_messages \
              WHERE software IS NOT NULL{and_ts} GROUP BY software, scanner) \
             ORDER BY n DESC, software, scanner LIMIT ?1"
        ),
        &[&limit],
        range,
        |r| Ok((r.get(0)?, r.get(1)?, unsigned(r.get(2)?), r.get(3)?)),
    )?;
    out.agents = agents.first().map_or(0, |a| unsigned(a.3));
    out.top_agents = agents.into_iter().map(|(a, t, n, _)| (a, t, n)).collect();

    dialog_stats(conn, range, &mut out)?;
    Ok(out)
}

/// Dialog counters of [`stats`]: dialogs overlapping `range`, by method and state.
fn dialog_stats(conn: &Connection, range: Option<TimeRange>, out: &mut SipStatsRows) -> Result<()> {
    let overlap = where_overlap(range, "first_ts", "last_ts");
    let dialogs: Vec<(String, String, i64, i64)> = query_ranged(
        conn,
        &format!(
            "SELECT method, state, count(*), coalesce(sum(duration_ns), 0) FROM sip_dialogs{overlap} \
             GROUP BY method, state"
        ),
        &[],
        range,
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    for (method, state, n, duration) in dialogs {
        let n = unsigned(n);
        out.dialogs += n;
        match method.as_str() {
            "INVITE" => {
                out.calls += n;
                if state == "completed" {
                    out.call_duration_ns = out.call_duration_ns.saturating_add(duration);
                }
                match out.call_states.iter_mut().find(|(s, _)| *s == state) {
                    Some(e) => e.1 += n,
                    None => out.call_states.push((state, n)),
                }
            }
            "REGISTER" => out.registrations += n,
            _ => {}
        }
    }
    out.call_states.sort();
    Ok(())
}

/// One scanner: a tool seen from one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipScannerEntry {
    pub tool: String,
    pub ip: IpAddr,
    pub messages: u64,
    /// Distinct methods sent, sorted.
    pub methods: Vec<String>,
    /// Distinct destination addresses.
    pub targets: u64,
    pub first_ts: i64,
    pub last_ts: i64,
    pub address: EndpointInfo,
}

/// Senders of scanner messages within `range`, most messages first, at most `limit`.
pub fn scanners(
    conn: &Connection,
    limit: u32,
    range: Option<TimeRange>,
) -> Result<Vec<SipScannerEntry>> {
    let plan = PointSql::new(conn, "sip_messages", "ts", range)?;
    let a = plan.and();
    let mut rows = query_ranged(
        conn,
        &format!(
            "SELECT s.tool, s.ip, s.n, s.targets, s.first_ts, s.last_ts, h.names, h.category, \
             h.country FROM \
             (SELECT scanner AS tool, src_ip AS ip, count(*) AS n, \
              count(DISTINCT dst_ip) AS targets, min(ts) AS first_ts, max(ts) AS last_ts \
              FROM sip_messages WHERE scanner IS NOT NULL{a} GROUP BY scanner, src_ip \
              ORDER BY n DESC, scanner, src_ip LIMIT ?1) s \
             LEFT JOIN hosts h ON h.ip = s.ip ORDER BY s.n DESC, s.tool, s.ip"
        ),
        &[&limit],
        range,
        |r| {
            let raw: String = r.get(1)?;
            Ok(SipScannerEntry {
                tool: r.get(0)?,
                ip: ip(&raw, 1)?,
                messages: unsigned(r.get(2)?),
                methods: Vec::new(),
                targets: unsigned(r.get(3)?),
                first_ts: r.get(4)?,
                last_ts: r.get(5)?,
                address: EndpointInfo {
                    names: json_strings(r.get(6)?, 6)?,
                    category: r.get(7)?,
                    country: r.get(8)?,
                },
            })
        },
    )?;
    // Distinct methods of each scanner, bounded (a tool may send any token as a method).
    for row in &mut rows {
        let address = row.ip.to_string();
        row.methods = query_ranged(
            conn,
            &format!(
                "SELECT DISTINCT method FROM sip_messages \
                 WHERE scanner = ?1 AND src_ip = ?2 AND method IS NOT NULL{a} \
                 ORDER BY method LIMIT ?3"
            ),
            &[&row.tool, &address, &MAX_SCANNER_METHODS],
            range,
            |r| r.get(0),
        )?;
    }
    Ok(rows)
}

#[cfg(test)]
mod tests;
