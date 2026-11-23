//! SDP body parser (RFC 4566), limited to what locates the media streams of a SIP session:
//! connection lines (`c=`), media lines (`m=`), codec names (`a=rtpmap:`) and the direction
//! attributes (`a=sendrecv`, `sendonly`, `recvonly`, `inactive`). Everything else is skipped.
//!
//! Bounded: at most [`MAX_BODY`] bytes read, [`MAX_MEDIA`] media and [`MAX_CODECS`] codecs per
//! media kept, short fields cut to [`MAX_TOKEN`] bytes.

use std::net::IpAddr;

use crate::sip::field;

/// Bytes of a body read.
pub const MAX_BODY: usize = 8 * 1024;
/// Media descriptions kept; the following ones set [`Sdp::media_truncated`].
pub const MAX_MEDIA: usize = 8;
/// Codec names kept per media.
pub const MAX_CODECS: usize = 16;
/// Longest media type, protocol or codec name kept, in bytes.
pub const MAX_TOKEN: usize = 32;
/// Payload formats of one `m=` line looked at.
const MAX_FORMATS: usize = 32;

/// Direction attribute of a media (RFC 4566 section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaDirection {
    SendRecv,
    SendOnly,
    RecvOnly,
    Inactive,
}

impl MediaDirection {
    /// Attribute name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SendRecv => "sendrecv",
            Self::SendOnly => "sendonly",
            Self::RecvOnly => "recvonly",
            Self::Inactive => "inactive",
        }
    }

    fn of_attribute(a: &str) -> Option<Self> {
        match a {
            "sendrecv" => Some(Self::SendRecv),
            "sendonly" => Some(Self::SendOnly),
            "recvonly" => Some(Self::RecvOnly),
            "inactive" => Some(Self::Inactive),
            _ => None,
        }
    }
}

/// One `m=` description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdpMedia {
    /// `audio`, `video`, `image`, `application`... (lower case).
    pub media: String,
    /// Transport port; 0 marks a refused media.
    pub port: u16,
    /// `RTP/AVP`, `RTP/SAVP`, `udptl`...
    pub proto: String,
    /// Media-level `c=` address, when present.
    pub connection: Option<IpAddr>,
    /// Codec names of the listed payload formats (`a=rtpmap`, else the static RTP/AVP types of
    /// RFC 3551), in the order of the `m=` line, deduplicated.
    pub codecs: Vec<String>,
    /// Media-level direction, else the session-level one.
    pub direction: Option<MediaDirection>,
}

/// The useful part of an SDP body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sdp {
    /// Session-level `c=` address.
    pub connection: Option<IpAddr>,
    pub media: Vec<SdpMedia>,
    /// More than [`MAX_MEDIA`] media descriptions.
    pub media_truncated: bool,
}

impl Sdp {
    /// Address of a media: its own `c=`, else the session's.
    pub fn address(&self, media: &SdpMedia) -> Option<IpAddr> {
        media.connection.or(self.connection)
    }
}

/// Media being read, with its formats and their `rtpmap` names.
struct Pending {
    media: SdpMedia,
    formats: Vec<u16>,
    rtpmap: Vec<(u16, String)>,
}

impl Pending {
    fn finish(mut self, session_direction: Option<MediaDirection>) -> SdpMedia {
        for f in &self.formats {
            if self.media.codecs.len() >= MAX_CODECS {
                break;
            }
            let name = self
                .rtpmap
                .iter()
                .find(|(pt, _)| pt == f)
                .map(|(_, n)| n.clone())
                .or_else(|| static_payload(*f).map(str::to_owned));
            if let Some(name) = name
                && !self.media.codecs.contains(&name)
            {
                self.media.codecs.push(name);
            }
        }
        self.media.direction = self.media.direction.or(session_direction);
        self.media
    }
}

/// Reads the connection and media lines of an SDP body. `None` when it holds no `c=` nor `m=`
/// line (not SDP).
pub fn parse(body: &[u8]) -> Option<Sdp> {
    let body = body.get(..body.len().min(MAX_BODY)).unwrap_or(body);
    let mut sdp = Sdp {
        connection: None,
        media: Vec::new(),
        media_truncated: false,
    };
    let mut session_direction = None;
    let mut current: Option<Pending> = None;
    let mut seen = false;
    for line in body.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(text) = std::str::from_utf8(line).ok() else {
            continue;
        };
        let Some((kind, value)) = text.split_once('=') else {
            continue;
        };
        match kind {
            "m" => {
                seen = true;
                if let Some(p) = current.take() {
                    sdp.media.push(p.finish(session_direction));
                }
                if sdp.media.len() >= MAX_MEDIA {
                    sdp.media_truncated = true;
                    continue;
                }
                current = media_line(value);
            }
            "c" => {
                seen = true;
                let addr = connection_line(value);
                match current.as_mut() {
                    Some(p) => p.media.connection = p.media.connection.or(addr),
                    None if sdp.media.is_empty() && !sdp.media_truncated => {
                        sdp.connection = sdp.connection.or(addr);
                    }
                    None => {}
                }
            }
            "a" => {
                let (name, arg) = value.split_once(':').unwrap_or((value, ""));
                let name = name.trim();
                if let Some(d) = MediaDirection::of_attribute(name) {
                    match current.as_mut() {
                        Some(p) => p.media.direction = p.media.direction.or(Some(d)),
                        None if sdp.media.is_empty() => {
                            session_direction = session_direction.or(Some(d));
                        }
                        None => {}
                    }
                } else if name.eq_ignore_ascii_case("rtpmap")
                    && let Some(p) = current.as_mut()
                    && p.rtpmap.len() < MAX_FORMATS
                    && let Some(entry) = rtpmap(arg)
                {
                    p.rtpmap.push(entry);
                }
            }
            _ => {}
        }
    }
    if let Some(p) = current.take() {
        sdp.media.push(p.finish(session_direction));
    }
    seen.then_some(sdp)
}

/// `<media> <port>[/<count>] <proto> <fmt> ...`.
fn media_line(value: &str) -> Option<Pending> {
    let mut parts = value.split_ascii_whitespace();
    let media = field(parts.next()?.as_bytes(), MAX_TOKEN)?.to_ascii_lowercase();
    let port = parts.next()?.split('/').next()?.parse::<u16>().ok()?;
    let proto = field(parts.next()?.as_bytes(), MAX_TOKEN)?;
    let formats = parts
        .take(MAX_FORMATS)
        .filter_map(|f| f.parse::<u16>().ok())
        .collect();
    Some(Pending {
        media: SdpMedia {
            media,
            port,
            proto,
            connection: None,
            codecs: Vec::new(),
            direction: None,
        },
        formats,
        rtpmap: Vec::new(),
    })
}

/// `IN IP4 <address>[/<ttl>[/<count>]]` or `IN IP6 <address>[/<count>]`.
fn connection_line(value: &str) -> Option<IpAddr> {
    let mut parts = value.split_ascii_whitespace();
    if !parts.next()?.eq_ignore_ascii_case("IN") {
        return None;
    }
    let family = parts.next()?;
    let addr: IpAddr = parts.next()?.split('/').next()?.parse().ok()?;
    let matches = match addr {
        IpAddr::V4(_) => family.eq_ignore_ascii_case("IP4"),
        IpAddr::V6(_) => family.eq_ignore_ascii_case("IP6"),
    };
    matches.then_some(addr)
}

/// `<payload type> <encoding name>/<clock rate>[/<params>]`.
fn rtpmap(arg: &str) -> Option<(u16, String)> {
    let mut parts = arg.split_ascii_whitespace();
    let pt = parts.next()?.parse::<u16>().ok()?;
    let name = parts.next()?.split('/').next()?;
    Some((pt, field(name.as_bytes(), MAX_TOKEN)?))
}

/// Static RTP/AVP payload types (RFC 3551, table 4), the usual audio ones.
fn static_payload(pt: u16) -> Option<&'static str> {
    Some(match pt {
        0 => "PCMU",
        3 => "GSM",
        4 => "G723",
        8 => "PCMA",
        9 => "G722",
        13 => "CN",
        18 => "G729",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    #[test]
    fn reads_connection_media_codecs_and_direction() {
        let body = b"v=0\r\no=alice 2890844526 2890844526 IN IP4 192.0.2.10\r\ns=-\r\n\
            c=IN IP4 192.0.2.10\r\nt=0 0\r\na=sendrecv\r\n\
            m=audio 49170 RTP/AVP 0 8 101\r\na=rtpmap:101 telephone-event/8000\r\n\
            m=video 51372 RTP/AVP 96\r\nc=IN IP6 2001:db8::5\r\na=rtpmap:96 H264/90000\r\n\
            a=recvonly\r\n";
        let sdp = parse(body).unwrap();
        assert_eq!(sdp.connection, Some("192.0.2.10".parse().unwrap()));
        assert_eq!(sdp.media.len(), 2);
        let audio = &sdp.media[0];
        assert_eq!((audio.media.as_str(), audio.port), ("audio", 49170));
        assert_eq!(audio.proto, "RTP/AVP");
        assert_eq!(audio.codecs, ["PCMU", "PCMA", "telephone-event"]);
        assert_eq!(audio.direction, Some(MediaDirection::SendRecv));
        assert_eq!(sdp.address(audio), Some("192.0.2.10".parse().unwrap()));
        let video = &sdp.media[1];
        assert_eq!(video.codecs, ["H264"]);
        assert_eq!(video.direction, Some(MediaDirection::RecvOnly));
        assert_eq!(sdp.address(video), Some("2001:db8::5".parse().unwrap()));
    }

    #[test]
    fn tolerates_lf_multicast_and_bad_lines() {
        let body = b"c=IN IP4 233.252.0.1/127/3\nm=audio 0/2 RTP/AVP 18\nm=audio x RTP/AVP\nc=IN IP4 nope\n\xff\xfe\n";
        let sdp = parse(body).unwrap();
        assert_eq!(sdp.connection, Some("233.252.0.1".parse().unwrap()));
        assert_eq!(sdp.media.len(), 1);
        assert_eq!(sdp.media[0].port, 0);
        assert_eq!(sdp.media[0].codecs, ["G729"]);
        // Family mismatch.
        assert!(parse(b"c=IN IP6 192.0.2.1\n").unwrap().connection.is_none());
        assert!(parse(b"hello world").is_none());
    }

    #[test]
    fn bounds_media_and_codecs() {
        let mut body = String::from("c=IN IP4 192.0.2.1\n");
        for i in 0..20 {
            let _ = write!(body, "m=audio {} RTP/AVP", 10_000 + i);
            for pt in 96..127 {
                let _ = write!(body, " {pt}");
            }
            body.push('\n');
            for pt in 96..127 {
                let _ = writeln!(body, "a=rtpmap:{pt} codec{pt}/8000");
            }
        }
        let sdp = parse(body.as_bytes()).unwrap();
        assert!(sdp.media.len() <= MAX_MEDIA);
        assert!(sdp.media.iter().all(|m| m.codecs.len() <= MAX_CODECS));
    }
}
