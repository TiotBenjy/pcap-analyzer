//! TLS record layer of one direction of a TCP stream (RFC 8446 5.1, RFC 5246 6.2).
//!
//! Records may be split over several segments and several records may share a segment: the
//! parser keeps at most one incomplete record header or plaintext record body. Encrypted
//! records (application data, handshake after `ChangeCipherSpec`) are skipped without being
//! buffered. Handshake messages may span several records: they are reassembled up to a bound.

/// Largest record body allowed by the specifications (2^14 + 2048, `TLSCiphertext`).
pub const MAX_RECORD_BODY: usize = 16_384 + 2_048;
const HEADER: usize = 5;

const CHANGE_CIPHER_SPEC: u8 = 20;
const ALERT: u8 = 21;
const HANDSHAKE: u8 = 22;
const APPLICATION_DATA: u8 = 23;
const HEARTBEAT: u8 = 24;

/// What a direction of the stream carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A complete plaintext handshake message (4-byte header included).
    Handshake(Vec<u8>),
    ChangeCipherSpec,
    /// A plaintext alert: level, description.
    Alert(u8, u8),
    ApplicationData,
}

/// Record parser of one direction.
#[derive(Debug, Default)]
pub struct DirParser {
    /// Incomplete record: header, then body (plaintext records only).
    buf: Vec<u8>,
    /// Body bytes left to skip of the current encrypted record.
    skip: usize,
    /// Pending handshake bytes (messages spanning records).
    hs: Vec<u8>,
    /// `ChangeCipherSpec` seen: later handshake records are encrypted.
    pub encrypted: bool,
    /// The stream is not TLS anymore (bad header) or has a gap: nothing more is parsed.
    pub broken: bool,
    /// Handshake reassembly gave up (message above the bound).
    pub hs_broken: bool,
}

impl DirParser {
    /// Bytes held in memory.
    pub fn buffered(&self) -> usize {
        self.buf.capacity() + self.hs.capacity()
    }

    /// Stops parsing and releases the buffers.
    pub fn abandon(&mut self) {
        self.broken = true;
        self.buf = Vec::new();
        self.hs = Vec::new();
    }

    /// Parses `data`, appending what it carried to `events`. Handshake messages longer than
    /// `max_message` bytes stop the handshake reassembly of this direction.
    pub fn feed(&mut self, mut data: &[u8], max_message: usize, events: &mut Vec<Event>) {
        while !data.is_empty() && !self.broken {
            if self.skip > 0 {
                let n = self.skip.min(data.len());
                self.skip -= n;
                data = data.get(n..).unwrap_or_default();
                continue;
            }
            if self.buf.len() < HEADER {
                let n = (HEADER - self.buf.len()).min(data.len());
                self.buf
                    .extend_from_slice(data.get(..n).unwrap_or_default());
                data = data.get(n..).unwrap_or_default();
                if self.buf.len() < HEADER {
                    break;
                }
            }
            let Some(&[kind, major, minor, hi, lo]) = self.buf.first_chunk::<HEADER>() else {
                break;
            };
            let len = usize::from(u16::from_be_bytes([hi, lo]));
            if !(CHANGE_CIPHER_SPEC..=HEARTBEAT).contains(&kind)
                || major != 3
                || minor > 4
                || len > MAX_RECORD_BODY
            {
                self.abandon();
                break;
            }
            let opaque = kind == APPLICATION_DATA
                || kind == HEARTBEAT
                || (kind == HANDSHAKE && (self.encrypted || self.hs_broken));
            if opaque {
                if kind == APPLICATION_DATA {
                    events.push(Event::ApplicationData);
                }
                self.buf.clear();
                self.skip = len;
                continue;
            }
            let need = HEADER + len - self.buf.len();
            let n = need.min(data.len());
            self.buf
                .extend_from_slice(data.get(..n).unwrap_or_default());
            data = data.get(n..).unwrap_or_default();
            if self.buf.len() < HEADER + len {
                break;
            }
            let body = std::mem::take(&mut self.buf);
            self.record(
                kind,
                body.get(HEADER..).unwrap_or_default(),
                max_message,
                events,
            );
            // Keep the allocation for the next record.
            self.buf = body;
            self.buf.clear();
        }
    }

    fn record(&mut self, kind: u8, body: &[u8], max_message: usize, events: &mut Vec<Event>) {
        match kind {
            CHANGE_CIPHER_SPEC => {
                self.encrypted = true;
                events.push(Event::ChangeCipherSpec);
            }
            ALERT => {
                if let [level, description] = *body {
                    events.push(Event::Alert(level, description));
                }
            }
            HANDSHAKE => self.handshake(body, max_message, events),
            _ => {}
        }
    }

    fn handshake(&mut self, body: &[u8], max_message: usize, events: &mut Vec<Event>) {
        self.hs.extend_from_slice(body);
        while let Some(&[_, a, b, c]) = self.hs.first_chunk::<4>() {
            let len = usize::try_from(u32::from_be_bytes([0, a, b, c])).unwrap_or(usize::MAX);
            if len > max_message {
                self.hs_broken = true;
                self.hs = Vec::new();
                return;
            }
            let total = 4 + len;
            if self.hs.len() < total {
                return;
            }
            let rest = self.hs.split_off(total);
            events.push(Event::Handshake(std::mem::replace(&mut self.hs, rest)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![kind, 3, 3];
        out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![kind];
        out.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
        out.extend_from_slice(body);
        out
    }

    fn run(chunks: &[&[u8]]) -> (DirParser, Vec<Event>) {
        let mut p = DirParser::default();
        let mut events = Vec::new();
        for c in chunks {
            p.feed(c, 1024, &mut events);
        }
        (p, events)
    }

    #[test]
    fn records_split_and_coalesced_byte_by_byte() {
        let hello = handshake(1, &[7; 40]);
        let mut stream = record(HANDSHAKE, &hello);
        stream.extend(record(CHANGE_CIPHER_SPEC, &[1]));
        stream.extend(record(APPLICATION_DATA, &[0xee; 300]));
        stream.extend(record(ALERT, &[2, 40]));
        let expected = vec![
            Event::Handshake(hello),
            Event::ChangeCipherSpec,
            Event::ApplicationData,
            Event::Alert(2, 40),
        ];
        let (_, all) = run(&[&stream]);
        assert_eq!(all, expected);
        let bytes: Vec<&[u8]> = stream.chunks(1).collect();
        let (p, split) = run(&bytes);
        assert_eq!(split, expected);
        assert!(p.encrypted && !p.broken);
    }

    #[test]
    fn handshake_messages_span_records_and_share_them() {
        let a = handshake(2, &[1; 30]);
        let b = handshake(11, &[2; 50]);
        let both = [a.clone(), b.clone()].concat();
        let (first, second) = both.split_at(45);
        let stream = [record(HANDSHAKE, first), record(HANDSHAKE, second)].concat();
        let (_, events) = run(&[&stream]);
        assert_eq!(events, vec![Event::Handshake(a), Event::Handshake(b)]);
    }

    #[test]
    fn encrypted_handshake_records_are_skipped() {
        let stream = [
            record(CHANGE_CIPHER_SPEC, &[1]),
            record(HANDSHAKE, &handshake(20, &[0; 12])),
            record(ALERT, &[0xab; 26]),
        ]
        .concat();
        let (_, events) = run(&[&stream]);
        assert_eq!(events, vec![Event::ChangeCipherSpec]);
    }

    #[test]
    fn hostile_headers_and_lengths() {
        // Not TLS at all.
        let (p, events) = run(&[b"GET / HTTP/1.1\r\n\r\n"]);
        assert!(p.broken && events.is_empty());
        // Record above the maximum size.
        let mut big = vec![HANDSHAKE, 3, 3];
        big.extend_from_slice(&u16::MAX.to_be_bytes());
        let (p, _) = run(&[&big]);
        assert!(p.broken);
        // Unknown record version.
        let (p, _) = run(&[&[HANDSHAKE, 2, 0, 0, 1, 0]]);
        assert!(p.broken);
        // Handshake message longer than the bound: reassembly stops, records still parsed.
        let stream = [
            record(HANDSHAKE, &[11, 0xff, 0xff, 0xff, 1, 2, 3]),
            record(APPLICATION_DATA, &[1]),
        ]
        .concat();
        let (p, events) = run(&[&stream]);
        assert!(p.hs_broken && !p.broken);
        assert_eq!(events, vec![Event::ApplicationData]);
        // Truncated record: nothing emitted, at most one record buffered.
        let hello = record(HANDSHAKE, &handshake(1, &[0; 100]));
        let (p, events) = run(&[&hello[..50]]);
        assert!(events.is_empty() && !p.broken);
        assert!(p.buffered() <= MAX_RECORD_BODY + HEADER + 1024);
        // Malformed alerts are ignored.
        let (_, events) = run(&[&record(ALERT, &[2])]);
        assert_eq!(events, Vec::<Event>::new());
    }
}
