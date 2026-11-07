//! Chunk splitter reproducing the rotation and naming of dumpcap, editcap and tcpdump.
//!
//! The timestamp embedded in dumpcap/editcap names is the UTC time of the first packet of
//! the chunk (the real tools use the local wall clock at file creation).

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use flate2::write::GzEncoder;
use flate2::{Compression, GzBuilder};

use crate::packet::Packet;
use crate::time::compact_timestamp;
use crate::writer::{
    Encoding, FileFormat, Interface, PcapNgWriter, PcapWriter, encode_with_interfaces, header_size,
    record_size, resolve_interfaces,
};

/// Rotation criterion.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SplitBy {
    /// New file before a packet that would make the current one exceed this many bytes
    /// (uncompressed size, headers included). A single oversized packet gets its own file.
    Size(u64),
    /// New file at the first packet at least this many nanoseconds after the first packet
    /// of the current file (dumpcap `-b duration:`, tcpdump `-G`).
    Duration(i64),
    /// Fixed number of packets per file (editcap `-c`).
    Packets(usize),
    /// New file starting at each of these packet indices (exact boundaries for tests).
    At(Vec<usize>),
}

/// File naming convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Naming {
    /// dumpcap default: `prefix_NNNNN_YYYYmmddHHMMSS.ext`, numbered from 1.
    Dumpcap,
    /// dumpcap `-b nametimenum:2`: `prefix_YYYYmmddHHMMSS_NNNNN.ext`, numbered from 1.
    DumpcapNameTimeNum,
    /// editcap `-c` / `-i`: `prefix_NNNNN_YYYYmmddHHMMSS.ext`, numbered from 0.
    Editcap,
    /// tcpdump `-C`: `prefix.ext`, then `prefix.ext1`, `prefix.ext2`, ...
    TcpdumpC,
}

impl Naming {
    fn default_start(self) -> u64 {
        match self {
            Self::Dumpcap | Self::DumpcapNameTimeNum | Self::TcpdumpC => 1,
            Self::Editcap => 0,
        }
    }
}

/// Splitter options.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SplitOptions {
    pub by: SplitBy,
    pub naming: Naming,
    pub prefix: String,
    /// Chunk `i` is encoded with `encodings[i % len]` (mixing pcap, pcapng and gzip in one
    /// set). Empty means pcapng.
    pub encodings: Vec<Encoding>,
    /// Extension without the dot; `None` derives it from the format (`pcap`/`pcapng`),
    /// `Some("")` writes no extension. `.gz` is always appended for compressed chunks.
    pub extension: Option<String>,
    /// First sequence number (dumpcap 1, editcap 0 by default). For tcpdump `-C`, the
    /// number of the second file (the first one has no number).
    pub start_number: Option<u64>,
}

impl SplitOptions {
    /// pcapng chunks named after `naming`, with the prefix `capture`.
    pub fn new(by: SplitBy, naming: Naming) -> Self {
        Self {
            by,
            naming,
            prefix: "capture".to_owned(),
            encodings: vec![Encoding::pcapng()],
            extension: None,
            start_number: None,
        }
    }

    #[must_use]
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    #[must_use]
    pub fn with_encoding(mut self, encoding: Encoding) -> Self {
        self.encodings = vec![encoding];
        self
    }

    #[must_use]
    pub fn with_encodings(mut self, encodings: Vec<Encoding>) -> Self {
        self.encodings = encodings;
        self
    }

    #[must_use]
    pub fn with_extension(mut self, extension: impl Into<String>) -> Self {
        self.extension = Some(extension.into());
        self
    }

    #[must_use]
    pub fn with_start_number(mut self, start: u64) -> Self {
        self.start_number = Some(start);
        self
    }
}

/// One planned chunk file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// Position in the set (0-based).
    pub index: usize,
    /// Sequence number embedded in the name (tcpdump `-C`: 0 for the unnumbered first file).
    pub number: u64,
    pub file_name: String,
    pub encoding: Encoding,
    /// pcapng interface blocks written in this chunk (all interfaces of the whole set).
    pub interfaces: Vec<Interface>,
    pub packets: Vec<Packet>,
}

impl Chunk {
    pub fn first_ts(&self) -> Option<i64> {
        self.packets.first().map(|p| p.ts_ns)
    }

    pub fn last_ts(&self) -> Option<i64> {
        self.packets.last().map(|p| p.ts_ns)
    }

    /// Uncompressed file size.
    pub fn raw_size(&self) -> u64 {
        header_size(&self.encoding.format, &self.interfaces)
            + self
                .packets
                .iter()
                .map(|p| record_size(&self.encoding.format, p))
                .sum::<u64>()
    }

    /// Bytes of the chunk file.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        encode_with_interfaces(&self.packets, &self.encoding, &self.interfaces)
    }
}

/// Encoding of one entry of the encoding cycle, with the interfaces it declares.
#[derive(Debug, Clone)]
struct Plan {
    encoding: Encoding,
    interfaces: Vec<Interface>,
    header: u64,
}

/// Rotation state machine shared by [`split`] and [`ChunkSink`].
#[derive(Debug)]
struct Rotator {
    by: SplitBy,
    cuts: BTreeSet<usize>,
    plans: Vec<Plan>,
    /// Index of the current chunk; `None` before the first packet.
    chunk: Option<usize>,
    seen: usize,
    first_ts: i64,
    count: usize,
    size: u64,
}

impl Rotator {
    /// `interfaces` is what pcapng chunks declare; `None` derives it from `all_packets`.
    fn new(opts: &SplitOptions, interfaces: Option<&[Interface]>, all_packets: &[Packet]) -> Self {
        match &opts.by {
            SplitBy::Size(n) => assert!(*n > 0, "chunk size must be positive"),
            SplitBy::Duration(d) => assert!(*d > 0, "chunk duration must be positive"),
            SplitBy::Packets(n) => assert!(*n > 0, "packets per chunk must be positive"),
            SplitBy::At(_) => {}
        }
        let cuts = match &opts.by {
            SplitBy::At(indices) => indices.iter().copied().collect(),
            _ => BTreeSet::new(),
        };
        let encodings = if opts.encodings.is_empty() {
            vec![Encoding::pcapng()]
        } else {
            opts.encodings.clone()
        };
        let plans = encodings
            .into_iter()
            .map(|encoding| {
                // Every chunk declares the interfaces of the whole set, like dumpcap does.
                let interfaces = match (&encoding.format, interfaces) {
                    (FileFormat::Pcap(_), _) => Vec::new(),
                    (FileFormat::PcapNg(_), Some(given)) => given.to_vec(),
                    (FileFormat::PcapNg(o), None) => resolve_interfaces(o, all_packets),
                };
                let header = header_size(&encoding.format, &interfaces);
                Plan {
                    encoding,
                    interfaces,
                    header,
                }
            })
            .collect();
        Self {
            by: opts.by.clone(),
            cuts,
            plans,
            chunk: None,
            seen: 0,
            first_ts: 0,
            count: 0,
            size: 0,
        }
    }

    fn plan(&self, chunk: usize) -> &Plan {
        &self.plans[chunk % self.plans.len()]
    }

    /// Accounts for `p`; returns `Some(index)` when `p` opens a new chunk.
    fn admit(&mut self, p: &Packet) -> Option<usize> {
        let index = self.seen;
        self.seen += 1;
        let next = match self.chunk {
            None => Some(0),
            Some(current) => {
                let format = &self.plan(current).encoding.format;
                let rotate = match &self.by {
                    SplitBy::Size(limit) => self.size + record_size(format, p) > *limit,
                    SplitBy::Duration(d) => p.ts_ns - self.first_ts >= *d,
                    SplitBy::Packets(n) => self.count >= *n,
                    SplitBy::At(_) => self.cuts.contains(&index),
                };
                rotate.then_some(current + 1)
            }
        };
        if let Some(chunk) = next {
            self.chunk = Some(chunk);
            self.first_ts = p.ts_ns;
            self.count = 0;
            self.size = self.plan(chunk).header;
        }
        let current = self.chunk.unwrap_or_default();
        self.size += record_size(&self.plan(current).encoding.format, p);
        self.count += 1;
        next
    }
}

fn chunk_number(opts: &SplitOptions, index: usize) -> u64 {
    let start = opts
        .start_number
        .unwrap_or_else(|| opts.naming.default_start());
    match opts.naming {
        Naming::TcpdumpC if index == 0 => 0,
        Naming::TcpdumpC => start + index as u64 - 1,
        _ => start + index as u64,
    }
}

/// Plans the chunks of `packets` (no I/O).
///
/// # Panics
/// If the criterion is degenerate (zero size, zero packets, non-positive duration).
pub fn split(packets: &[Packet], opts: &SplitOptions) -> Vec<Chunk> {
    let mut rotator = Rotator::new(opts, None, packets);
    let mut chunks: Vec<Chunk> = Vec::new();
    for p in packets {
        if let Some(index) = rotator.admit(p) {
            let plan = rotator.plan(index);
            let number = chunk_number(opts, index);
            chunks.push(Chunk {
                index,
                number,
                file_name: file_name(opts, &plan.encoding, index, number, p.ts_ns),
                encoding: plan.encoding.clone(),
                interfaces: plan.interfaces.clone(),
                packets: Vec::new(),
            });
        }
        if let Some(chunk) = chunks.last_mut() {
            chunk.packets.push(p.clone());
        }
    }
    chunks
}

fn file_name(opts: &SplitOptions, enc: &Encoding, index: usize, number: u64, ts_ns: i64) -> String {
    let ext = opts
        .extension
        .clone()
        .unwrap_or_else(|| enc.format.extension().to_owned());
    let dot_ext = if ext.is_empty() {
        String::new()
    } else {
        format!(".{ext}")
    };
    let gz = if enc.gzip { ".gz" } else { "" };
    let prefix = &opts.prefix;
    let ts = compact_timestamp(ts_ns);
    match opts.naming {
        Naming::Dumpcap | Naming::Editcap => format!("{prefix}_{number:05}_{ts}{dot_ext}{gz}"),
        Naming::DumpcapNameTimeNum => format!("{prefix}_{ts}_{number:05}{dot_ext}{gz}"),
        Naming::TcpdumpC if index == 0 => format!("{prefix}{dot_ext}{gz}"),
        Naming::TcpdumpC => format!("{prefix}{dot_ext}{number}{gz}"),
    }
}

/// Writes planned chunks into `dir` (created if needed); returns the paths in chunk order.
pub fn write_chunks(dir: &Path, chunks: &[Chunk]) -> io::Result<Vec<PathBuf>> {
    fs::create_dir_all(dir)?;
    chunks
        .iter()
        .map(|c| {
            let path = dir.join(&c.file_name);
            fs::write(&path, c.encode()?)?;
            Ok(path)
        })
        .collect()
}

/// [`split`] then [`write_chunks`].
pub fn split_to_dir(
    dir: &Path,
    packets: &[Packet],
    opts: &SplitOptions,
) -> io::Result<(Vec<Chunk>, Vec<PathBuf>)> {
    let chunks = split(packets, opts);
    let paths = write_chunks(dir, &chunks)?;
    Ok((chunks, paths))
}

/// Underlying file of a streamed chunk, optionally gzip-compressed.
enum FileSink {
    Plain(BufWriter<File>),
    Gz(GzEncoder<BufWriter<File>>),
}

impl FileSink {
    fn create(path: &Path, gzip: bool) -> io::Result<Self> {
        let file = BufWriter::new(File::create(path)?);
        Ok(if gzip {
            Self::Gz(
                GzBuilder::new()
                    .mtime(0)
                    .write(file, Compression::default()),
            )
        } else {
            Self::Plain(file)
        })
    }

    fn finish(self) -> io::Result<()> {
        match self {
            Self::Plain(mut w) => w.flush(),
            Self::Gz(gz) => gz.finish()?.flush(),
        }
    }
}

impl Write for FileSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(w) => w.write(buf),
            Self::Gz(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(w) => w.flush(),
            Self::Gz(w) => w.flush(),
        }
    }
}

enum OpenWriter {
    Pcap(PcapWriter<FileSink>),
    PcapNg(PcapNgWriter<FileSink>),
}

impl OpenWriter {
    fn write_packet(&mut self, p: &Packet) -> io::Result<u64> {
        match self {
            Self::Pcap(w) => w.write_packet(p),
            Self::PcapNg(w) => w.write_packet(p),
        }
    }

    fn finish(self) -> io::Result<()> {
        match self {
            Self::Pcap(w) => w.into_inner().finish(),
            Self::PcapNg(w) => w.into_inner().finish(),
        }
    }
}

/// Streaming counterpart of [`split_to_dir`]: packets are written as they are pushed, so
/// arbitrarily large sets can be produced in bounded memory. Rotation and naming are
/// identical to [`split`] given the same interfaces.
pub struct ChunkSink {
    dir: PathBuf,
    opts: SplitOptions,
    rotator: Rotator,
    open: Option<OpenWriter>,
    paths: Vec<PathBuf>,
}

impl ChunkSink {
    /// `interfaces` are declared by every pcapng chunk (one per `Packet::interface` value).
    pub fn new(dir: &Path, opts: &SplitOptions, interfaces: &[Interface]) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            opts: opts.clone(),
            rotator: Rotator::new(opts, Some(interfaces), &[]),
            open: None,
            paths: Vec::new(),
        })
    }

    pub fn push(&mut self, p: &Packet) -> io::Result<()> {
        if let Some(index) = self.rotator.admit(p) {
            if let Some(open) = self.open.take() {
                open.finish()?;
            }
            let plan = self.rotator.plan(index);
            let number = chunk_number(&self.opts, index);
            let path = self.dir.join(file_name(
                &self.opts,
                &plan.encoding,
                index,
                number,
                p.ts_ns,
            ));
            let sink = FileSink::create(&path, plan.encoding.gzip)?;
            self.open = Some(match &plan.encoding.format {
                FileFormat::Pcap(o) => OpenWriter::Pcap(PcapWriter::new(sink, *o, p.linktype)?),
                FileFormat::PcapNg(o) => {
                    OpenWriter::PcapNg(PcapNgWriter::new(sink, o.endian, plan.interfaces.clone())?)
                }
            });
            self.paths.push(path);
        }
        match self.open.as_mut() {
            Some(w) => w.write_packet(p).map(|_| ()),
            None => Err(io::Error::other("no open chunk")),
        }
    }

    /// Closes the last chunk; returns every written path in order.
    pub fn finish(mut self) -> io::Result<Vec<PathBuf>> {
        if let Some(open) = self.open.take() {
            open.finish()?;
        }
        Ok(self.paths)
    }
}
