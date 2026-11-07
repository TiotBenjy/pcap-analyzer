//! `netsift-fixtures`: writes synthetic captures (single file or chunk set) to a directory.

use std::io::Write as _;
use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

use netsift_fixtures::scenario::Scenario;
use netsift_fixtures::scenarios::Kind;
use netsift_fixtures::split::{ChunkSink, Naming, SplitBy, SplitOptions};
use netsift_fixtures::time::NS_PER_SEC;
use netsift_fixtures::writer::{Encoding, Interface};

#[derive(Debug, Parser)]
#[command(name = "netsift-fixtures", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a synthetic capture, optionally split into chunks.
    Gen(GenArgs),
}

#[derive(Debug, clap::Args)]
struct GenArgs {
    /// Output directory (created if needed).
    #[arg(long)]
    out: PathBuf,
    /// Scenario: demo, dns, http, tls, nbns, smb, snmp, ftp.
    #[arg(long, default_value = "demo", value_parser = parse_kind)]
    scenario: Kind,
    /// Number of rounds of the scenario, one second apart.
    #[arg(long, default_value_t = 1)]
    repeat: usize,
    /// Split criterion: `size=BYTES` (k/M/G suffixes, powers of 1000), `duration=SECONDS`,
    /// `packets=N`. Without it a single file is written.
    #[arg(long, value_parser = parse_split)]
    split: Option<SplitBy>,
    /// Chunk naming convention.
    #[arg(long, value_enum, default_value_t = NamingArg::Dumpcap)]
    naming: NamingArg,
    /// Container format.
    #[arg(long, value_enum, default_value_t = FormatArg::Pcapng)]
    format: FormatArg,
    /// Gzip-compress every file.
    #[arg(long)]
    gzip: bool,
    /// File name prefix.
    #[arg(long, default_value = "capture")]
    prefix: String,
    /// First chunk number (dumpcap: 1, editcap: 0 by default).
    #[arg(long)]
    start_number: Option<u64>,
    /// Generator seed (ports, sequence numbers, ids).
    #[arg(long, default_value_t = netsift_fixtures::scenario::DEFAULT_SEED)]
    seed: u64,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum NamingArg {
    Dumpcap,
    Nametimenum,
    Editcap,
    Tcpdump,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FormatArg {
    Pcap,
    PcapNs,
    Pcapng,
}

fn parse_kind(s: &str) -> Result<Kind, String> {
    Kind::from_name(s).ok_or_else(|| {
        let names: Vec<&str> = Kind::ALL.iter().map(|k| k.name()).collect();
        format!(
            "unknown scenario `{s}` (expected one of: {})",
            names.join(", ")
        )
    })
}

fn parse_split(s: &str) -> Result<SplitBy, String> {
    let (key, value) = s
        .split_once('=')
        .ok_or_else(|| "expected size=N, duration=S or packets=N".to_owned())?;
    match key {
        "size" => {
            let (digits, factor) = match value.chars().last() {
                Some('k' | 'K') => (&value[..value.len() - 1], 1_000),
                Some('M') => (&value[..value.len() - 1], 1_000_000),
                Some('G') => (&value[..value.len() - 1], 1_000_000_000),
                _ => (value, 1),
            };
            let n: u64 = digits.parse().map_err(|e| format!("invalid size: {e}"))?;
            Ok(SplitBy::Size(n.saturating_mul(factor).max(1)))
        }
        "duration" => {
            let secs: f64 = value
                .parse()
                .map_err(|e| format!("invalid duration: {e}"))?;
            if !(secs > 0.0 && secs < 1e9) {
                return Err("duration must be positive".to_owned());
            }
            #[allow(clippy::cast_possible_truncation)]
            let ns = (secs * 1e9).round() as i64;
            Ok(SplitBy::Duration(ns.max(1)))
        }
        "packets" => {
            let n: usize = value.parse().map_err(|e| format!("invalid count: {e}"))?;
            if n == 0 {
                return Err("packet count must be positive".to_owned());
            }
            Ok(SplitBy::Packets(n))
        }
        other => Err(format!("unknown split criterion `{other}`")),
    }
}

fn main() -> Result<()> {
    let Cli {
        command: Command::Gen(args),
    } = Cli::parse();
    gen_capture(&args)
}

fn gen_capture(args: &GenArgs) -> Result<()> {
    if args.repeat == 0 {
        bail!("--repeat must be at least 1");
    }
    let mut encoding = match args.format {
        FormatArg::Pcap => Encoding::pcap(),
        FormatArg::PcapNs => Encoding::pcap_ns(),
        FormatArg::Pcapng => Encoding::pcapng(),
    };
    encoding.gzip = args.gzip;
    let naming = match args.naming {
        NamingArg::Dumpcap => Naming::Dumpcap,
        NamingArg::Nametimenum => Naming::DumpcapNameTimeNum,
        NamingArg::Editcap => Naming::Editcap,
        NamingArg::Tcpdump => Naming::TcpdumpC,
    };
    // Without --split, everything goes into one file named `<prefix>.<ext>`.
    let (by, naming) = match &args.split {
        Some(by) => (by.clone(), naming),
        None => (SplitBy::Size(u64::MAX), Naming::TcpdumpC),
    };
    let mut opts = SplitOptions::new(by, naming)
        .with_prefix(args.prefix.clone())
        .with_encoding(encoding);
    opts.start_number = args.start_number;

    // Rounds are generated one at a time and streamed to disk: memory stays bounded.
    let mut sink = ChunkSink::new(&args.out, &opts, &[Interface::ethernet()])
        .with_context(|| format!("cannot create {}", args.out.display()))?;
    let mut sc = Scenario::new().with_seed(args.seed);
    let mut packets = 0u64;
    let mut bytes = 0u64;
    for round in 0..args.repeat {
        if round > 0 {
            sc.advance(NS_PER_SEC);
        }
        args.scenario.append_to(&mut sc);
        // The scenario keeps its clock, ports and generator state; written packets are dropped.
        for p in sc.take_packets() {
            sink.push(&p)?;
            packets += 1;
            bytes += p.data.len() as u64;
        }
    }
    let paths = sink.finish()?;

    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "{packets} packets, {bytes} frame bytes, {} file(s) in {}",
        paths.len(),
        args.out.display()
    )?;
    for path in &paths {
        if let Some(name) = path.file_name() {
            writeln!(stdout, "  {}", name.to_string_lossy())?;
        }
    }
    Ok(())
}
