//! `netsift ingest`: import a capture file or a folder of chunks into a data directory.

use std::fmt::Write as _;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Args;
use netsift_engine::{
    CancelToken, GroupSelection, IngestOptions, IngestReport, Phase, Progress, ingest,
};
use netsift_store::{Catalog, SessionState};

/// Exit code of an import cancelled by the user (session kept, marked incomplete).
pub const EXIT_INCOMPLETE: u8 = 130;

#[derive(Debug, Args)]
pub struct IngestArgs {
    /// Capture file, or folder of chunk files.
    pub input: PathBuf,
    /// Data directory (catalog and sessions); created if needed.
    #[arg(long)]
    pub out: PathBuf,
    /// Session name (default: chunk set label).
    #[arg(long)]
    pub name: Option<String>,
    /// Number of flow shards (default: cores - 2, at least 1).
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..=256))]
    pub shards: Option<u16>,
    /// Chunk set to import when the folder holds several (index from the listing).
    #[arg(long, conflicts_with = "merge_all")]
    pub group: Option<usize>,
    /// Import every chunk set of the folder as one session.
    #[arg(long)]
    pub merge_all: bool,
    /// Include sub-directories.
    #[arg(long)]
    pub recursive: bool,
}

impl IngestArgs {
    fn options(&self) -> IngestOptions {
        let selection = match (self.group, self.merge_all) {
            (Some(i), _) => GroupSelection::Index(i),
            (None, true) => GroupSelection::MergeAll,
            (None, false) => GroupSelection::Single,
        };
        IngestOptions {
            name: self.name.clone(),
            selection,
            recursive: self.recursive,
            shards: self.shards.map(usize::from),
            ..IngestOptions::default()
        }
    }
}

/// Runs the import; progress goes to `err`, the final report to `out`.
pub fn run(
    args: &IngestArgs,
    cancel: &CancelToken,
    interactive: bool,
    err: &mut dyn Write,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    std::fs::create_dir_all(&args.out)
        .with_context(|| format!("cannot create data directory {}", args.out.display()))?;
    let catalog = Catalog::open(&args.out)
        .with_context(|| format!("cannot open the catalog in {}", args.out.display()))?;
    let mut printer = ProgressPrinter::new(interactive);
    let result = ingest(
        &catalog,
        &args.input,
        &args.options(),
        cancel,
        &mut |p: &Progress| printer.print(err, p),
    );
    printer.end(err);
    let report = result?;
    write_report(out, &report, &args.out)?;
    Ok(match report.state {
        SessionState::Incomplete => ExitCode::from(EXIT_INCOMPLETE),
        _ => ExitCode::SUCCESS,
    })
}

/// Progress on stderr: one rewritten line on a terminal, a line every few seconds otherwise.
struct ProgressPrinter {
    interactive: bool,
    last: Option<Instant>,
    line_open: bool,
}

impl ProgressPrinter {
    fn new(interactive: bool) -> Self {
        Self {
            interactive,
            last: None,
            line_open: false,
        }
    }

    fn print(&mut self, w: &mut dyn Write, p: &Progress) {
        let every = if self.interactive {
            Duration::ZERO
        } else {
            Duration::from_secs(5)
        };
        let due = self.last.is_none_or(|t| t.elapsed() >= every);
        if p.phase == Phase::Reading && !due {
            return;
        }
        self.last = Some(Instant::now());
        let line = progress_line(p);
        // Progress output is best effort: a closed stderr must not fail the import.
        if self.interactive {
            let _ = write!(w, "\r\x1b[2K{line}");
            self.line_open = true;
        } else {
            let _ = writeln!(w, "{line}");
        }
        let _ = w.flush();
    }

    fn end(&mut self, w: &mut dyn Write) {
        if self.line_open {
            let _ = writeln!(w);
            self.line_open = false;
        }
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn progress_line(p: &Progress) -> String {
    let phase = match p.phase {
        Phase::Reading => "reading",
        Phase::Finishing => "finishing",
        Phase::Done => "done",
    };
    let mut line = format!(
        "{phase:<9} {:5.1}%  {} / {}  {} packets  {}/s",
        p.fraction() * 100.0,
        human_bytes(p.bytes_read),
        human_bytes(p.bytes_total),
        p.packets,
        human_bytes(p.bytes_per_sec() as u64),
    );
    if let (Some(chunk), Some(name)) = (p.chunk, &p.chunk_name) {
        let _ = write!(line, "  chunk {}/{} {name}", chunk + 1, p.chunks_total);
    }
    if let Some(eta) = p.eta() {
        let _ = write!(line, "  eta {}", human_duration(eta));
    }
    line
}

fn write_report(w: &mut dyn Write, r: &IngestReport, data_dir: &std::path::Path) -> Result<()> {
    let anomalies = if r.anomaly_kinds.is_empty() {
        r.anomalies.to_string()
    } else {
        let kinds: Vec<String> = r
            .anomaly_kinds
            .iter()
            .map(|(k, n)| format!("{k} {n}"))
            .collect();
        format!("{} ({})", r.anomalies, kinds.join(", "))
    };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let throughput = human_bytes(r.bytes_per_sec() as u64);
    let rejected = r.writer.total_rejected();
    let lines = [
        ("session", format!("{} ({})", r.session, r.name)),
        ("state", r.state.as_str().to_owned()),
        ("group", r.group.clone()),
        (
            "chunks",
            format!("{} read, {} listed", r.chunks_read, r.chunks),
        ),
        ("anomalies", anomalies),
        ("packets", r.packets.to_string()),
        ("bytes", human_bytes(r.bytes_read)),
        ("flows", r.flows.to_string()),
        ("hosts", r.hosts.to_string()),
        ("shards", r.shards.to_string()),
        ("duration", human_duration(r.duration)),
        ("throughput", format!("{throughput}/s")),
        (
            "rows",
            format!("{} written, {rejected} rejected", r.writer.total_rows()),
        ),
        ("data dir", data_dir.display().to_string()),
    ];
    for (k, v) in lines {
        writeln!(w, "{k:<11} {v}")?;
    }
    Ok(())
}

#[allow(clippy::cast_precision_loss)]
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    let name = UNITS.get(unit).copied().unwrap_or("B");
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {name}")
    }
}

fn human_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 3600 {
        format!("{}h{:02}m{:02}s", secs / 3600, secs % 3600 / 60, secs % 60)
    } else if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{:.2} s", d.as_secs_f64())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024 * 1024), "5.0 GiB");
        assert_eq!(human_duration(Duration::from_millis(1500)), "1.50 s");
        assert_eq!(human_duration(Duration::from_secs(125)), "2m05s");
        assert_eq!(human_duration(Duration::from_secs(3725)), "1h02m05s");
    }

    #[test]
    fn progress_line_mentions_chunk_and_rate() {
        let p = Progress {
            phase: Phase::Reading,
            bytes_read: 512,
            bytes_total: 1024,
            packets: 10,
            chunk: Some(1),
            chunk_name: Some("cap_00002_20231114221320.pcapng".into()),
            chunks_total: 3,
            elapsed: Duration::from_secs(1),
        };
        let line = progress_line(&p);
        assert!(line.contains(" 50.0%"), "{line}");
        assert!(line.contains("chunk 2/3 cap_00002"), "{line}");
        assert!(line.contains("512 B/s"), "{line}");
        assert!(line.contains("eta 1.00 s"), "{line}");
    }
}
