//! `netsift export pcap`: write a session, a time range or one flow to a pcapng file, with the
//! same engine code as the "Save PCAP" action of the application.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use netsift_engine::{CancelToken, ExportError, ExportSelection, plan_export};
use netsift_store::{Catalog, OpenMode, SessionId, SessionState};

#[derive(Debug, Subcommand)]
pub enum ExportCommand {
    /// Write packets of a session to a pcapng file.
    Pcap(PcapArgs),
}

#[derive(Debug, Args)]
pub struct PcapArgs {
    /// Data directory (catalog and sessions).
    #[arg(long, default_value = ".data")]
    pub data_dir: PathBuf,
    /// Session id (see the catalog or the application).
    #[arg(long)]
    pub session: String,
    /// Export one flow (`flows.id`).
    #[arg(long, conflicts_with_all = ["from_ns", "to_ns"])]
    pub flow: Option<u64>,
    /// Start of a time range, nanoseconds since the Unix epoch (inclusive).
    #[arg(long, requires = "to_ns")]
    pub from_ns: Option<i64>,
    /// End of a time range, nanoseconds since the Unix epoch (inclusive).
    #[arg(long, requires = "from_ns")]
    pub to_ns: Option<i64>,
    /// File to write; never overwritten.
    #[arg(long, short)]
    pub output: PathBuf,
}

impl PcapArgs {
    fn selection(&self) -> ExportSelection {
        match (self.flow, self.from_ns, self.to_ns) {
            (Some(id), _, _) => ExportSelection::Flow { id },
            (None, Some(from_ns), Some(to_ns)) => ExportSelection::Range { from_ns, to_ns },
            _ => ExportSelection::Session,
        }
    }
}

/// Runs the export; the report goes to `out`.
pub fn run(command: &ExportCommand, cancel: &CancelToken, out: &mut dyn Write) -> Result<ExitCode> {
    let ExportCommand::Pcap(args) = command;
    let id: SessionId = args.session.parse().context("invalid session id")?;
    let catalog = Catalog::open(&args.data_dir)
        .with_context(|| format!("cannot open the catalog in {}", args.data_dir.display()))?;
    let info = catalog
        .get(&id)?
        .with_context(|| format!("session {id} does not exist"))?;
    match info.state {
        SessionState::Ready | SessionState::Incomplete => {}
        SessionState::Importing => bail!("session {id} is still being imported"),
        SessionState::Failed => bail!("the import of session {id} failed"),
    }
    let session = catalog
        .open_session(&id, OpenMode::ReadOnly)
        .with_context(|| format!("cannot open session {id}"))?;
    let plan = plan_export(&session, &args.selection())?;
    drop(session);
    match plan.run(&args.output, cancel, &mut |_| {}) {
        Ok(report) => {
            writeln!(
                out,
                "{}: {} packets, {} bytes, {} source file(s) read",
                args.output.display(),
                report.packets,
                report.bytes_written,
                report.chunks_read
            )?;
            if report.read_errors > 0 {
                writeln!(
                    out,
                    "warning: {} read error(s) in the sources: packets may be missing",
                    report.read_errors
                )?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(ExportError::Cancelled) => Ok(ExitCode::from(crate::ingest::EXIT_INCOMPLETE)),
        Err(e) => Err(e.into()),
    }
}
