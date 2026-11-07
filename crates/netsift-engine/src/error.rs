//! Error type of the engine.

use std::fmt::Write as _;
use std::path::PathBuf;

use netsift_capture::chunkset::ChunkSetError;
use netsift_store::{SessionId, StoreError};

use crate::plan::GroupSummary;

/// Errors of [`crate::ingest`].
///
/// Input errors ([`EngineError::Input`], [`EngineError::NoCapture`],
/// [`EngineError::MultipleGroups`], [`EngineError::GroupOutOfRange`]) are detected before any
/// session is created. Once the session exists, a failure marks it `failed` in the catalog and
/// is reported as [`EngineError::ImportFailed`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EngineError {
    #[error("cannot read input {}: {source}", path.display())]
    Input {
        path: PathBuf,
        #[source]
        source: ChunkSetError,
    },
    #[error("no capture file found in {} ({rejected} file(s) not recognized)", path.display())]
    NoCapture { path: PathBuf, rejected: usize },
    #[error("{}", multiple_groups(path, groups))]
    MultipleGroups {
        path: PathBuf,
        groups: Vec<GroupSummary>,
    },
    #[error("group {index} does not exist: {} has {} group(s)", path.display(), groups.len())]
    GroupOutOfRange {
        path: PathBuf,
        index: usize,
        groups: Vec<GroupSummary>,
    },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("import of session {session} failed: {reason}")]
    ImportFailed { session: SessionId, reason: String },
}

fn multiple_groups(path: &std::path::Path, groups: &[GroupSummary]) -> String {
    let mut s = format!(
        "{} contains {} chunk sets; choose one group or merge them all:",
        path.display(),
        groups.len()
    );
    for g in groups {
        let _ = write!(s, "\n  {g}");
    }
    s
}
