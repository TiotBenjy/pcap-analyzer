//! Input planning: inventory of a file or folder, grouping into chunk sets, group selection.

use std::fmt;
use std::path::{Path, PathBuf};

use netsift_capture::chunkset::{
    self, ChunkGroup, GroupKind, Grouping, Inventory, InventoryOptions,
};

use crate::error::EngineError;

/// Which chunk set of the input is imported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GroupSelection {
    /// The only group; an input holding several groups is refused with
    /// [`EngineError::MultipleGroups`] (which lists them).
    #[default]
    Single,
    /// The group at this index of [`InputPlan::groups`].
    Index(usize),
    /// Every group, merged into one session (ordered by timestamp).
    MergeAll,
}

/// One candidate chunk set, as shown to the user before choosing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSummary {
    pub index: usize,
    pub label: String,
    /// Naming convention that recognized the group (`dumpcap`, `tcpdump`, `folder`...).
    pub kind: &'static str,
    /// Files read by an import (duplicates and unreadable files excluded).
    pub files: usize,
    /// Total size of these files.
    pub bytes: u64,
    /// First packet time of the group, when known.
    pub first_ts: Option<i64>,
}

impl fmt::Display for GroupSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} ({}, {} file(s), {} bytes)",
            self.index, self.label, self.kind, self.files, self.bytes
        )
    }
}

/// Stable name of a group kind.
pub fn kind_name(kind: GroupKind) -> &'static str {
    match kind {
        GroupKind::Dumpcap => "dumpcap",
        GroupKind::DumpcapNameTimeNum => "dumpcap_nametimenum",
        GroupKind::TcpdumpRotation => "tcpdump",
        GroupKind::CommonPrefix => "common_prefix",
        GroupKind::Folder => "folder",
        GroupKind::Merged => "merged",
    }
}

fn summary(index: usize, group: &ChunkGroup) -> GroupSummary {
    GroupSummary {
        index,
        label: group.label.clone(),
        kind: kind_name(group.kind),
        files: group.active().count(),
        bytes: group.total_bytes(),
        first_ts: group.active().filter_map(|(_, m)| m.entry.first_ts()).min(),
    }
}

/// Result of [`plan_input`]: what the input contains, before any session is created.
#[derive(Debug, Clone)]
pub struct InputPlan {
    /// Canonical (absolute) path of the input.
    pub root: PathBuf,
    pub inventory: Inventory,
    pub grouping: Grouping,
}

/// Inventories `path` (a capture file or a folder) and groups its files into chunk sets.
pub fn plan_input(path: &Path, recursive: bool) -> Result<InputPlan, EngineError> {
    let input_err = |source| EngineError::Input {
        path: path.to_path_buf(),
        source,
    };
    let root = std::fs::canonicalize(path).map_err(|e| {
        input_err(chunkset::ChunkSetError::Io {
            path: path.to_path_buf(),
            source: e,
        })
    })?;
    let options = InventoryOptions {
        recursive,
        ..InventoryOptions::default()
    };
    let inventory = chunkset::inventory(&root, &options).map_err(input_err)?;
    let grouping = chunkset::group(&inventory);
    Ok(InputPlan {
        root,
        inventory,
        grouping,
    })
}

impl InputPlan {
    /// Candidate chunk sets, in the order expected by [`GroupSelection::Index`].
    pub fn groups(&self) -> Vec<GroupSummary> {
        self.grouping
            .groups
            .iter()
            .enumerate()
            .map(|(i, g)| summary(i, g))
            .collect()
    }

    /// The chunk set to import.
    pub fn select(&self, selection: GroupSelection) -> Result<ChunkGroup, EngineError> {
        let groups = &self.grouping.groups;
        if groups.is_empty() {
            return Err(EngineError::NoCapture {
                path: self.root.clone(),
                rejected: self.inventory.rejected().count(),
            });
        }
        match selection {
            GroupSelection::Single => match groups.as_slice() {
                [only] => Ok(only.clone()),
                _ => Err(EngineError::MultipleGroups {
                    path: self.root.clone(),
                    groups: self.groups(),
                }),
            },
            GroupSelection::Index(index) => {
                groups
                    .get(index)
                    .cloned()
                    .ok_or_else(|| EngineError::GroupOutOfRange {
                        path: self.root.clone(),
                        index,
                        groups: self.groups(),
                    })
            }
            GroupSelection::MergeAll => match groups.as_slice() {
                // A single set keeps its sequence numbers (merging drops them).
                [only] => Ok(only.clone()),
                _ => Ok(ChunkGroup::merge(groups.clone())),
            },
        }
    }
}
