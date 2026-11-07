//! SQLite session schema, migrations, batched writer and queries.
//!
//! - [`Catalog`]: `catalog.db`, the list of sessions of a data directory;
//! - [`Session`]: one `sessions/<id>/` directory (`session.db` in WAL mode, `blobs/`, `thumbs/`);
//! - [`schema`]: migration registries (registration point for analyzers, `NNNN_<name>.sql`);
//! - [`StoreWriter`]: single writer thread committing [`StoreRecord`]s in batches;
//! - [`query`]: base read queries and keyset pagination.

pub mod catalog;
mod error;
mod id;
pub mod migrate;
pub mod query;
pub mod records;
pub mod schema;
pub mod session;
mod time;
pub mod writer;

pub use catalog::{Catalog, SessionInfo, SessionState};
pub use error::{Result, StoreError};
pub use id::SessionId;
pub use query::{Keyset, Page, PageRequest, keyset_page};
pub use records::{
    AnomalyRow, ChunkFormat, ChunkRow, ChunkStatus, FlowRow, HostRow, MetaRow, StoreRecord,
    TimeseriesRow,
};
pub use session::{OpenMode, Session};
pub use writer::{StoreSender, StoreWriter, WriterConfig, WriterStats};

/// Crate name, used by smoke tests and diagnostics.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(super::CRATE_NAME, "netsift-store");
    }
}
