//! GeoIP lookups (DB-IP Lite mmdb) and address classification.
//!
//! - [`AddressCategory`]: classification of an IP address (private, public, multicast...),
//!   pure and without database, aligned with the legends of the network views;
//! - [`GeoDb`]: ISO 3166-1 alpha-2 country of public addresses, read from the DB-IP
//!   IP-to-Country Lite database (`MaxMind` DB format, CC BY 4.0: attribution shown in the
//!   "About" card of the application). Shared between threads behind an `Arc`, with a
//!   bounded LRU cache;
//! - [`open_or_warn`]: what an import uses. Without a usable database, countries are simply
//!   unknown;
//! - [`install`]: validation and atomic replacement of the database by a downloaded or
//!   user-chosen file (no network here: the download is done by the API).

// The database file is untrusted input: no panic paths in library code.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod category;
mod country;
mod db;
mod install;
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

pub use category::{AddressCategory, UnknownCategory};
pub use country::CountryCode;
pub use db::{
    DB_DIR, DB_FILE_NAME, DEFAULT_CACHE_CAPACITY, GeoDb, GeoError, MAX_DB_BYTES, default_path,
    open_or_warn,
};
pub use install::{MAX_COMPRESSED_BYTES, decode_database, install, read_database_file};

/// Crate name, used by smoke tests and diagnostics.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(super::CRATE_NAME, "netsift-geo");
    }
}
