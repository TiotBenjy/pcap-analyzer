//! GeoIP lookups (DB-IP Lite mmdb) and address classification.
//!
//! - [`AddressCategory`]: classification of an IP address (private, public, multicast...),
//!   pure and without database, aligned with the legends of the network views;
//! - [`GeoDb`]: ISO 3166-1 alpha-2 country of public addresses, read from the DB-IP
//!   IP-to-Country Lite database (`MaxMind` DB format, CC BY 4.0: attribution shown in the
//!   "About" card of the application). Shared between threads behind an `Arc`, with a
//!   bounded LRU cache;
//! - [`open_or_warn`]: what an import uses. Without a usable database, countries are simply
//!   unknown.

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
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;

pub use category::{AddressCategory, UnknownCategory};
pub use country::CountryCode;
pub use db::{
    DB_DIR, DB_FILE_NAME, DEFAULT_CACHE_CAPACITY, GeoDb, GeoError, MAX_DB_BYTES, default_path,
    open_or_warn,
};

/// Crate name, used by smoke tests and diagnostics.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(super::CRATE_NAME, "netsift-geo");
    }
}
