//! GeoIP lookups (DB-IP Lite mmdb) and address classification.

/// Crate name, used by smoke tests and diagnostics.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(super::CRATE_NAME, "netsift-geo");
    }
}
