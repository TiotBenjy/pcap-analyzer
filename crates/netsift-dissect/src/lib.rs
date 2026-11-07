//! Pure, I/O-free, fuzzable protocol parsers (L2 to L7).
#![forbid(unsafe_code)]
// Captures are hostile input: parsers must never panic (see CLAUDE.md).
// Tests are exempted through clippy.toml (allow-*-in-tests).
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unreachable,
    clippy::arithmetic_side_effects
)]

/// Crate name, used by smoke tests and diagnostics.
pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        assert_eq!(super::CRATE_NAME, "netsift-dissect");
    }
}
