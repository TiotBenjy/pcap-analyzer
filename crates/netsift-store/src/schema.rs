//! Migration registries (registration point shared by the analyzer branches).
//!
//! Numbering convention (`docs/GIT_WORKFLOW.md`): file `migrations/NNNN_<name>.sql`, one
//! reserved range per owner, so parallel branches never pick the same number:
//!
//! | Range     | Owner   |   | Range     | Owner   |
//! |-----------|---------|---|-----------|---------|
//! | 0001-0099 | core    |   | 0500-0599 | smb     |
//! | 0100-0199 | dns     |   | 0600-0699 | creds   |
//! | 0200-0299 | http    |   | 0700-0799 | objects |
//! | 0300-0399 | tls     |   | 0800-0899 | servers |
//! | 0400-0499 | flows   |   | 0900-0999 | network |
//! | 1000-1099 | arp     |   | 1100-1199 | ethernet |
//! | 1200-1299 | ssdp    |   | 1400-1499 | ftp     |
//! | 1500-1599 | telnet  |   |           |         |
//!
//! To add a migration: create the SQL file, then add **one line** to [`SESSION_MIGRATIONS`]
//! at its numeric position. Never edit or renumber a migration that has been merged into
//! `main`: write a new one instead. The registry must stay strictly increasing (unit test).
//!
//! A migration that removes an index writes `DROP INDEX IF EXISTS`: an import interrupted before
//! its end-of-import steps has its secondary indexes dropped (ADR-023, `deferred.rs`) until the
//! step `indexes` creates them again.

use crate::migrate::{Migration, MigrationSet};

macro_rules! migration {
    ($version:literal, $name:literal, $file:literal) => {
        Migration {
            version: $version,
            name: $name,
            sql: include_str!(concat!("../migrations/", $file)),
        }
    };
}

/// Migrations of `sessions/<id>/session.db`, sorted by version.
pub static SESSION_MIGRATIONS: &[Migration] = &[
    // --- core (0001-0099) ---
    migration!(1, "core", "0001_core.sql"),
    migration!(
        2,
        "core_timeseries_rollup",
        "0002_core_timeseries_rollup.sql"
    ),
    migration!(3, "core_time_ranges", "0003_core_time_ranges.sql"),
    // --- analyzers (0100+): one line per migration, in numeric order ---
    migration!(100, "dns", "0100_dns.sql"),
    migration!(101, "dns_time_ranges", "0101_dns_time_ranges.sql"),
    migration!(200, "http", "0200_http.sql"),
    migration!(201, "http_fts_deferred", "0201_http_fts_deferred.sql"),
    migration!(202, "http_time_ranges", "0202_http_time_ranges.sql"),
    migration!(300, "tls", "0300_tls.sql"),
    migration!(301, "tls_stats_indexes", "0301_tls_stats_indexes.sql"),
    migration!(302, "tls_time_ranges", "0302_tls_time_ranges.sql"),
    migration!(400, "flows", "0400_flows.sql"),
    migration!(401, "flows_conversation", "0401_flows_conversation.sql"),
    migration!(
        402,
        "flows_category_counts",
        "0402_flows_category_counts.sql"
    ),
    migration!(500, "smb", "0500_smb.sql"),
    migration!(600, "credentials", "0600_credentials.sql"),
    migration!(700, "objects", "0700_objects.sql"),
    migration!(800, "servers", "0800_servers.sql"),
    migration!(801, "servers_materialized", "0801_servers_materialized.sql"),
    migration!(802, "servers_ranks", "0802_servers_ranks.sql"),
    migration!(900, "network", "0900_network.sql"),
    migration!(1000, "arp", "1000_arp.sql"),
    migration!(1100, "ethernet", "1100_ethernet.sql"),
    migration!(1200, "ssdp", "1200_ssdp.sql"),
    migration!(1400, "ftp", "1400_ftp.sql"),
    migration!(1500, "telnet", "1500_telnet.sql"),
];

/// Migrations of `catalog.db`, sorted by version (owned by the core only).
pub static CATALOG_MIGRATIONS: &[Migration] =
    &[migration!(1, "sessions", "catalog/0001_sessions.sql")];

/// Session database family (`application_id` = "NSFS").
pub static SESSION_SCHEMA: MigrationSet = MigrationSet {
    kind: "session",
    application_id: 0x4E53_4653,
    migrations: SESSION_MIGRATIONS,
};

/// Catalog database family (`application_id` = "NSFC").
pub static CATALOG_SCHEMA: MigrationSet = MigrationSet {
    kind: "catalog",
    application_id: 0x4E53_4643,
    migrations: CATALOG_MIGRATIONS,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_sorted(migrations: &[Migration]) {
        assert!(!migrations.is_empty());
        for pair in migrations.windows(2) {
            assert!(
                pair[0].version < pair[1].version,
                "migrations must be strictly increasing: {} then {}",
                pair[0].version,
                pair[1].version
            );
        }
        for m in migrations {
            assert!(m.version > 0);
            assert!(!m.sql.trim().is_empty(), "migration {} is empty", m.version);
            let upper = m.sql.to_ascii_uppercase();
            assert!(
                !upper.contains("BEGIN TRANSACTION") && !upper.contains("COMMIT"),
                "migration {} must not control transactions",
                m.version
            );
        }
    }

    #[test]
    fn registries_are_strictly_increasing() {
        assert_sorted(SESSION_MIGRATIONS);
        assert_sorted(CATALOG_MIGRATIONS);
    }

    #[test]
    fn core_comes_first_and_is_named_core() {
        assert_eq!(SESSION_MIGRATIONS[0].version, 1);
        for m in SESSION_MIGRATIONS.iter().filter(|m| m.version < 100) {
            assert!(
                m.name.starts_with("core"),
                "0001-0099 is reserved for the core"
            );
        }
    }
}
