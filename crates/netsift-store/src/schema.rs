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
//!
//! To add a migration: create the SQL file, then add **one line** to [`SESSION_MIGRATIONS`]
//! at its numeric position. Never edit or renumber a migration that has been merged into
//! `main`: write a new one instead. The registry must stay strictly increasing (unit test).

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
    // --- analyzers (0100+): one line per migration, in numeric order ---
    migration!(400, "flows", "0400_flows.sql"),
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
