//! End-of-import steps of the analyzers (ADR-014): cross-shard pairing, derived tables, search
//! indexes. They run once every record is written, on the writer connection, in the order of
//! [`SESSION_FINALIZERS`].
//!
//! A `meta` marker ([`MARKER_KEY`]: `id:version` of every step done, comma separated) records
//! what ran, so that [`run_finalizers`] only runs the missing steps: after an interrupted import
//! (crash, `STOP_LIMIT` exceeded, session recovered as `incomplete`), after a failed step, or
//! when a new version of a step comes with an update. A failed step never fails the import: it
//! is reported, its marker stays absent, and the next run (at the next opening of the session)
//! tries again.
//!
//! Cost: each step is set-based SQL over its own tables (the DNS one is linear in the
//! transactions, plus one indexed lookup per group query). No progress is reported while they
//! run: the import stays in its `finishing` phase until they end.

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::Result;

/// End-of-import step of an analyzer.
#[derive(Debug, Clone, Copy)]
pub struct Finalizer {
    /// Stable identifier (the analyzer id).
    pub id: &'static str,
    /// Bumped when the step changes in a way that existing sessions must replay.
    pub version: u32,
    /// Steps that must have succeeded before this one runs (their ids).
    pub after: &'static [&'static str],
    /// Tables the step fills from `reads`. On a session upgraded after its import (ADR-013),
    /// they leave [`crate::session::TABLES_ADDED_AFTER_IMPORT`] once filled, unless one of
    /// `reads` is still listed there (its analyzer did not run: nothing to derive).
    pub fills: &'static [&'static str],
    /// Tables the step derives its content from.
    pub reads: &'static [&'static str],
    /// The step, run inside a transaction (it must not control transactions itself).
    /// Idempotent, independent of the arrival order of the records.
    pub run: fn(&Connection) -> Result<()>,
}

impl Finalizer {
    fn marker(&self) -> String {
        format!("{}:{}", self.id, self.version)
    }
}

/// `meta` key of the steps done.
pub const MARKER_KEY: &str = "finalizers";

/// End-of-import steps, **in execution order**. Registration point: one line per analyzer.
/// A step goes after every step listed in its `after` (checked by a test); between
/// independent steps, append at the end. The order is never alphabetical by construction.
pub static SESSION_FINALIZERS: &[Finalizer] = &[
    // --- analyzers: one line each, in execution order ---
    Finalizer {
        id: "dns",
        version: 1,
        after: &[],
        fills: &["dns_pairs", "dns_fts"],
        reads: &["dns_messages"],
        run: crate::dns::finalize,
    },
    Finalizer {
        id: "servers",
        version: 1,
        after: &[],
        fills: &[],
        reads: &["dhcp_messages"],
        run: crate::servers::finalize,
    },
];

/// Outcome of [`run_finalizers`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FinalizeReport {
    /// Steps run now and recorded as done.
    pub ran: Vec<&'static str>,
    /// Steps that failed (rolled back, marker absent), with the error message.
    pub failed: Vec<(&'static str, String)>,
    /// Steps not run because a step they come after is not done.
    pub skipped: Vec<&'static str>,
}

impl FinalizeReport {
    pub fn is_complete(&self) -> bool {
        self.failed.is_empty() && self.skipped.is_empty()
    }
}

/// Markers of the steps done (`id:version`), from `meta`.
pub fn finalizers_done(conn: &Connection) -> Result<Vec<String>> {
    let value: Option<String> = conn
        .query_row("SELECT value FROM meta WHERE key = ?1", [MARKER_KEY], |r| {
            r.get(0)
        })
        .optional()?;
    Ok(value
        .unwrap_or_default()
        .split(',')
        .filter(|m| !m.is_empty())
        .map(str::to_owned)
        .collect())
}

/// True when every registered step is recorded as done.
pub fn finalizers_complete(conn: &Connection) -> Result<bool> {
    let done = finalizers_done(conn)?;
    Ok(SESSION_FINALIZERS
        .iter()
        .all(|f| done.contains(&f.marker())))
}

/// Runs the registered steps that are not recorded as done, in order, each in its own
/// transaction with its marker. Idempotent: a second call does nothing. Errors of a step are
/// reported in the result; only an error outside the steps (reading `meta`) is returned.
/// Requires a writable connection outside any transaction.
pub fn run_finalizers(conn: &Connection) -> Result<FinalizeReport> {
    run_with(conn, SESSION_FINALIZERS)
}

pub(crate) fn run_with(conn: &Connection, steps: &[Finalizer]) -> Result<FinalizeReport> {
    let mut done = finalizers_done(conn)?;
    let mut report = FinalizeReport::default();
    for step in steps {
        let marker = step.marker();
        if done.contains(&marker) {
            continue;
        }
        let ready = step.after.iter().all(|dep| {
            steps
                .iter()
                .any(|s| s.id == *dep && done.contains(&s.marker()))
        });
        if !ready {
            report.skipped.push(step.id);
            continue;
        }
        // Older versions of the same step are replaced by the new marker.
        let mut next: Vec<String> = done
            .iter()
            .filter(|m| m.split(':').next() != Some(step.id))
            .cloned()
            .collect();
        next.push(marker);
        match run_one(conn, step, &next.join(",")) {
            Ok(()) => {
                done = next;
                report.ran.push(step.id);
            }
            Err(e) => report.failed.push((step.id, e.to_string())),
        }
    }
    Ok(report)
}

fn run_one(conn: &Connection, step: &Finalizer, markers: &str) -> Result<()> {
    conn.execute_batch("BEGIN")?;
    let result = (step.run)(conn).and_then(|()| {
        unlist_filled(conn, step)?;
        conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) \
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![MARKER_KEY, markers],
        )?;
        Ok(())
    });
    match result {
        Ok(()) => {
            conn.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// Removes the tables a step filled from the "added after the import" list (see
/// [`Finalizer::fills`]), in the transaction of the step.
fn unlist_filled(conn: &Connection, step: &Finalizer) -> Result<()> {
    use crate::session::{TABLES_ADDED_AFTER_IMPORT, tables_added_after_import};
    let mut tables = tables_added_after_import(conn)?;
    if step.fills.is_empty() || step.reads.iter().any(|t| tables.contains(*t)) {
        return Ok(());
    }
    let before = tables.len();
    tables.retain(|t| !step.fills.contains(&t.as_str()));
    if tables.len() == before {
        return Ok(());
    }
    if tables.is_empty() {
        conn.execute(
            "DELETE FROM meta WHERE key = ?1",
            [TABLES_ADDED_AFTER_IMPORT],
        )?;
    } else {
        let value = tables.into_iter().collect::<Vec<_>>().join(",");
        conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) \
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![TABLES_ADDED_AFTER_IMPORT, value],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StoreError;
    use crate::session::{OpenMode, Session};

    fn session() -> (tempfile::TempDir, Session) {
        let dir = tempfile::tempdir().unwrap();
        let session = Session::open(dir.path(), OpenMode::ReadWrite).unwrap();
        (dir, session)
    }

    fn ok(conn: &Connection) -> Result<()> {
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('ok.count', '1') \
             ON CONFLICT (key) DO UPDATE SET value = value + 1",
            [],
        )?;
        Ok(())
    }

    fn fails(conn: &Connection) -> Result<()> {
        conn.execute("INSERT INTO meta (key, value) VALUES ('half', 'done')", [])?;
        Err(StoreError::InvalidValue {
            field: "test",
            reason: "failing step",
        })
    }

    fn meta(conn: &Connection, key: &str) -> Option<String> {
        crate::query::get_meta(conn, key).unwrap()
    }

    #[test]
    fn registry_order_respects_dependencies_and_ids_are_unique() {
        for (i, step) in SESSION_FINALIZERS.iter().enumerate() {
            assert!(!step.id.contains([':', ',']), "{}", step.id);
            for dep in step.after {
                let pos = SESSION_FINALIZERS.iter().position(|s| s.id == *dep);
                assert!(
                    pos.is_some_and(|p| p < i),
                    "{} must come after {dep}",
                    step.id
                );
            }
            assert_eq!(
                SESSION_FINALIZERS
                    .iter()
                    .filter(|s| s.id == step.id)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn missing_steps_run_once_and_are_recorded() {
        let (_dir, session) = session();
        let conn = session.conn();
        assert!(!finalizers_complete(conn).unwrap());
        let report = run_finalizers(conn).unwrap();
        let ids: Vec<&str> = SESSION_FINALIZERS.iter().map(|f| f.id).collect();
        assert_eq!(report.ran, ids);
        assert!(report.is_complete());
        let markers: Vec<String> = SESSION_FINALIZERS.iter().map(Finalizer::marker).collect();
        assert_eq!(meta(conn, MARKER_KEY), Some(markers.join(",")));
        assert!(finalizers_complete(conn).unwrap());
        // Idempotent: nothing left to run.
        assert_eq!(run_finalizers(conn).unwrap(), FinalizeReport::default());
    }

    #[test]
    fn a_failed_step_is_rolled_back_and_retried_and_blocks_its_dependents() {
        let (_dir, session) = session();
        let conn = session.conn();
        let steps = [
            Finalizer {
                id: "first",
                version: 1,
                after: &[],
                fills: &[],
                reads: &[],
                run: ok,
            },
            Finalizer {
                id: "broken",
                version: 1,
                after: &[],
                fills: &[],
                reads: &[],
                run: fails,
            },
            Finalizer {
                id: "dependent",
                version: 1,
                after: &["broken"],
                fills: &[],
                reads: &[],
                run: ok,
            },
        ];
        let report = run_with(conn, &steps).unwrap();
        assert_eq!(report.ran, vec!["first"]);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].0, "broken");
        assert_eq!(report.skipped, vec!["dependent"]);
        assert_eq!(meta(conn, "half"), None, "rolled back");
        assert_eq!(meta(conn, MARKER_KEY).as_deref(), Some("first:1"));

        // Next opening: the step is fixed; only the missing ones run.
        let fixed = [
            steps[0],
            Finalizer {
                run: ok,
                ..steps[1]
            },
            steps[2],
        ];
        let report = run_with(conn, &fixed).unwrap();
        assert_eq!(report.ran, vec!["broken", "dependent"]);
        assert_eq!(meta(conn, "ok.count").as_deref(), Some("3"));
        assert_eq!(
            meta(conn, MARKER_KEY).as_deref(),
            Some("first:1,broken:1,dependent:1")
        );
    }

    #[test]
    fn a_failed_step_does_not_fail_the_import_and_runs_again_later() {
        use crate::writer::{StoreWriter, WriterConfig};
        let dir = tempfile::tempdir().unwrap();
        let writer = StoreWriter::spawn(
            Session::open(dir.path(), OpenMode::Import).unwrap(),
            WriterConfig::default(),
        )
        .unwrap();
        // Another connection breaks the DNS step before the end of the import.
        let other = Session::open(dir.path(), OpenMode::ReadWrite).unwrap();
        other
            .conn()
            .execute_batch("ALTER TABLE dns_pairs RENAME TO dns_pairs_away")
            .unwrap();
        let stats = writer.finish().unwrap();
        assert!(!stats.finalize.ran.contains(&"dns"));
        assert_eq!(stats.finalize.failed.len(), 1);
        assert_eq!(stats.finalize.failed[0].0, "dns");
        assert!(!finalizers_complete(other.conn()).unwrap());

        // Repaired: the next opening runs the missing step.
        other
            .conn()
            .execute_batch("ALTER TABLE dns_pairs_away RENAME TO dns_pairs")
            .unwrap();
        assert_eq!(run_finalizers(other.conn()).unwrap().ran, vec!["dns"]);
        assert!(finalizers_complete(other.conn()).unwrap());
    }

    #[test]
    fn a_new_version_replays_the_step() {
        let (_dir, session) = session();
        let conn = session.conn();
        let v1 = [Finalizer {
            id: "step",
            version: 1,
            after: &[],
            fills: &[],
            reads: &[],
            run: ok,
        }];
        run_with(conn, &v1).unwrap();
        let v2 = [Finalizer {
            version: 2,
            ..v1[0]
        }];
        assert_eq!(run_with(conn, &v2).unwrap().ran, vec!["step"]);
        assert_eq!(meta(conn, MARKER_KEY).as_deref(), Some("step:2"));
    }
}
