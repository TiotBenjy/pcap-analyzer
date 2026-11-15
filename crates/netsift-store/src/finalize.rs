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
//! transactions, plus one indexed lookup per group query). [`run_finalizers_with_progress`]
//! reports the step running and the number of steps done: the writer publishes it, and the
//! import reports a `finalizing` phase while the steps run (P4.8).

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
    // --- core ---
    Finalizer {
        // First: the secondary indexes dropped by the import (ADR-023), read by the steps below.
        id: "indexes",
        version: 1,
        after: &[],
        fills: &[],
        reads: &[],
        run: crate::deferred::finalize,
    },
    Finalizer {
        id: "timeseries",
        version: 1,
        after: &[],
        fills: &["timeseries_minute", "timeseries_hour"],
        reads: &["timeseries"],
        run: crate::traffic::finalize,
    },
    // --- analyzers: one line each, in execution order ---
    Finalizer {
        id: "dns",
        version: 1,
        after: &["indexes"],
        fills: &["dns_pairs", "dns_fts"],
        reads: &["dns_messages"],
        run: crate::dns::finalize,
    },
    Finalizer {
        id: "servers",
        // 2: materializes the roles (0801). 3: ranks the servers of each role (0802).
        version: 3,
        // After `dns`: when a host reaches MAX_HOST_NAMES, DNS names are kept first, always.
        after: &["indexes", "dns"],
        fills: &["server_evidence", "server_roles", "server_ranks"],
        reads: &["dhcp_messages"],
        run: crate::servers::finalize,
    },
    Finalizer {
        id: "objects",
        version: 1,
        after: &["indexes"],
        // Nothing to unlist: a session imported before P3.6 never stored bodies, so its
        // `objects` stays "not analyzed" (ADR-013) rather than empty.
        fills: &[],
        reads: &["http_transactions"],
        run: crate::objects::finalize,
    },
    Finalizer {
        id: "http",
        version: 1,
        after: &[],
        fills: &["http_transactions_fts", "http_headers_fts"],
        reads: &["http_transactions", "http_headers"],
        run: crate::http::finalize,
    },
    Finalizer {
        id: "network",
        version: 1,
        // Not after `indexes`: it reads its sources by primary key and in storage order, and the
        // indexes of the tables it fills are never deferred.
        after: &[],
        fills: &[
            "network_hosts",
            "network_edges",
            "network_country_edges",
            "network_expand",
            "network_host_counts",
            "network_protocols",
            "network_ends",
        ],
        reads: &["conversations", "hosts", "host_traffic"],
        run: crate::network::finalize,
    },
    Finalizer {
        id: "connections",
        version: 1,
        // Reads by primary key only; after `indexes` because the category filter it serves
        // looks rare categories up in `conversations_dst_ip` (deferred).
        after: &["indexes"],
        fills: &["conversation_categories"],
        reads: &["conversations", "hosts"],
        run: crate::connections::finalize,
    },
    Finalizer {
        id: "ports",
        version: 1,
        after: &[],
        fills: &["open_port_hosts"],
        reads: &["open_ports", "hosts"],
        run: crate::ports::finalize,
    },
];

/// Progress of [`run_finalizers_with_progress`], reported before each step and once at the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepProgress {
    /// Steps finished (run, failed or skipped) out of `total`.
    pub done: usize,
    /// Steps that were pending when the run started.
    pub total: usize,
    /// Identifier of the step running ([`Finalizer::id`]); `None` once every step is finished.
    pub step: Option<&'static str>,
}

/// Outcome of [`run_finalizers`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FinalizeReport {
    /// Steps run now and recorded as done.
    pub ran: Vec<&'static str>,
    /// Steps that failed (rolled back, marker absent), with the error message.
    pub failed: Vec<(&'static str, String)>,
    /// Steps not run because a step they come after is not done.
    pub skipped: Vec<&'static str>,
    /// Wall-clock time of every step run (succeeded or failed), in order.
    pub timings: Vec<(&'static str, std::time::Duration)>,
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

/// True when the current version of step `id` is recorded as done. Readers of a table that only
/// a step fills fall back to its sources while it is not (session served read-only before its
/// steps ran, or a failed step): slower, never wrong (ADR-023).
pub fn step_done(conn: &Connection, id: &str) -> Result<bool> {
    let Some(step) = SESSION_FINALIZERS.iter().find(|f| f.id == id) else {
        return Ok(false);
    };
    Ok(finalizers_done(conn)?.contains(&step.marker()))
}

/// True when step `id` is recorded as done in version `version` or a later one: for the readers
/// of a table that a later version of the step still fills the same way (the roles of `servers`
/// since version 2), so that a session waiting for the replay of a newer version keeps reading it.
pub fn step_done_since(conn: &Connection, id: &str, version: u32) -> Result<bool> {
    Ok(finalizers_done(conn)?.iter().any(|m| {
        m.split_once(':')
            .is_some_and(|(step, v)| step == id && v.parse::<u32>().is_ok_and(|v| v >= version))
    }))
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
    run_with(conn, SESSION_FINALIZERS, &mut |_| {})
}

/// [`run_finalizers`], calling `progress` before each pending step and once after the last one
/// (`step` = `None`, `done` = `total`).
pub fn run_finalizers_with_progress(
    conn: &Connection,
    progress: &mut dyn FnMut(StepProgress),
) -> Result<FinalizeReport> {
    run_with(conn, SESSION_FINALIZERS, progress)
}

pub(crate) fn run_with(
    conn: &Connection,
    steps: &[Finalizer],
    progress: &mut dyn FnMut(StepProgress),
) -> Result<FinalizeReport> {
    let mut done = finalizers_done(conn)?;
    let mut report = FinalizeReport::default();
    let total = steps.iter().filter(|s| !done.contains(&s.marker())).count();
    let mut finished = 0;
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
            finished += 1;
            continue;
        }
        progress(StepProgress {
            done: finished,
            total,
            step: Some(step.id),
        });
        // Older versions of the same step are replaced by the new marker.
        let mut next: Vec<String> = done
            .iter()
            .filter(|m| m.split(':').next() != Some(step.id))
            .cloned()
            .collect();
        next.push(marker);
        let started = std::time::Instant::now();
        let outcome = run_one(conn, step, &next.join(","));
        report.timings.push((step.id, started.elapsed()));
        match outcome {
            Ok(()) => {
                done = next;
                report.ran.push(step.id);
            }
            Err(e) => report.failed.push((step.id, e.to_string())),
        }
        finished += 1;
    }
    progress(StepProgress {
        done: finished,
        total,
        step: None,
    });
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
        let mut seen = Vec::new();
        let report = run_with(conn, &steps, &mut |p| seen.push(p)).unwrap();
        assert_eq!(report.ran, vec!["first"]);
        // Progress: before each step run, skipped steps counted as finished, then the end.
        let p = |done, step| StepProgress {
            done,
            total: 3,
            step,
        };
        assert_eq!(
            seen,
            vec![p(0, Some("first")), p(1, Some("broken")), p(3, None)]
        );
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
        let mut seen = Vec::new();
        let report = run_with(conn, &fixed, &mut |p| seen.push(p)).unwrap();
        assert_eq!(report.ran, vec!["broken", "dependent"]);
        // Only the pending steps count.
        assert_eq!(seen.first().map(|p| (p.done, p.total)), Some((0, 2)));
        assert_eq!(seen.last().map(|p| (p.done, p.step)), Some((2, None)));
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
        // Another connection breaks the DNS step before the end of the import (its search
        // index: the tables keep their name, so the deferred indexes can be built).
        let other = Session::open(dir.path(), OpenMode::ReadWrite).unwrap();
        other
            .conn()
            .execute_batch("ALTER TABLE dns_fts RENAME TO dns_fts_away")
            .unwrap();
        let stats = writer.finish().unwrap();
        assert!(!stats.finalize.ran.contains(&"dns"));
        assert_eq!(stats.finalize.failed.len(), 1);
        assert_eq!(stats.finalize.failed[0].0, "dns");
        assert!(!finalizers_complete(other.conn()).unwrap());

        // Repaired: the next opening runs the missing step.
        other
            .conn()
            .execute_batch("ALTER TABLE dns_fts_away RENAME TO dns_fts")
            .unwrap();
        // The steps that come after `dns` were postponed with it.
        let after_dns: Vec<&str> = SESSION_FINALIZERS
            .iter()
            .filter(|f| f.id == "dns" || f.after.contains(&"dns"))
            .map(|f| f.id)
            .collect();
        assert_eq!(run_finalizers(other.conn()).unwrap().ran, after_dns);
        assert!(finalizers_complete(other.conn()).unwrap());
    }

    #[test]
    fn the_writer_publishes_the_progress_of_its_steps() {
        use crate::writer::{StoreWriter, WriterConfig};
        let dir = tempfile::tempdir().unwrap();
        let writer = StoreWriter::spawn(
            Session::open(dir.path(), OpenMode::Import).unwrap(),
            WriterConfig::default(),
        )
        .unwrap();
        let watch = writer.finalize_watch();
        assert_eq!(watch.get(), None, "nothing before the end of the records");
        writer.finish().unwrap();
        let n = SESSION_FINALIZERS.len();
        assert_eq!(
            watch.get(),
            Some(StepProgress {
                done: n,
                total: n,
                step: None
            })
        );
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
        run_with(conn, &v1, &mut |_| {}).unwrap();
        let v2 = [Finalizer {
            version: 2,
            ..v1[0]
        }];
        assert_eq!(run_with(conn, &v2, &mut |_| {}).unwrap().ran, vec!["step"]);
        assert_eq!(meta(conn, MARKER_KEY).as_deref(), Some("step:2"));
    }
}
