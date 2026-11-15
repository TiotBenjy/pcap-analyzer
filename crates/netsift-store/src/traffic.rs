//! Read-only queries of the session overview: traffic time series resampled on the server,
//! global totals, link types and per-table row counts.
//!
//! The `timeseries` table holds one row per (one-second bucket, protocol label). A view asks for
//! a period and a number of points: [`BucketPlan::new`] picks a round bucket width (1 s, 2 s,
//! 5 s, ... 1 h, 1 d...) aligned on the clock so that at most `max_points` buckets cover the
//! period, then [`resample`] sums the rows of each bucket with one range scan of the primary key.
//!
//! At the end of the import, [`finalize`] folds the one-second rows into `timeseries_minute` and
//! `timeseries_hour` (`0002_core_timeseries_rollup.sql`) and records the totals in `meta`: a plan
//! whose bucket width is a multiple of a minute (or an hour) reads the coarser table, and the
//! totals no longer sum the whole table. Until the step has run (session opened by a read-only
//! server, failed step), both fall back to the one-second table.

use rusqlite::{Connection, OptionalExtension};

use crate::error::{Result, StoreError};
use crate::session::tables_added_after_import;

/// Round bucket widths, in seconds; beyond the last one, whole days.
const NICE_STEPS: [i64; 20] = [
    1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1_800, 3_600, 7_200, 10_800, 21_600, 43_200,
    86_400, 172_800, 604_800,
];
const DAY: i64 = 86_400;

/// Buckets covering a period: `points` buckets of `step_s` seconds from `start_s` (aligned on a
/// multiple of `step_s`). Bucket `i` covers `[start_s + i * step_s, start_s + (i + 1) * step_s)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketPlan {
    pub start_s: i64,
    pub step_s: i64,
    pub points: u32,
}

impl BucketPlan {
    /// Plan for the seconds `from_s..=to_s` in at most `max_points` buckets (at least 1).
    pub fn new(from_s: i64, to_s: i64, max_points: u32) -> Result<Self> {
        if to_s < from_s {
            return Err(StoreError::InvalidValue {
                field: "range",
                reason: "the end is before the start",
            });
        }
        let max = i128::from(max_points.max(1));
        let span = i128::from(to_s) - i128::from(from_s) + 1;
        let mut candidates = NICE_STEPS.iter().map(|s| i128::from(*s)).chain(
            // Past a week, whole days (ceil), then doubling: the loop always ends.
            std::iter::successors(
                Some(i128::from(DAY) * ceil_div(span, i128::from(DAY) * max)),
                |s| Some(s * 2),
            ),
        );
        loop {
            let Some(step) = candidates.next() else {
                return Err(StoreError::InvalidValue {
                    field: "range",
                    reason: "too long",
                });
            };
            let start = i128::from(from_s).div_euclid(step) * step;
            let points = ceil_div(i128::from(to_s) - start + 1, step);
            if points <= max {
                return Ok(Self {
                    start_s: i64::try_from(start).map_err(|_| too_long())?,
                    step_s: i64::try_from(step).map_err(|_| too_long())?,
                    points: u32::try_from(points).map_err(|_| too_long())?,
                });
            }
        }
    }

    /// Last second covered (inclusive).
    pub fn end_s(&self) -> i64 {
        self.start_s
            .saturating_add(self.step_s.saturating_mul(i64::from(self.points)))
            .saturating_sub(1)
    }
}

/// `ceil(a / b)` for `b > 0` (`i128::div_ceil` is unstable).
fn ceil_div(a: i128, b: i128) -> i128 {
    (a + b - 1).div_euclid(b)
}

fn too_long() -> StoreError {
    StoreError::InvalidValue {
        field: "range",
        reason: "too long",
    }
}

/// First and last one-second buckets of the time series, `None` when it is empty.
pub fn traffic_bounds(conn: &Connection) -> Result<Option<(i64, i64)>> {
    let (first, last): (Option<i64>, Option<i64>) = conn.query_row(
        "SELECT min(bucket_s), max(bucket_s) FROM timeseries",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(first.zip(last))
}

/// `meta` keys of the time series totals (bytes and packets), written by [`finalize`] with the
/// rollup tables; their presence means the rollups are complete.
pub const TOTAL_BYTES_META: &str = "timeseries.total_bytes";
pub const TOTAL_PACKETS_META: &str = "timeseries.total_packets";

/// Rollup tables, finest first: (table, bucket width in seconds).
const ROLLUPS: [(&str, i64); 2] = [("timeseries_minute", 60), ("timeseries_hour", 3_600)];

/// Sums per bucket start and label of one rollup level, for the bucket being folded.
struct Fold {
    width: i64,
    bucket: Option<i64>,
    sums: std::collections::BTreeMap<String, (u64, u64)>,
}

impl Fold {
    fn add(
        &mut self,
        insert: &mut rusqlite::CachedStatement<'_>,
        bucket_s: i64,
        proto: &str,
        bytes: u64,
        packets: u64,
    ) -> Result<()> {
        let bucket = bucket_s.div_euclid(self.width) * self.width;
        if self.bucket != Some(bucket) {
            self.flush(insert)?;
            self.bucket = Some(bucket);
        }
        let e = self.sums.entry(proto.to_owned()).or_default();
        e.0 = e.0.saturating_add(bytes);
        e.1 = e.1.saturating_add(packets);
        Ok(())
    }

    fn flush(&mut self, insert: &mut rusqlite::CachedStatement<'_>) -> Result<()> {
        let Some(bucket) = self.bucket else {
            return Ok(());
        };
        for (proto, (bytes, packets)) in std::mem::take(&mut self.sums) {
            insert.execute(rusqlite::params![
                bucket,
                proto,
                signed(bytes),
                signed(packets)
            ])?;
        }
        Ok(())
    }
}

/// End-of-import step `timeseries` ([`crate::finalize::SESSION_FINALIZERS`]): rebuilds the
/// minute and hour tables and the totals, in the transaction of the caller. Idempotent.
///
/// One scan of `timeseries` in key order (bucket, then label): bucket starts of every level
/// only grow, so each level keeps the sums of its current bucket only (memory bounded by the
/// number of labels) and inserts rows in key order.
pub(crate) fn finalize(conn: &Connection) -> Result<()> {
    for (table, _) in ROLLUPS {
        conn.execute(&format!("DELETE FROM {table}"), [])?;
    }
    let mut minute = conn.prepare_cached(
        "INSERT INTO timeseries_minute (bucket_s, proto, bytes, packets) VALUES (?1, ?2, ?3, ?4)",
    )?;
    let mut hour = conn.prepare_cached(
        "INSERT INTO timeseries_hour (bucket_s, proto, bytes, packets) VALUES (?1, ?2, ?3, ?4)",
    )?;
    let mut folds = ROLLUPS.map(|(_, width)| Fold {
        width,
        bucket: None,
        sums: std::collections::BTreeMap::new(),
    });
    let (mut total_bytes, mut total_packets) = (0u64, 0u64);
    let mut read = conn.prepare(
        "SELECT bucket_s, proto, bytes, packets FROM timeseries ORDER BY bucket_s, proto",
    )?;
    let mut rows = read.query([])?;
    while let Some(row) = rows.next()? {
        let bucket_s: i64 = row.get(0)?;
        let proto = row.get_ref(1)?.as_str().map_err(rusqlite::Error::from)?;
        let bytes = unsigned(row.get(2)?);
        let packets = unsigned(row.get(3)?);
        total_bytes = total_bytes.saturating_add(bytes);
        total_packets = total_packets.saturating_add(packets);
        let [m, h] = &mut folds;
        m.add(&mut minute, bucket_s, proto, bytes, packets)?;
        h.add(&mut hour, bucket_s, proto, bytes, packets)?;
    }
    let [m, h] = &mut folds;
    m.flush(&mut minute)?;
    h.flush(&mut hour)?;
    for (key, value) in [
        (TOTAL_BYTES_META, total_bytes),
        (TOTAL_PACKETS_META, total_packets),
    ] {
        conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) \
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            rusqlite::params![key, value.to_string()],
        )?;
    }
    Ok(())
}

/// Totals recorded by [`finalize`], `None` before it has run.
fn recorded_totals(conn: &Connection) -> Result<Option<(u64, u64)>> {
    let read = |key: &str| -> Result<Option<u64>> {
        Ok(crate::query::get_meta(conn, key)?.and_then(|v| v.parse().ok()))
    };
    Ok(read(TOTAL_BYTES_META)?.zip(read(TOTAL_PACKETS_META)?))
}

/// Table read for buckets of `step_s` seconds: the coarsest rollup whose width divides it
/// (plans align their start on a multiple of the step), once the rollups are complete.
fn source_table(conn: &Connection, step_s: i64) -> Result<&'static str> {
    if recorded_totals(conn)?.is_none() {
        return Ok("timeseries");
    }
    Ok(ROLLUPS
        .iter()
        .rev()
        .find(|(_, width)| step_s % width == 0)
        .map_or("timeseries", |(table, _)| *table))
}

/// Sums of one bucket and one protocol label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficBucket {
    /// Index in the plan (`0..points`).
    pub index: u32,
    pub proto: String,
    pub bytes: u64,
    pub packets: u64,
}

/// Rows of `plan`, summed per bucket and protocol label (buckets without traffic are absent),
/// ordered by bucket then label.
///
/// One range scan of the primary key of the coarsest table that can serve the plan (see
/// [`finalize`]), summed in memory: grouping in SQL on the computed bucket would sort every row
/// first. Memory is bounded by `points` x distinct labels.
pub fn resample(conn: &Connection, plan: &BucketPlan) -> Result<Vec<TrafficBucket>> {
    let table = source_table(conn, plan.step_s)?;
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT bucket_s, proto, bytes, packets FROM {table} WHERE bucket_s BETWEEN ?1 AND ?2"
    ))?;
    let mut rows = stmt.query(rusqlite::params![plan.start_s, plan.end_s()])?;
    // Interned labels; sums per (bucket, label slot).
    let mut labels: Vec<String> = Vec::new();
    let mut sums: std::collections::HashMap<(u32, usize), (u64, u64)> =
        std::collections::HashMap::new();
    while let Some(row) = rows.next()? {
        let bucket_s: i64 = row.get(0)?;
        let Ok(index) = u32::try_from((bucket_s - plan.start_s).div_euclid(plan.step_s)) else {
            continue;
        };
        if index >= plan.points {
            continue;
        }
        let proto = row.get_ref(1)?.as_str().map_err(rusqlite::Error::from)?;
        let slot = if let Some(slot) = labels.iter().position(|l| l == proto) {
            slot
        } else {
            labels.push(proto.to_owned());
            labels.len() - 1
        };
        let e = sums.entry((index, slot)).or_default();
        e.0 = e.0.saturating_add(unsigned(row.get(2)?));
        e.1 = e.1.saturating_add(unsigned(row.get(3)?));
    }
    let mut out: Vec<TrafficBucket> = sums
        .into_iter()
        .map(|((index, slot), (bytes, packets))| TrafficBucket {
            index,
            proto: labels.get(slot).cloned().unwrap_or_default(),
            bytes,
            packets,
        })
        .collect();
    out.sort_unstable_by(|a, b| (a.index, &a.proto).cmp(&(b.index, &b.proto)));
    Ok(out)
}

/// Total bytes and packets of the time series (on-wire lengths): recorded at the end of the
/// import ([`finalize`]), summed over the table before.
pub fn traffic_totals(conn: &Connection) -> Result<(u64, u64)> {
    if let Some(totals) = recorded_totals(conn)? {
        return Ok(totals);
    }
    let (bytes, packets): (Option<i64>, Option<i64>) =
        conn.query_row("SELECT sum(bytes), sum(packets) FROM timeseries", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    Ok((unsigned(bytes.unwrap_or(0)), unsigned(packets.unwrap_or(0))))
}

/// Distinct link types of the chunks, ascending.
pub fn linktypes(conn: &Connection) -> Result<Vec<u32>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT j.value FROM chunks, json_each(chunks.linktypes) AS j \
         WHERE j.type = 'integer' ORDER BY j.value",
    )?;
    let rows = stmt.query_map([], |r| r.get::<_, i64>(0))?;
    let mut out = Vec::new();
    for v in rows {
        if let Ok(v) = u32::try_from(v?) {
            out.push(v);
        }
    }
    Ok(out)
}

/// Number of rows of `table`, `None` when the session has no such table (a module added by a
/// later version) or when the table was created by an upgrade after the import, so its analyzer
/// did not run (ADR-013). `table` comes from a static registry; anything but `[a-z0-9_]` is
/// refused.
pub fn count_rows(conn: &Connection, table: &'static str) -> Result<Option<u64>> {
    let valid = !table.is_empty()
        && table
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if !valid {
        return Err(StoreError::InvalidValue {
            field: "table",
            reason: "not a plain table name",
        });
    }
    let exists = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type IN ('table', 'view') AND name = ?1",
            [table],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !exists || tables_added_after_import(conn)?.contains(table) {
        return Ok(None);
    }
    let n: i64 = conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
    Ok(Some(unsigned(n)))
}

fn unsigned(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn signed(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::migrate;
    use crate::schema::SESSION_SCHEMA;

    fn db() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn, &SESSION_SCHEMA).unwrap();
        conn
    }

    fn insert(conn: &Connection, bucket_s: i64, proto: &str, bytes: i64, packets: i64) {
        conn.execute(
            "INSERT INTO timeseries (bucket_s, proto, bytes, packets) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![bucket_s, proto, bytes, packets],
        )
        .unwrap();
    }

    #[test]
    fn plan_uses_round_aligned_steps_within_the_limit() {
        // Short period: one-second buckets, no alignment needed.
        let p = BucketPlan::new(100, 159, 1000).unwrap();
        assert_eq!((p.start_s, p.step_s, p.points), (100, 1, 60));
        assert_eq!(p.end_s(), 159);

        // 24 h in 1000 points: 2-minute buckets aligned on even minutes.
        let day_start = 1_700_000_000;
        let p = BucketPlan::new(day_start, day_start + DAY - 1, 1000).unwrap();
        assert_eq!(p.step_s, 120);
        assert_eq!(p.start_s % 120, 0);
        assert!(p.points <= 1000 && p.points >= 720, "{p:?}");
        assert!(p.start_s <= day_start && p.end_s() >= day_start + DAY - 1);

        // 2000 points: one-minute buckets.
        let p = BucketPlan::new(day_start, day_start + DAY - 1, 2000).unwrap();
        assert_eq!(p.step_s, 60);
        assert!(p.points <= 2000);

        // Alignment that would add a bucket picks the next round step.
        let p = BucketPlan::new(59, 60, 1).unwrap();
        assert_eq!(p.points, 1);
        assert!(p.start_s <= 59 && p.end_s() >= 60);
    }

    #[test]
    fn plan_handles_extreme_ranges() {
        let p = BucketPlan::new(-9_223_372_036_854, 9_223_372_036_854, 2000).unwrap();
        assert!(p.points <= 2000 && p.points > 0);
        assert_eq!(p.step_s % DAY, 0);
        let p = BucketPlan::new(-5, -5, 0).unwrap();
        assert_eq!((p.start_s, p.points), (-5, 1));
        assert!(BucketPlan::new(10, 9, 100).is_err());
    }

    #[test]
    fn resample_sums_rows_per_bucket_and_protocol() {
        let conn = db();
        assert_eq!(traffic_bounds(&conn).unwrap(), None);
        for s in 0..10 {
            insert(&conn, 1_000 + s, "dns", 100, 1);
            insert(&conn, 1_000 + s, "http", 1_000, 2);
        }
        insert(&conn, 2_000, "tls", 5, 1); // outside the plan below
        assert_eq!(traffic_bounds(&conn).unwrap(), Some((1_000, 2_000)));

        let plan = BucketPlan::new(1_000, 1_009, 2).unwrap();
        assert_eq!((plan.start_s, plan.step_s, plan.points), (1_000, 5, 2));
        let rows = resample(&conn, &plan).unwrap();
        assert_eq!(
            rows,
            vec![
                TrafficBucket {
                    index: 0,
                    proto: "dns".into(),
                    bytes: 500,
                    packets: 5
                },
                TrafficBucket {
                    index: 0,
                    proto: "http".into(),
                    bytes: 5_000,
                    packets: 10
                },
                TrafficBucket {
                    index: 1,
                    proto: "dns".into(),
                    bytes: 500,
                    packets: 5
                },
                TrafficBucket {
                    index: 1,
                    proto: "http".into(),
                    bytes: 5_000,
                    packets: 10
                },
            ]
        );
        assert_eq!(traffic_totals(&conn).unwrap(), (11_005, 31));
    }

    #[test]
    fn linktypes_and_row_counts() {
        let conn = db();
        conn.execute_batch(
            "INSERT INTO chunks (id, path, linktypes) VALUES (0, 'a', '[1, 127]'), (1, 'b', '[1]'), \
             (2, 'c', '[]'), (3, 'd', '[\"x\", -1]');",
        )
        .unwrap();
        assert_eq!(linktypes(&conn).unwrap(), vec![1, 127]);
        assert_eq!(count_rows(&conn, "chunks").unwrap(), Some(4));
        assert_eq!(count_rows(&conn, "dns_queries").unwrap(), None);
        // A table created by an upgrade after the import: its analyzer did not run.
        conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, 'anomalies,chunks')",
            [crate::session::TABLES_ADDED_AFTER_IMPORT],
        )
        .unwrap();
        assert_eq!(count_rows(&conn, "chunks").unwrap(), None);
        assert_eq!(count_rows(&conn, "flows").unwrap(), Some(0));
        assert!(count_rows(&conn, "chunks; DROP TABLE meta").is_err());
        assert!(count_rows(&conn, "").is_err());
    }

    /// Sparse random traffic over three days (several labels, empty stretches, hour and day
    /// boundaries crossed).
    fn random_series(conn: &Connection, start: i64) {
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let labels = ["dns", "tls", "http", "other_udp"];
        let mut s = start;
        while s < start + 3 * DAY {
            for label in labels {
                if next() % 3 == 0 {
                    let bytes = i64::try_from(next() % 100_000).unwrap();
                    insert(conn, s, label, bytes, bytes / 100 + 1);
                }
            }
            s += i64::try_from(1 + next() % 90).unwrap();
        }
    }

    #[test]
    fn rollups_give_the_same_series_and_totals_as_the_seconds() {
        for start in [1_700_000_123, 1_000] {
            let conn = db();
            random_series(&conn, start);
            let (first, last) = traffic_bounds(&conn).unwrap().unwrap();
            let totals = traffic_totals(&conn).unwrap();
            let periods = [
                (first, last),
                (first + 4_000, first + 4_000 + 7_200),
                (first + 37, last - 1_234),
            ];
            let mut before = Vec::new();
            for (from, to) in periods {
                for points in [1, 7, 60, 500, 2_000] {
                    let plan = BucketPlan::new(from, to, points).unwrap();
                    before.push((plan, resample(&conn, &plan).unwrap()));
                }
            }
            // Read before the step: the one-second table.
            assert_eq!(source_table(&conn, 3_600).unwrap(), "timeseries");

            finalize(&conn).unwrap();
            // Idempotent.
            finalize(&conn).unwrap();
            assert_eq!(source_table(&conn, 7_200).unwrap(), "timeseries_hour");
            assert_eq!(source_table(&conn, 120).unwrap(), "timeseries_minute");
            assert_eq!(source_table(&conn, 30).unwrap(), "timeseries");
            assert_eq!(traffic_totals(&conn).unwrap(), totals);
            let mut used = std::collections::BTreeSet::new();
            for (plan, rows) in before {
                used.insert(source_table(&conn, plan.step_s).unwrap());
                assert_eq!(resample(&conn, &plan).unwrap(), rows, "{plan:?}");
            }
            assert_eq!(used.len(), 3, "every table is exercised: {used:?}");
            // Minute rows hold the sums of their seconds.
            let (minutes, sum): (i64, i64) = conn
                .query_row(
                    "SELECT count(*), sum(bytes) FROM timeseries_minute WHERE bucket_s % 60 = 0",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert!(minutes > 0);
            assert_eq!(u64::try_from(sum).unwrap(), totals.0);
        }
    }

    #[test]
    fn rollup_reads_use_the_primary_key() {
        let conn = db();
        for table in ["timeseries_minute", "timeseries_hour"] {
            let plan: Vec<String> = conn
                .prepare(&format!(
                    "EXPLAIN QUERY PLAN SELECT bucket_s, proto, bytes, packets FROM {table} \
                     WHERE bucket_s BETWEEN 1 AND 2"
                ))
                .unwrap()
                .query_map([], |r| r.get::<_, String>(3))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            let plan = plan.join(" | ");
            assert!(
                plan.contains("SEARCH") && plan.contains("PRIMARY KEY"),
                "{plan}"
            );
            assert!(!plan.contains("TEMP B-TREE"), "{plan}");
        }
        let plan: Vec<String> = conn
            .prepare(
                "EXPLAIN QUERY PLAN SELECT bucket_s, proto, bytes, packets FROM timeseries \
                 ORDER BY bucket_s, proto",
            )
            .unwrap()
            .query_map([], |r| r.get::<_, String>(3))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!plan.join(" ").contains("TEMP B-TREE"), "{plan:?}");
    }
}
