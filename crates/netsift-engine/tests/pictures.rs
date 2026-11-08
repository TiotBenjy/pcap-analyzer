//! End-to-end imports of HTTP images (task P3.6): selection of the stored bodies, the
//! `objects` table, thumbnails, and their independence from the chunking and the shard count
//! (an image cut between two chunk files included).

use std::path::{Path, PathBuf};

use netsift_engine::{CancelToken, IngestOptions, IngestReport, ingest};
use netsift_fixtures::images::{GALLERY_OBJECTS, gallery};
use netsift_fixtures::{Encoding, Naming, Scenario, SplitBy, SplitOptions, split_to_dir, write_file};
use netsift_store::{Catalog, OpenMode, SessionState};
use tempfile::TempDir;

fn run(catalog: &Catalog, input: &Path, shards: usize) -> IngestReport {
    let options = IngestOptions {
        shards: Some(shards),
        ..IngestOptions::default()
    };
    let report = ingest(catalog, input, &options, &CancelToken::new(), &mut |_| {}).unwrap();
    assert_eq!(report.state, SessionState::Ready);
    report
}

fn files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Comparable content of `objects` (everything but nothing order-dependent is left out).
fn object_rows(catalog: &Catalog, report: &IngestReport) -> Vec<String> {
    let session = catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap();
    let mut stmt = session
        .conn()
        .prepare(
            "SELECT id || ' ' || substr(sha256, 1, 12) || ' ' || mime || ' ' || size || ' ' || \
             coalesce(width, '-') || 'x' || coalesce(height, '-') || ' ' || thumb || ' x' || \
             occurrences || ' ' || coalesce(host, '-') || coalesce(uri, '') || ' ' || \
             coalesce(declared_type, '-') FROM objects ORDER BY id",
        )
        .unwrap();
    stmt.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// The gallery, with the largest image response located to cut it between two chunks.
fn traffic() -> (Vec<netsift_fixtures::Packet>, usize) {
    let mut sc = Scenario::new();
    gallery(&mut sc);
    let packets = sc.into_packets();
    // The longest run of full-size server segments is the largest image: cut in its middle.
    let (mut best, mut run_start, mut best_len) = (0, 0, 0);
    for (i, p) in packets.iter().enumerate() {
        if p.data.len() < 1000 {
            run_start = i + 1;
        } else if i + 1 - run_start > best_len {
            best_len = i + 1 - run_start;
            best = run_start + best_len / 2;
        }
    }
    assert!(best_len > 10, "no large image found");
    (packets, best)
}

#[test]
fn gallery_objects_do_not_depend_on_chunking_nor_shards() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let (packets, middle) = traffic();

    let single = tmp.path().join("single.pcap");
    write_file(&single, &packets, &Encoding::pcap()).unwrap();
    let reference = run(&catalog, &single, 1);
    let expected = object_rows(&catalog, &reference);
    insta::assert_snapshot!(expected.join("\n"));
    assert_eq!(expected.len(), GALLERY_OBJECTS);

    let dir = tmp.path().join("chunks");
    let opts = SplitOptions::new(SplitBy::At(vec![middle]), Naming::Dumpcap)
        .with_encoding(Encoding::pcapng());
    assert_eq!(split_to_dir(&dir, &packets, &opts).unwrap().1.len(), 2);
    for shards in [1, 4] {
        let report = run(&catalog, &dir, shards);
        assert_eq!(report.chunks_read, 2);
        assert_eq!(object_rows(&catalog, &report), expected, "{shards} shards");
    }
}

#[test]
fn only_images_reach_the_disk_and_thumbnails_are_generated() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let (packets, _) = traffic();
    let file = tmp.path().join("gallery.pcap");
    write_file(&file, &packets, &Encoding::pcap()).unwrap();
    let report = run(&catalog, &file, 2);
    let dir = catalog.session_dir(&report.session);

    // One blob per distinct image, nothing else (page, script, form, fake image).
    let blobs = files(&dir.join("blobs"));
    assert_eq!(blobs.len(), GALLERY_OBJECTS, "{blobs:?}");
    for blob in &blobs {
        let data = std::fs::read(blob).unwrap();
        assert!(!data.starts_with(b"<html") && !data.starts_with(b"<!doctype"));
        assert!(!data.windows(8).any(|w| w == b"password"));
    }
    let session = catalog.open_session(&report.session, OpenMode::ReadOnly).unwrap();
    let conn = session.conn();
    let count = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
    assert_eq!(count("SELECT count(*) FROM http_transactions WHERE req_sha256 IS NOT NULL"), 0);
    // Thumbnails: every raster image but the truncated JPEG; the SVG is never rasterized.
    assert_eq!(count("SELECT count(*) FROM objects WHERE thumb = 'none'"), 1);
    assert_eq!(count("SELECT count(*) FROM objects WHERE thumb = 'failed'"), 1);
    let ready = count("SELECT count(*) FROM objects WHERE thumb = 'ready'");
    assert_eq!(usize::try_from(ready).unwrap(), GALLERY_OBJECTS - 2);
    let thumbs = files(&dir.join("thumbs"));
    assert_eq!(thumbs.len(), GALLERY_OBJECTS - 2, "{thumbs:?}");
    for t in &thumbs {
        assert_eq!(t.extension().and_then(|e| e.to_str()), Some("png"));
        let img = image::open(t).unwrap();
        assert!(img.width() <= 320 && img.height() <= 320);
    }
    let failed: String = conn
        .query_row("SELECT uri FROM objects WHERE thumb = 'failed'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(failed, "/broken/cut.jpg");
}

#[test]
fn the_blob_budget_bounds_the_session() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let (packets, _) = traffic();
    let file = tmp.path().join("gallery.pcap");
    write_file(&file, &packets, &Encoding::pcap()).unwrap();
    let options = IngestOptions {
        shards: Some(1),
        max_blob_bytes: 2000,
        ..IngestOptions::default()
    };
    let report = ingest(&catalog, &file, &options, &CancelToken::new(), &mut |_| {}).unwrap();
    let dir = catalog.session_dir(&report.session);
    let total: u64 = files(&dir.join("blobs"))
        .iter()
        .map(|p| std::fs::metadata(p).unwrap().len())
        .sum();
    assert!(total <= 2000, "{total}");
    assert!(object_rows(&catalog, &report).len() < GALLERY_OBJECTS);
}
