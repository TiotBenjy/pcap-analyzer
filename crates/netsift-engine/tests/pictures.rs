//! End-to-end imports of HTTP images (task P3.6): selection of the stored bodies, the
//! `objects` table, thumbnails, and their independence from the chunking and the shard count
//! (an image cut between two chunk files included).

use std::path::{Path, PathBuf};

use netsift_engine::{CancelToken, IngestOptions, IngestReport, ingest};
use netsift_fixtures::images::{GALLERY_OBJECTS, gallery};
use netsift_fixtures::{
    Encoding, Naming, Scenario, SplitBy, SplitOptions, split_to_dir, write_file,
};
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
    let session = catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap();
    let conn = session.conn();
    let count = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
    assert_eq!(
        count("SELECT count(*) FROM http_transactions WHERE req_sha256 IS NOT NULL"),
        0
    );
    // Thumbnails: every raster image but the truncated JPEG; the SVG is never rasterized.
    assert_eq!(
        count("SELECT count(*) FROM objects WHERE thumb = 'none'"),
        1
    );
    assert_eq!(
        count("SELECT count(*) FROM objects WHERE thumb = 'failed'"),
        1
    );
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
        .query_row("SELECT uri FROM objects WHERE thumb = 'failed'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(failed, "/broken/cut.jpg");
}

/// The blob files of a session, as `<sha>` names.
fn blob_names(catalog: &Catalog, report: &IngestReport) -> Vec<String> {
    let mut names: Vec<String> = files(&catalog.session_dir(&report.session).join("blobs"))
        .iter()
        .filter_map(|p| p.file_name()?.to_str().map(ToOwned::to_owned))
        .collect();
    names.sort();
    names
}

#[test]
fn a_large_download_in_parallel_does_not_starve_the_images() {
    use netsift_fixtures::Host;
    use netsift_fixtures::scenario::TcpOptions;

    // A 3 MiB download (not an image) spread over the time of the gallery, with a shard
    // budget of 1 MiB: only its preview may be kept, whatever shard it shares.
    let mut gallery_sc = Scenario::new();
    gallery(&mut gallery_sc);
    let start = gallery_sc.packets().first().map_or(0, |p| p.ts_ns);
    let mut packets = gallery_sc.into_packets();
    let mut sc = Scenario::starting_at(start - 500_000_000).with_seed(99);
    let client = Host::v4([0x02, 0, 0x5e, 0x10, 0, 0x30], [192, 168, 1, 30]);
    let server = Host::v4([0x02, 0, 0x5e, 0x10, 0, 0x01], [198, 51, 100, 40]);
    let mut s = sc.tcp_open(client, server, &TcpOptions::new(80));
    s.client_send(b"GET /backup.tar HTTP/1.1\r\nHost: files.example.test\r\n\r\n");
    let size = 3 * 1024 * 1024;
    s.server_send(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-tar\r\nContent-Length: {size}\r\n\r\n"
        )
        .as_bytes(),
    );
    // Two thirds before the gallery starts, the rest once it is over: the body stays open
    // (and, before ADR-016's retention rules, its bytes stayed counted) during the gallery.
    s.server_send(&vec![0x55u8; size * 2 / 3]);
    s.scenario().advance(2_000_000_000);
    s.server_send(&vec![0x55u8; size - size * 2 / 3]);
    s.close();
    packets.extend(sc.into_packets());
    packets.sort_by_key(|p| p.ts_ns);

    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let file = tmp.path().join("mixed.pcap");
    write_file(&file, &packets, &Encoding::pcap()).unwrap();
    let mut results = Vec::new();
    for shards in [1, 4] {
        let mut options = IngestOptions {
            shards: Some(shards),
            ..IngestOptions::default()
        };
        options.analyzers.config_mut().http.max_retained_bytes = 1024 * 1024;
        let report = ingest(&catalog, &file, &options, &CancelToken::new(), &mut |_| {}).unwrap();
        results.push((
            object_rows(&catalog, &report),
            blob_names(&catalog, &report),
        ));
    }
    assert_eq!(results[0].0.len(), GALLERY_OBJECTS, "{:#?}", results[0].0);
    assert_eq!(results[0].1.len(), GALLERY_OBJECTS);
    assert_eq!(results[0], results[1]);
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
