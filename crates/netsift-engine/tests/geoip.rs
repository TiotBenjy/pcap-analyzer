//! GeoIP during an import: `hosts.category` is always filled, `hosts.country` when a country
//! database is available (default location or `IngestOptions::geoip_path`), and a missing or
//! invalid database never fails the import.

use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};

use netsift_engine::{CancelToken, IngestOptions, IngestReport, ingest};
use netsift_fixtures::scenario::HttpGet;
use netsift_fixtures::scenarios::hosts;
use netsift_fixtures::{Encoding, Host, Scenario, write_file};
use netsift_geo::test_util::MmdbBuilder;
use netsift_store::{Catalog, OpenMode, SessionState};
use tempfile::TempDir;

/// A LAN workstation talking to public servers (IPv4 and IPv6), a documentation-range server
/// and the subnet broadcast.
fn capture(dir: &Path) -> PathBuf {
    let mut sc = Scenario::new();
    let gateway = hosts::router().mac;
    sc.http_get(
        hosts::workstation(),
        Host::v4(gateway, [81, 2, 3, 4]),
        &HttpGet::default(),
    );
    sc.http_get(
        hosts::workstation_v6(),
        Host::v6(gateway, Ipv6Addr::new(0x2a01, 0xe0a, 0, 0, 0, 0, 0, 1)),
        &HttpGet::default(),
    );
    sc.http_get(
        hosts::workstation(),
        Host::v4(gateway, [9, 9, 9, 9]),
        &HttpGet::default(),
    );
    sc.http_get(
        hosts::workstation(),
        hosts::web_server(),
        &HttpGet::default(),
    );
    sc.udp(hosts::workstation(), hosts::broadcast(), 137, 137, b"x");
    let path = dir.join("geo.pcapng");
    write_file(&path, sc.packets(), &Encoding::pcapng()).unwrap();
    path
}

fn database() -> Vec<u8> {
    MmdbBuilder::new()
        .network(IpAddr::from([81, 0, 0, 0]), 8, "FR")
        .network("2a01::".parse().unwrap(), 16, "FR")
        // Documentation range: reserved, never looked up even if present.
        .network(IpAddr::from([203, 0, 113, 0]), 24, "DE")
        .build()
}

fn hosts_table(catalog: &Catalog, report: &IngestReport) -> Vec<String> {
    let session = catalog
        .open_session(&report.session, OpenMode::ReadOnly)
        .unwrap();
    let mut stmt = session
        .conn()
        .prepare(
            "SELECT ip || ' ' || coalesce(category, '-') || ' ' || coalesce(country, '-') \
             FROM hosts ORDER BY ip",
        )
        .unwrap();
    stmt.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn import(catalog: &Catalog, input: &Path, options: &IngestOptions) -> IngestReport {
    let report = ingest(catalog, input, options, &CancelToken::new(), &mut |_| {}).unwrap();
    assert_eq!(
        catalog.get(&report.session).unwrap().unwrap().state,
        SessionState::Ready
    );
    report
}

const WITH_COUNTRIES: [&str; 6] = [
    "192.168.1.10 private -",
    "192.168.1.255 private -",
    "2001:db8:1::10 reserved -",
    "203.0.113.80 reserved -",
    "2a01:e0a::1 public FR",
    "81.2.3.4 public FR",
];

fn with_country_unknown(rows: &[&str]) -> Vec<String> {
    rows.iter()
        .map(|r| format!("{} -", r.rsplit_once(' ').unwrap().0))
        .collect()
}

fn expected(rows: &[&str]) -> Vec<String> {
    // 9.9.9.9 is public but absent from the test database.
    let mut all: Vec<String> = rows.iter().map(|r| (*r).to_owned()).collect();
    all.push("9.9.9.9 public -".to_owned());
    all.sort();
    all
}

#[test]
fn database_at_the_default_location_fills_countries() {
    let tmp = TempDir::new().unwrap();
    let data = tmp.path().join("data");
    let catalog = Catalog::open(&data).unwrap();
    let db_path = netsift_geo::default_path(&data);
    std::fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    std::fs::write(&db_path, database()).unwrap();

    let input = capture(tmp.path());
    let report = import(&catalog, &input, &IngestOptions::default());
    assert_eq!(hosts_table(&catalog, &report), expected(&WITH_COUNTRIES));
}

#[test]
fn explicit_database_path_fills_countries() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let db_path = tmp.path().join("elsewhere.mmdb");
    std::fs::write(&db_path, database()).unwrap();

    let input = capture(tmp.path());
    let options = IngestOptions {
        geoip_path: Some(db_path),
        shards: Some(3),
        ..IngestOptions::default()
    };
    let report = import(&catalog, &input, &options);
    assert_eq!(hosts_table(&catalog, &report), expected(&WITH_COUNTRIES));
}

#[test]
fn missing_or_invalid_database_leaves_countries_unknown() {
    let tmp = TempDir::new().unwrap();
    let catalog = Catalog::open(tmp.path().join("data")).unwrap();
    let input = capture(tmp.path());
    let corrupt = tmp.path().join("corrupt.mmdb");
    std::fs::write(&corrupt, b"definitely not a MaxMind database").unwrap();

    let unknown = expected(
        &with_country_unknown(&WITH_COUNTRIES)
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    for geoip_path in [None, Some(tmp.path().join("missing.mmdb")), Some(corrupt)] {
        let options = IngestOptions {
            geoip_path,
            ..IngestOptions::default()
        };
        let report = import(&catalog, &input, &options);
        assert_eq!(hosts_table(&catalog, &report), unknown);
    }
}
