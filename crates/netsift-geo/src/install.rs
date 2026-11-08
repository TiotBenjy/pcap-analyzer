//! Validation and atomic installation of a replacement country database (downloaded or chosen
//! by the user). Everything here treats the bytes as hostile: sizes are bounded while reading,
//! the database must open, be a country database and answer control lookups before it replaces
//! the current file, and a failure leaves the current file untouched.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;
use maxminddb::Reader;

use crate::db::{COUNTRY_PATH, GeoDb, GeoError, MAX_DB_BYTES};

/// Larger gzip-compressed databases are refused (the published file is about 4 MiB).
pub const MAX_COMPRESSED_BYTES: u64 = 32 << 20;

/// Public addresses of well-known anycast resolvers: a usable country database maps at least
/// one of them to a country.
const CONTROL_IPS: [IpAddr; 4] = [
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
];

/// Longest `database_type` echoed back in an error.
const MAX_TYPE_ECHO: usize = 64;

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Database bytes from a raw `.mmdb` or a gzip-compressed `.mmdb.gz` (detected by its magic
/// number), with both sizes bounded: [`MAX_COMPRESSED_BYTES`] compressed, [`MAX_DB_BYTES`]
/// decompressed (checked while inflating, never after).
pub fn decode_database(raw: Vec<u8>) -> Result<Vec<u8>, GeoError> {
    if !raw.starts_with(&GZIP_MAGIC) {
        return if len_u64(&raw) > MAX_DB_BYTES {
            Err(GeoError::TooLarge)
        } else {
            Ok(raw)
        };
    }
    if len_u64(&raw) > MAX_COMPRESSED_BYTES {
        return Err(GeoError::TooLarge);
    }
    let mut out = Vec::new();
    GzDecoder::new(raw.as_slice())
        .take(MAX_DB_BYTES + 1)
        .read_to_end(&mut out)
        .map_err(GeoError::Compression)?;
    if len_u64(&out) > MAX_DB_BYTES {
        return Err(GeoError::TooLarge);
    }
    Ok(out)
}

/// Reads a database file chosen by the user (`.mmdb` or `.mmdb.gz`), bounded by
/// [`MAX_DB_BYTES`] whatever its declared size, then decodes it with [`decode_database`].
pub fn read_database_file(path: &Path) -> Result<Vec<u8>, GeoError> {
    let mut raw = Vec::new();
    File::open(path)?
        .take(MAX_DB_BYTES + 1)
        .read_to_end(&mut raw)?;
    decode_database(raw)
}

/// Checks that `reader` holds a usable country database: its type names a country database
/// (`DBIP-Country-Lite`, `GeoLite2-Country`...) and the control lookups answer without error,
/// at least one of them with a country.
pub(crate) fn check_country<S: AsRef<[u8]>>(reader: &Reader<S>) -> Result<(), GeoError> {
    let kind = &reader.metadata().database_type;
    if !kind.to_ascii_lowercase().contains("country") {
        let echo: String = kind
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_TYPE_ECHO)
            .collect();
        return Err(GeoError::NotCountry(echo));
    }
    let mut answered = 0usize;
    for ip in CONTROL_IPS {
        let code = reader
            .lookup(ip)
            .and_then(|r| r.decode_path::<String>(&COUNTRY_PATH))?;
        if code.is_some_and(|c| c.len() == 2 && c != "ZZ") {
            answered += 1;
        }
    }
    if answered == 0 {
        return Err(GeoError::NoControlAnswer);
    }
    Ok(())
}

/// Validates `bytes` (decoded database, see [`decode_database`]) and installs them at `target`:
/// written to a temporary file of the same folder, flushed to disk, then renamed over `target`
/// (atomic on the same file system). Returns the new database, ready to use. On any error the
/// previous file at `target` is left as it was and the temporary file is removed.
pub fn install(target: &Path, bytes: Vec<u8>) -> Result<GeoDb, GeoError> {
    if len_u64(&bytes) > MAX_DB_BYTES {
        return Err(GeoError::TooLarge);
    }
    check_country(&Reader::from_source(bytes.as_slice())?)?;
    let dir = target.parent().ok_or_else(|| {
        GeoError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the database path has no parent folder",
        ))
    })?;
    std::fs::create_dir_all(dir)?;
    let tmp = temp_path(dir, target);
    let written = write_synced(&tmp, &bytes).and_then(|()| std::fs::rename(&tmp, target));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(GeoError::Io(e));
    }
    sync_dir(dir);
    GeoDb::from_bytes(bytes)
}

fn write_synced(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Makes the rename durable (POSIX); best effort, and not possible on Windows.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Unique hidden name next to `target`: process id, time and a counter, created with
/// `create_new` so an existing file is never reused.
fn temp_path(dir: &Path, target: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let name = target
        .file_name()
        .map_or_else(|| "geoip".into(), |n| n.to_string_lossy().into_owned());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!(".{name}.{}.{nanos}.{n}.tmp", std::process::id()))
}

fn len_u64(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;
    use crate::test_util::MmdbBuilder;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn country_db(code: &str) -> Vec<u8> {
        MmdbBuilder::new()
            .network(ip("8.8.8.0"), 24, code)
            .network(ip("81.0.0.0"), 8, code)
            .build()
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    fn files_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn decodes_raw_and_gzip_databases() {
        let raw = country_db("FR");
        assert_eq!(decode_database(raw.clone()).unwrap(), raw);
        assert_eq!(decode_database(gzip(&raw)).unwrap(), raw);
        // A gzip header followed by garbage.
        let mut broken = gzip(&raw);
        broken.truncate(20);
        assert!(matches!(
            decode_database(broken),
            Err(GeoError::Compression(_))
        ));
    }

    #[test]
    fn sizes_are_bounded_while_decoding() {
        // Inflates beyond MAX_DB_BYTES: refused once the limit is crossed.
        let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
        let zeros = vec![0u8; 1 << 20];
        for _ in 0..=(MAX_DB_BYTES >> 20) {
            enc.write_all(&zeros).unwrap();
        }
        let bomb = enc.finish().unwrap();
        assert!(len_u64(&bomb) < MAX_COMPRESSED_BYTES);
        assert!(matches!(decode_database(bomb), Err(GeoError::TooLarge)));

        // Compressed size above the bound (only the magic matters for the check).
        let mut big = vec![0u8; usize::try_from(MAX_COMPRESSED_BYTES).unwrap() + 1];
        big[..2].copy_from_slice(&GZIP_MAGIC);
        assert!(matches!(decode_database(big), Err(GeoError::TooLarge)));

        let raw = vec![0u8; usize::try_from(MAX_DB_BYTES).unwrap() + 1];
        assert!(matches!(decode_database(raw), Err(GeoError::TooLarge)));
    }

    #[test]
    fn reads_files_with_a_bound() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("db.mmdb.gz");
        std::fs::write(&path, gzip(&country_db("FR"))).unwrap();
        assert_eq!(read_database_file(&path).unwrap(), country_db("FR"));

        let huge = tmp.path().join("huge.mmdb");
        File::create(&huge)
            .unwrap()
            .set_len(MAX_DB_BYTES + 1)
            .unwrap();
        assert!(matches!(read_database_file(&huge), Err(GeoError::TooLarge)));
        assert!(read_database_file(&tmp.path().join("missing")).is_err_and(|e| e.is_not_found()));
    }

    #[test]
    fn only_country_databases_that_answer_are_accepted() {
        let check = |bytes: Vec<u8>| check_country(&Reader::from_source(bytes).unwrap());
        check(country_db("US")).unwrap();

        let city = MmdbBuilder::new()
            .database_type("DBIP-City-Lite")
            .network(ip("8.8.8.0"), 24, "US")
            .build();
        let err = check(city).unwrap_err();
        assert!(
            matches!(&err, GeoError::NotCountry(t) if t == "DBIP-City-Lite"),
            "{err}"
        );

        // A country database that knows none of the control addresses.
        let empty = MmdbBuilder::new().network(ip("81.0.0.0"), 8, "FR").build();
        assert!(matches!(check(empty), Err(GeoError::NoControlAnswer)));
        let unknown = MmdbBuilder::new().network(ip("8.8.8.0"), 24, "ZZ").build();
        assert!(matches!(check(unknown), Err(GeoError::NoControlAnswer)));

        // Control characters and long types are not echoed as is.
        let odd = MmdbBuilder::new()
            .database_type(&format!("x\u{7}{}", "y".repeat(200)))
            .build();
        let GeoError::NotCountry(echo) = check(odd).unwrap_err() else {
            panic!("expected NotCountry");
        };
        assert_eq!(echo.chars().count(), MAX_TYPE_ECHO);
        assert!(!echo.contains('\u{7}'));
    }

    #[test]
    fn install_replaces_the_file_atomically() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("geoip").join(crate::DB_FILE_NAME);
        let db = install(&target, country_db("FR")).unwrap();
        assert_eq!(db.country(ip("8.8.8.8")).unwrap().as_str(), "FR");
        assert_eq!(std::fs::read(&target).unwrap(), country_db("FR"));

        let db = install(&target, country_db("DE")).unwrap();
        assert_eq!(db.country(ip("81.1.1.1")).unwrap().as_str(), "DE");
        assert_eq!(std::fs::read(&target).unwrap(), country_db("DE"));
        // No temporary file left behind.
        assert_eq!(
            files_in(target.parent().unwrap()),
            [crate::DB_FILE_NAME.to_owned()]
        );
    }

    #[test]
    fn a_refused_database_leaves_the_current_one_intact() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join(crate::DB_FILE_NAME);
        install(&target, country_db("FR")).unwrap();

        for bad in [
            b"not a database".to_vec(),
            MmdbBuilder::new().database_type("City").build(),
            MmdbBuilder::new().network(ip("81.0.0.0"), 8, "FR").build(),
        ] {
            assert!(install(&target, bad).is_err());
            assert_eq!(std::fs::read(&target).unwrap(), country_db("FR"));
        }
        // A write failure (the target is a non-empty folder) removes the temporary file.
        let blocked = tmp.path().join("blocked");
        std::fs::create_dir_all(blocked.join("inside")).unwrap();
        assert!(matches!(
            install(&blocked, country_db("FR")),
            Err(GeoError::Io(_))
        ));
        assert_eq!(
            files_in(tmp.path()),
            ["blocked".to_owned(), crate::DB_FILE_NAME.to_owned()]
        );
    }
}
