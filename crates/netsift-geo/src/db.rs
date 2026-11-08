//! Country lookups in a DB-IP IP-to-Country Lite database (`MaxMind` DB format).

use std::fmt;
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use lru::LruCache;
use maxminddb::{PathElement, Reader};

use crate::category::AddressCategory;
use crate::country::CountryCode;

/// Directory of the GeoIP database inside the data directory (written by `./x.sh geoip`).
pub const DB_DIR: &str = "geoip";
/// File name of the database (DB-IP IP-to-Country Lite).
pub const DB_FILE_NAME: &str = "dbip-country-lite.mmdb";
/// Number of addresses kept by the lookup cache of a [`GeoDb`].
pub const DEFAULT_CACHE_CAPACITY: usize = 65_536;
/// Larger files are refused (the country database is about 10 MiB).
pub const MAX_DB_BYTES: u64 = 64 << 20;

/// The cache is split in independently locked shards so that flow shards rarely contend.
const CACHE_SHARDS: usize = 16;

/// Default location of the database: `<data_dir>/geoip/dbip-country-lite.mmdb`.
pub fn default_path(data_dir: &Path) -> PathBuf {
    data_dir.join(DB_DIR).join(DB_FILE_NAME)
}

/// Error of [`GeoDb::open`].
#[derive(Debug, thiserror::Error)]
pub enum GeoError {
    #[error("cannot read the GeoIP database: {0}")]
    Io(#[from] std::io::Error),
    #[error("GeoIP database larger than {MAX_DB_BYTES} bytes")]
    TooLarge,
    #[error("invalid GeoIP database: {0}")]
    Invalid(#[from] maxminddb::MaxMindDbError),
}

impl GeoError {
    /// The database file does not exist (the usual case before `./x.sh geoip`).
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Io(e) if e.kind() == std::io::ErrorKind::NotFound)
    }
}

type Shard = Mutex<LruCache<IpAddr, Option<CountryCode>>>;

/// A country database, read-only and shareable between threads (`Arc<GeoDb>`).
///
/// Lookups go through a bounded LRU cache. A lookup never fails: an address that is not
/// public, absent from the database or unreadable (corrupt database) has no country. A
/// corrupt record is reported once per database through `tracing`.
pub struct GeoDb {
    reader: Reader<Vec<u8>>,
    cache: Box<[Shard]>,
    lookup_error_reported: AtomicBool,
}

impl fmt::Debug for GeoDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeoDb")
            .field("database_type", &self.database_type())
            .field("build_epoch", &self.build_epoch())
            .finish_non_exhaustive()
    }
}

impl GeoDb {
    /// Reads the database at `path` into memory.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, GeoError> {
        // Bounded read (no gap between a size check and the read).
        let mut bytes = Vec::new();
        std::fs::File::open(path.as_ref())?
            .take(MAX_DB_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_DB_BYTES {
            return Err(GeoError::TooLarge);
        }
        Self::from_bytes(bytes)
    }

    /// Database held in memory.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, GeoError> {
        Self::with_cache_capacity(bytes, DEFAULT_CACHE_CAPACITY)
    }

    /// Database held in memory, with a cache of about `capacity` addresses (at least one per
    /// cache shard).
    pub fn with_cache_capacity(bytes: Vec<u8>, capacity: usize) -> Result<Self, GeoError> {
        let reader = Reader::from_source(bytes)?;
        let per_shard =
            NonZeroUsize::new(capacity.div_ceil(CACHE_SHARDS)).unwrap_or(NonZeroUsize::MIN);
        let cache = (0..CACHE_SHARDS)
            .map(|_| Mutex::new(LruCache::new(per_shard)))
            .collect();
        Ok(Self {
            reader,
            cache,
            lookup_error_reported: AtomicBool::new(false),
        })
    }

    /// `database_type` of the metadata (`"DBIP-Country-Lite"`).
    pub fn database_type(&self) -> &str {
        &self.reader.metadata().database_type
    }

    /// Build time of the database, in seconds since the Unix epoch.
    pub fn build_epoch(&self) -> u64 {
        self.reader.metadata().build_epoch
    }

    /// Country of `ip`: `None` for addresses that are not [`AddressCategory::Public`] (without
    /// any lookup) and for addresses unknown to the database. IPv4-mapped IPv6 addresses are
    /// looked up as IPv4, and so are NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`) addresses
    /// whose embedded IPv4 address is public: the IPv4 host is the actual peer.
    pub fn country(&self, ip: IpAddr) -> Option<CountryCode> {
        let mut ip = ip.to_canonical();
        if AddressCategory::of(ip) != AddressCategory::Public {
            return None;
        }
        if let IpAddr::V6(v6) = ip
            && let Some(v4) = embedded_ipv4(v6)
            && AddressCategory::of(IpAddr::V4(v4)) == AddressCategory::Public
        {
            ip = IpAddr::V4(v4);
        }
        let shard = self.cache.get(shard_of(ip))?;
        if let Some(hit) = shard
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&ip)
        {
            return *hit;
        }
        let country = self.lookup(ip);
        shard
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .put(ip, country);
        country
    }

    fn lookup(&self, ip: IpAddr) -> Option<CountryCode> {
        const PATH: [PathElement<'static>; 2] =
            [PathElement::Key("country"), PathElement::Key("iso_code")];
        let code = self
            .reader
            .lookup(ip)
            .and_then(|r| r.decode_path::<String>(&PATH));
        match code {
            // "ZZ" is the user-assigned code for "unknown".
            Ok(code) => code
                .and_then(|c| CountryCode::new(&c))
                .filter(|c| c.as_str() != "ZZ"),
            Err(e) => {
                if !self.lookup_error_reported.swap(true, Ordering::Relaxed) {
                    tracing::warn!("GeoIP lookup failed, the database may be corrupt: {e}");
                }
                None
            }
        }
    }
}

/// IPv4 address carried by a NAT64 well-known prefix address (`64:ff9b::/96`, last 32 bits)
/// or a 6to4 address (`2002:AABB:CCDD::/48`, bits 16 to 47).
fn embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let pair = |hi: u16, lo: u16| Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo));
    match v6.segments() {
        [0x64, 0xff9b, 0, 0, 0, 0, hi, lo] | [0x2002, hi, lo, ..] => Some(pair(hi, lo)),
        _ => None,
    }
}

fn shard_of(ip: IpAddr) -> usize {
    let folded = match ip {
        IpAddr::V4(v4) => v4.octets().iter().fold(0u8, |a, b| a ^ b),
        IpAddr::V6(v6) => v6.octets().iter().fold(0u8, |a, b| a ^ b),
    };
    usize::from(folded) % CACHE_SHARDS
}

static WARNED_MISSING: AtomicBool = AtomicBool::new(false);
static WARNED_INVALID: AtomicBool = AtomicBool::new(false);

/// Opens the database at `path` for an import. A missing or invalid database is not an
/// error: countries are then unknown, and a warning is logged once per process (one for a
/// missing file, one for an invalid one).
pub fn open_or_warn(path: &Path) -> Option<Arc<GeoDb>> {
    match GeoDb::open(path) {
        Ok(db) => {
            tracing::debug!(path = %path.display(), ?db, "GeoIP database loaded");
            Some(Arc::new(db))
        }
        Err(e) => {
            let flag = if e.is_not_found() {
                &WARNED_MISSING
            } else {
                &WARNED_INVALID
            };
            if first_time(flag) {
                tracing::warn!(
                    path = %path.display(),
                    "GeoIP database unavailable, countries will be unknown: {e}"
                );
            }
            None
        }
    }
}

/// `true` the first time it is called with `flag`.
fn first_time(flag: &AtomicBool) -> bool {
    !flag.swap(true, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MmdbBuilder;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn sample() -> Vec<u8> {
        MmdbBuilder::new()
            .network(ip("81.0.0.0"), 8, "FR")
            .network(ip("8.8.8.0"), 24, "us")
            .network(ip("1.0.0.0"), 24, "ZZ")
            .network(ip("2a01::"), 16, "FR")
            .network(ip("2001:4860::"), 32, "US")
            // Inside private and documentation space: must never be returned.
            .network(ip("10.0.0.0"), 8, "DE")
            .network(ip("203.0.113.0"), 24, "DE")
            .network(ip("2001:db8::"), 32, "DE")
            .build()
    }

    fn country(db: &GeoDb, s: &str) -> Option<String> {
        db.country(ip(s)).map(|c| c.to_string())
    }

    #[test]
    fn public_addresses_get_their_country() {
        let db = GeoDb::from_bytes(sample()).unwrap();
        assert_eq!(db.database_type(), "NetSift-Test-Country");
        assert_eq!(country(&db, "81.2.3.4").as_deref(), Some("FR"));
        assert_eq!(country(&db, "81.255.255.255").as_deref(), Some("FR"));
        assert_eq!(country(&db, "8.8.8.8").as_deref(), Some("US"));
        assert_eq!(country(&db, "2a01:e0a::1").as_deref(), Some("FR"));
        assert_eq!(country(&db, "2001:4860:4860::8888").as_deref(), Some("US"));
        assert_eq!(country(&db, "::ffff:81.1.1.1").as_deref(), Some("FR"));
    }

    #[test]
    fn nat64_and_6to4_use_their_public_embedded_ipv4() {
        let db = GeoDb::from_bytes(sample()).unwrap();
        // 64:ff9b::81.2.3.4 and 2002:5102:0304:: carry 81.2.3.4.
        assert_eq!(country(&db, "64:ff9b::5102:304").as_deref(), Some("FR"));
        assert_eq!(country(&db, "2002:5102:304::1").as_deref(), Some("FR"));
        assert_eq!(country(&db, "64:ff9b::808:808").as_deref(), Some("US"));
        // Embedded IPv4 private or unknown: no country from the IPv4 side.
        assert_eq!(country(&db, "64:ff9b::a00:1"), None);
        assert_eq!(country(&db, "2002:a00:1::1"), None);
        assert_eq!(country(&db, "2002:909:909::1"), None);
        assert_eq!(
            embedded_ipv4("2001:db8::1".parse().unwrap()),
            None,
            "only NAT64 and 6to4 embed an IPv4 address"
        );
    }

    #[test]
    fn non_public_and_unknown_addresses_have_no_country() {
        let db = GeoDb::from_bytes(sample()).unwrap();
        for s in [
            "10.1.2.3",
            "203.0.113.5",
            "2001:db8::1",
            "192.168.1.1",
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "fe80::1",
            "::ffff:10.0.0.1",
            // Public but absent from the database.
            "82.0.0.1",
            "80.255.255.255",
            "9.9.9.9",
            "2a02::1",
            // "ZZ" means unknown.
            "1.0.0.1",
        ] {
            assert_eq!(country(&db, s), None, "{s}");
        }
    }

    #[test]
    fn cache_is_bounded_and_consistent() {
        let db = GeoDb::with_cache_capacity(sample(), 1).unwrap();
        for _ in 0..3 {
            for i in 0..=255u8 {
                let a = IpAddr::from([81, 0, 0, i]);
                assert_eq!(db.country(a).map(|c| c.to_string()).as_deref(), Some("FR"));
                let b = IpAddr::from([9, 0, 0, i]);
                assert_eq!(db.country(b), None);
            }
        }
        let cached: usize = db.cache.iter().map(|s| s.lock().unwrap().len()).sum();
        assert!(cached <= CACHE_SHARDS, "{cached} entries cached");
    }

    #[test]
    fn shared_between_threads() {
        let db = Arc::new(GeoDb::from_bytes(sample()).unwrap());
        let handles: Vec<_> = (0..4u8)
            .map(|t| {
                let db = Arc::clone(&db);
                std::thread::spawn(move || {
                    (0..=255u8)
                        .filter(|i| db.country(IpAddr::from([81, t, *i, 1])).is_some())
                        .count()
                })
            })
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), 256);
        }
    }

    #[test]
    fn missing_or_invalid_files_are_errors_for_open_and_none_for_open_or_warn() {
        let dir = std::env::temp_dir().join(format!("netsift-geo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let missing = dir.join("missing.mmdb");
        let err = GeoDb::open(&missing).unwrap_err();
        assert!(err.is_not_found(), "{err}");
        assert!(open_or_warn(&missing).is_none());

        let corrupt = dir.join("corrupt.mmdb");
        std::fs::write(&corrupt, b"not a maxmind database").unwrap();
        let err = GeoDb::open(&corrupt).unwrap_err();
        assert!(matches!(err, GeoError::Invalid(_)), "{err}");
        assert!(open_or_warn(&corrupt).is_none());

        // Oversized (sparse file): refused after reading at most MAX_DB_BYTES + 1 bytes.
        let huge = dir.join("huge.mmdb");
        std::fs::File::create(&huge)
            .unwrap()
            .set_len(MAX_DB_BYTES + 1)
            .unwrap();
        assert!(matches!(GeoDb::open(&huge), Err(GeoError::TooLarge)));

        // Truncated: the metadata marker is gone.
        let mut truncated = sample();
        truncated.truncate(truncated.len() / 2);
        assert!(GeoDb::from_bytes(truncated).is_err());

        let valid = dir.join("valid.mmdb");
        std::fs::write(&valid, sample()).unwrap();
        let db = open_or_warn(&valid).unwrap();
        assert_eq!(country(&db, "81.0.0.1").as_deref(), Some("FR"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn corrupt_data_section_gives_no_country() {
        let mut bytes = sample();
        // Overwrite the data section (just after the search tree and its 16-byte separator)
        // with an invalid control byte sequence: only the first record (81.0.0.0/8) is hit, the
        // metadata stays intact.
        let db = GeoDb::from_bytes(bytes.clone()).unwrap();
        let tree = usize::try_from(db.reader.metadata().node_count).unwrap() * 6;
        for b in bytes.iter_mut().skip(tree + 16).take(16) {
            *b = 0xff;
        }
        let db = GeoDb::from_bytes(bytes).unwrap();
        assert_eq!(country(&db, "81.2.3.4"), None);
        assert_eq!(country(&db, "81.2.3.4"), None, "cached");
        // Other records are intact.
        assert_eq!(country(&db, "8.8.8.8").as_deref(), Some("US"));
    }

    #[test]
    fn warnings_are_emitted_once() {
        let flag = AtomicBool::new(false);
        assert!(first_time(&flag));
        assert!(!first_time(&flag));
    }

    #[test]
    fn default_path_is_under_the_data_dir() {
        assert_eq!(
            default_path(Path::new("/data")),
            Path::new("/data/geoip/dbip-country-lite.mmdb")
        );
    }
}
