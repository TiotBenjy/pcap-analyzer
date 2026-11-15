//! Pure parts of the update check, without I/O: the release JSON of GitHub, the version
//! comparison, the choice of the installer for this platform and the `SHA256SUMS.txt` lookup.
//! Everything here comes from the network: bounded, never trusted.

use std::cmp::Ordering;

use reqwest::Url;
use semver::Version;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::outbound::parse_sha256;

/// Assets of a release considered at most (a release has 7 files).
pub(crate) const MAX_ASSETS: usize = 64;
/// Characters of release notes kept at most; the rest is cut.
pub(crate) const MAX_NOTES_CHARS: usize = 8_000;
/// Longest asset name accepted (also the default file name of the save dialog).
const MAX_ASSET_NAME: usize = 200;
/// Longest URL kept from the JSON.
const MAX_URL_LEN: usize = 1_024;

/// `GET /repos/{owner}/{repo}/releases/latest`: the fields read, the others are ignored.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct GhRelease {
    pub(crate) tag_name: String,
    #[serde(default)]
    pub(crate) draft: bool,
    #[serde(default)]
    pub(crate) prerelease: bool,
    #[serde(default)]
    pub(crate) body: Option<String>,
    #[serde(default)]
    pub(crate) html_url: Option<String>,
    #[serde(default)]
    pub(crate) assets: Vec<GhAsset>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct GhAsset {
    pub(crate) name: String,
    pub(crate) size: u64,
    pub(crate) browser_download_url: String,
}

/// Package format of an installer, and of the installed application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export)]
pub enum PackageFormat {
    /// Linux `.AppImage`.
    AppImage,
    /// Linux `.deb` (Debian, Ubuntu).
    Deb,
    /// Linux `.rpm` (Fedora, openSUSE).
    Rpm,
    /// Windows NSIS installer (`-setup.exe`).
    Nsis,
    /// Windows `.msi`.
    Msi,
    /// macOS `.dmg` (universal).
    Dmg,
}

impl PackageFormat {
    /// Format of a published file, from its name (as published by `release.yml`).
    fn of_name(name: &str) -> Option<Self> {
        let lower = name.to_ascii_lowercase();
        [
            (".appimage", Self::AppImage),
            (".deb", Self::Deb),
            (".rpm", Self::Rpm),
            ("-setup.exe", Self::Nsis),
            (".msi", Self::Msi),
            (".dmg", Self::Dmg),
        ]
        .into_iter()
        .find_map(|(suffix, format)| lower.ends_with(suffix).then_some(format))
    }

    /// Operating system (`std::env::consts::OS`) the format installs on.
    fn os(self) -> &'static str {
        match self {
            Self::AppImage | Self::Deb | Self::Rpm => "linux",
            Self::Nsis | Self::Msi => "windows",
            Self::Dmg => "macos",
        }
    }

    /// Order of the formats of one system when the installed one is unknown: the `AppImage` runs
    /// on any distribution, the NSIS installer is the default of Windows.
    fn rank(self) -> u8 {
        match self {
            Self::AppImage | Self::Nsis | Self::Dmg => 0,
            Self::Deb | Self::Msi => 1,
            Self::Rpm => 2,
        }
    }
}

/// Where the application runs: `std::env::consts` and the installed format, when known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Platform {
    pub(crate) os: &'static str,
    pub(crate) arch: &'static str,
    pub(crate) installed: Option<PackageFormat>,
}

impl Platform {
    pub(crate) fn current() -> Self {
        Self {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            installed: None,
        }
    }
}

/// Version of a tag (`v1.2.3` or `1.2.3`).
pub(crate) fn tag_version(tag: &str) -> Option<Version> {
    let tag = tag.trim();
    let bare = tag
        .strip_prefix('v')
        .or_else(|| tag.strip_prefix('V'))
        .unwrap_or(tag);
    Version::parse(bare).ok()
}

/// Version of `release` when it is newer than `current`: drafts, prereleases (flag or `SemVer`
/// suffix) and unparsable tags are ignored; build metadata does not count.
pub(crate) fn newer_version(release: &GhRelease, current: &str) -> Option<Version> {
    if release.draft || release.prerelease {
        return None;
    }
    let version = tag_version(&release.tag_name)?;
    let current = Version::parse(current).ok()?;
    (version.pre.is_empty() && version.cmp_precedence(&current) == Ordering::Greater)
        .then_some(version)
}

/// The published file may be offered: plain name (no path, no control character, not hidden).
fn valid_asset_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_ASSET_NAME
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-+~".contains(c))
}

/// The file is built for `arch` (`universal` dmg on macOS).
fn arch_matches(name: &str, platform: &Platform) -> bool {
    let lower = name.to_ascii_lowercase();
    if platform.os == "macos" && lower.contains("universal") {
        return true;
    }
    let tokens: &[&str] = match platform.arch {
        "x86_64" => &["amd64", "x86_64", "x64"],
        "aarch64" => &["aarch64", "arm64"],
        _ => &[],
    };
    tokens.iter().any(|t| lower.contains(t))
}

/// An installer of the release for this platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Installer {
    pub(crate) format: PackageFormat,
    pub(crate) name: String,
    pub(crate) size: u64,
    pub(crate) url: String,
}

/// Installers of `assets` for `platform` whose URL starts with `download_prefix`: the installed
/// format first, then the default order of the system ([`PackageFormat::rank`]).
pub(crate) fn installers(
    assets: &[GhAsset],
    platform: &Platform,
    download_prefix: &str,
) -> Vec<Installer> {
    let mut out: Vec<Installer> = assets
        .iter()
        .take(MAX_ASSETS)
        .filter(|a| {
            valid_asset_name(&a.name) && valid_url(&a.browser_download_url, download_prefix)
        })
        .filter_map(|a| {
            let format = PackageFormat::of_name(&a.name)?;
            (format.os() == platform.os && arch_matches(&a.name, platform)).then(|| Installer {
                format,
                name: a.name.clone(),
                size: a.size,
                url: a.browser_download_url.clone(),
            })
        })
        .collect();
    out.sort_by(|a, b| {
        let installed = |i: &Installer| Some(i.format) != platform.installed;
        (installed(a), a.format.rank(), &a.name).cmp(&(installed(b), b.format.rank(), &b.name))
    });
    out
}

/// `url` points under `prefix` (a trusted URL ending with `/`): same scheme, host and port, no
/// credentials, query or fragment, path segments of `prefix` first (the first two, owner and
/// repository, compared without case) followed by at least one non-empty segment. Dot segments
/// (`.`, `..`, also percent-encoded) and backslashes are refused before parsing, since parsing
/// would resolve them.
pub(crate) fn valid_url(url: &str, prefix: &str) -> bool {
    if url.len() > MAX_URL_LEN
        || url
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
        || url.to_ascii_lowercase().contains("%2e")
        || url
            .split(['/', '?', '#'])
            .any(|seg| seg == "." || seg == "..")
    {
        return false;
    }
    let (Ok(url), Ok(prefix)) = (Url::parse(url), Url::parse(prefix)) else {
        return false;
    };
    if url.scheme() != prefix.scheme()
        || url.host_str() != prefix.host_str()
        || url.port_or_known_default() != prefix.port_or_known_default()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    let (Some(segments), Some(expected)) = (url.path_segments(), prefix.path_segments()) else {
        return false;
    };
    let segments: Vec<&str> = segments.collect();
    let expected: Vec<&str> = expected.filter(|s| !s.is_empty()).collect();
    let Some(rest) = segments.get(expected.len()..) else {
        return false;
    };
    let same_prefix = segments
        .iter()
        .zip(&expected)
        .enumerate()
        .all(|(i, (a, b))| {
            if i < 2 {
                a.eq_ignore_ascii_case(b)
            } else {
                a == b
            }
        });
    same_prefix && !rest.is_empty() && rest.iter().all(|s| !s.is_empty())
}

/// Expected SHA-256 (lowercase) of `name` in a `sha256sum` output: `<hash>  <name>` (text mode)
/// or `<hash> *<name>` (binary mode), one file per line. Missing, invalid or contradictory
/// entries give `None`.
pub(crate) fn expected_sha256(sums: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(sums).ok()?;
    let mut found: Option<String> = None;
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let Some((hash, rest)) = line.split_once(' ') else {
            continue;
        };
        let file = rest.strip_prefix(' ').or_else(|| rest.strip_prefix('*'));
        if file != Some(name) || parse_sha256(hash).is_none() {
            continue;
        }
        let hash = hash.to_ascii_lowercase();
        match &found {
            Some(previous) if *previous != hash => return None,
            _ => found = Some(hash),
        }
    }
    found
}

/// Release notes as plain text: line breaks and tabs kept, other control and bidirectional
/// formatting characters dropped, at most [`MAX_NOTES_CHARS`] characters. True when cut.
pub(crate) fn plain_notes(body: Option<&str>) -> (String, bool) {
    let mut out = String::new();
    let mut count = 0;
    let mut truncated = false;
    for c in body.unwrap_or_default().chars() {
        let keep = c == '\n' || c == '\t' || !(c.is_control() || is_bidi_control(c));
        if !keep {
            continue;
        }
        if count == MAX_NOTES_CHARS {
            truncated = true;
            break;
        }
        out.push(c);
        count += 1;
    }
    let trimmed = out.trim_end().len();
    out.truncate(trimmed);
    (out, truncated)
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "https://github.com/o/r/releases/download/";

    fn asset(name: &str) -> GhAsset {
        GhAsset {
            name: name.to_owned(),
            size: 1_000,
            browser_download_url: format!("{PREFIX}v0.2.0/{name}"),
        }
    }

    /// The files `release.yml` publishes for 0.2.0 (Tauri names).
    fn published() -> Vec<GhAsset> {
        [
            "NetSift_0.2.0_amd64.AppImage",
            "NetSift_0.2.0_amd64.deb",
            "NetSift-0.2.0-1.x86_64.rpm",
            "NetSift_0.2.0_x64-setup.exe",
            "NetSift_0.2.0_x64_en-US.msi",
            "NetSift_0.2.0_universal.dmg",
            "SHA256SUMS.txt",
        ]
        .map(asset)
        .to_vec()
    }

    fn release(tag: &str) -> GhRelease {
        GhRelease {
            tag_name: tag.to_owned(),
            draft: false,
            prerelease: false,
            body: None,
            html_url: None,
            assets: Vec::new(),
        }
    }

    fn names(platform: Platform) -> Vec<String> {
        installers(&published(), &platform, PREFIX)
            .into_iter()
            .map(|i| i.name)
            .collect()
    }

    fn linux(installed: Option<PackageFormat>) -> Platform {
        Platform {
            os: "linux",
            arch: "x86_64",
            installed,
        }
    }

    #[test]
    fn tags_parse_with_or_without_v() {
        assert_eq!(tag_version("v1.2.3"), Some(Version::new(1, 2, 3)));
        assert_eq!(tag_version("1.2.3"), Some(Version::new(1, 2, 3)));
        assert_eq!(tag_version(" V0.10.0 "), Some(Version::new(0, 10, 0)));
        assert_eq!(tag_version("release-1"), None);
        assert_eq!(tag_version("v1.2"), None);
        assert_eq!(tag_version(""), None);
    }

    #[test]
    fn only_a_newer_final_release_counts() {
        assert_eq!(
            newer_version(&release("v0.2.0"), "0.1.0"),
            Some(Version::new(0, 2, 0))
        );
        assert_eq!(
            newer_version(&release("v0.1.10"), "0.1.9"),
            Some(Version::new(0, 1, 10))
        );
        // Equal or older: up to date.
        assert_eq!(newer_version(&release("v0.1.0"), "0.1.0"), None);
        assert_eq!(newer_version(&release("v0.0.9"), "0.1.0"), None);
        // Build metadata does not make a version newer.
        assert_eq!(newer_version(&release("v0.1.0+build.2"), "0.1.0"), None);
        // Prereleases, by flag or by suffix, and drafts are ignored.
        assert_eq!(newer_version(&release("v0.2.0-rc.1"), "0.1.0"), None);
        let mut pre = release("v0.2.0");
        pre.prerelease = true;
        assert_eq!(newer_version(&pre, "0.1.0"), None);
        let mut draft = release("v0.2.0");
        draft.draft = true;
        assert_eq!(newer_version(&draft, "0.1.0"), None);
        // A final release is newer than the prerelease it follows.
        assert_eq!(
            newer_version(&release("v0.2.0"), "0.2.0-rc.1"),
            Some(Version::new(0, 2, 0))
        );
        // Unparsable tag or running version.
        assert_eq!(newer_version(&release("latest"), "0.1.0"), None);
        assert_eq!(newer_version(&release("v0.2.0"), "dev"), None);
    }

    #[test]
    fn the_installed_linux_format_comes_first() {
        let appimage = "NetSift_0.2.0_amd64.AppImage";
        let deb = "NetSift_0.2.0_amd64.deb";
        let rpm = "NetSift-0.2.0-1.x86_64.rpm";
        assert_eq!(names(linux(None)), [appimage, deb, rpm]);
        assert_eq!(
            names(linux(Some(PackageFormat::AppImage))),
            [appimage, deb, rpm]
        );
        assert_eq!(names(linux(Some(PackageFormat::Deb))), [deb, appimage, rpm]);
        assert_eq!(names(linux(Some(PackageFormat::Rpm))), [rpm, appimage, deb]);
        let formats: Vec<_> = installers(&published(), &linux(None), PREFIX)
            .into_iter()
            .map(|i| i.format)
            .collect();
        assert_eq!(
            formats,
            [
                PackageFormat::AppImage,
                PackageFormat::Deb,
                PackageFormat::Rpm
            ]
        );
    }

    #[test]
    fn windows_and_macos_get_their_own_installers() {
        let windows = |installed| Platform {
            os: "windows",
            arch: "x86_64",
            installed,
        };
        let setup = "NetSift_0.2.0_x64-setup.exe";
        let msi = "NetSift_0.2.0_x64_en-US.msi";
        assert_eq!(names(windows(None)), [setup, msi]);
        assert_eq!(names(windows(Some(PackageFormat::Msi))), [msi, setup]);
        for arch in ["aarch64", "x86_64"] {
            let mac = Platform {
                os: "macos",
                arch,
                installed: Some(PackageFormat::Dmg),
            };
            assert_eq!(names(mac), ["NetSift_0.2.0_universal.dmg"]);
        }
    }

    #[test]
    fn no_installer_for_another_architecture_or_system() {
        let arm = Platform {
            os: "linux",
            arch: "aarch64",
            installed: None,
        };
        assert_eq!(names(arm), Vec::<String>::new());
        let bsd = Platform {
            os: "freebsd",
            arch: "x86_64",
            installed: None,
        };
        assert_eq!(names(bsd), Vec::<String>::new());
        // An arm64 build, if one is published, is offered there and only there.
        let mut assets = published();
        assets.push(asset("NetSift_0.2.0_arm64.deb"));
        let found = installers(&assets, &arm, PREFIX);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "NetSift_0.2.0_arm64.deb");
        assert!(
            !installers(&assets, &linux(None), PREFIX)
                .iter()
                .any(|i| i.name.contains("arm64"))
        );
    }

    #[test]
    fn odd_names_and_foreign_urls_are_never_offered() {
        let mut odd = vec![
            asset("../NetSift_0.2.0_amd64.deb"),
            asset(".NetSift_0.2.0_amd64.deb"),
            asset("dir/NetSift_0.2.0_amd64.deb"),
            asset("NetSift 0.2.0_amd64.deb"),
            asset(&format!("{}_amd64.deb", "N".repeat(MAX_ASSET_NAME))),
        ];
        let mut foreign = asset("NetSift_0.2.0_amd64.AppImage");
        foreign.browser_download_url = "https://evil.example/NetSift_0.2.0_amd64.AppImage".into();
        odd.push(foreign);
        let mut spaced = asset("NetSift_0.2.0_amd64.rpm");
        spaced.browser_download_url.push_str(" x");
        odd.push(spaced);
        assert_eq!(installers(&odd, &linux(None), PREFIX), []);
        assert!(!valid_url(PREFIX, PREFIX));
    }

    #[test]
    fn urls_are_compared_by_parts_not_by_text() {
        let ok = |url: &str| valid_url(url, PREFIX);
        assert!(ok(
            "https://github.com/o/r/releases/download/v0.2.0/NetSift.deb"
        ));
        // Owner and repository without case, host normalized by the parser.
        assert!(ok(
            "https://GitHub.com/O/R/releases/download/v0.2.0/NetSift.deb"
        ));
        assert!(ok(
            "https://github.com:443/o/r/releases/download/v0.2.0/a%20b.deb"
        ));
        for bad in [
            // The prefix itself, an empty or a trailing empty segment.
            "https://github.com/o/r/releases/download/",
            "https://github.com/o/r/releases/download//x",
            "https://github.com/o/r/releases/download/v1/",
            // Dot segments, plain or encoded, and backslashes.
            "https://github.com/o/r/releases/download/../../../other/repo/x",
            "https://github.com/o/r/releases/download/v1/../x",
            "https://github.com/o/r/releases/download/./x",
            "https://github.com/o/r/releases/download/%2e%2e/%2E%2E/x",
            "https://github.com/o/r/releases/download/%2e/x",
            "https://github.com/o/r/releases/download\\..\\x",
            // Query, fragment, credentials.
            "https://github.com/o/r/releases/download/v1/x?y=1",
            "https://github.com/o/r/releases/download/v1/x#y",
            "https://u:p@github.com/o/r/releases/download/v1/x",
            // Other scheme, host, port, repository, path.
            "http://github.com/o/r/releases/download/v1/x",
            "https://github.com.evil.example/o/r/releases/download/v1/x",
            "https://github.com:8443/o/r/releases/download/v1/x",
            "https://github.com/o/other/releases/download/v1/x",
            "https://github.com/o/r/releases/Download/v1/x",
            "https://github.com/o/r/releasesdownload/v1/x",
            "https://github.com/o/r",
            "not a url",
        ] {
            assert!(!ok(bad), "{bad}");
        }
        // Release pages.
        let page = "https://github.com/o/r/releases/";
        assert!(valid_url(
            "https://github.com/o/r/releases/tag/v0.2.0",
            page
        ));
        assert!(!valid_url("https://github.com/o/r/issues/1", page));
    }

    #[test]
    fn checksums_are_read_in_text_and_binary_mode() {
        let a = "a".repeat(64);
        let b = "B".repeat(64);
        let sums = format!(
            "{a}  NetSift_0.2.0_amd64.deb\n{b} *NetSift_0.2.0_universal.dmg\r\n{}  other\n",
            "c".repeat(64)
        );
        let sums = sums.as_bytes();
        assert_eq!(
            expected_sha256(sums, "NetSift_0.2.0_amd64.deb").as_deref(),
            Some(a.as_str())
        );
        // Lowercase, whatever the file says.
        assert_eq!(
            expected_sha256(sums, "NetSift_0.2.0_universal.dmg"),
            Some("b".repeat(64))
        );
        assert_eq!(expected_sha256(sums, "NetSift_0.2.0_amd64.rpm"), None);
        // Partial name, invalid hash, one space only, not UTF-8.
        assert_eq!(expected_sha256(sums, "NetSift_0.2.0_amd64"), None);
        let bad = format!("{}  f\n", "z".repeat(64));
        assert_eq!(expected_sha256(bad.as_bytes(), "f"), None);
        let single = format!("{a} f\n");
        assert_eq!(expected_sha256(single.as_bytes(), "f"), None);
        assert_eq!(expected_sha256(&[0xff, 0xfe], "f"), None);
        // Two different hashes for one name: refused; the same twice: fine.
        let twice = format!("{a}  f\n{b}  f\n");
        assert_eq!(expected_sha256(twice.as_bytes(), "f"), None);
        let same = format!("{a}  f\n{a} *f\n");
        assert_eq!(expected_sha256(same.as_bytes(), "f"), Some(a));
    }

    #[test]
    fn notes_are_plain_bounded_text() {
        let (notes, cut) = plain_notes(Some("## Fixes\r\n\n- one\u{1b}[31m\t<b>x</b>\u{202e}\n\n"));
        assert_eq!(notes, "## Fixes\n\n- one[31m\t<b>x</b>");
        assert!(!cut);
        assert_eq!(plain_notes(None), (String::new(), false));
        let long = "é".repeat(MAX_NOTES_CHARS + 10);
        let (notes, cut) = plain_notes(Some(&long));
        assert_eq!(notes.chars().count(), MAX_NOTES_CHARS);
        assert!(cut);
        let exact = "x".repeat(MAX_NOTES_CHARS);
        assert_eq!(plain_notes(Some(&exact)), (exact.clone(), false));
    }
}
