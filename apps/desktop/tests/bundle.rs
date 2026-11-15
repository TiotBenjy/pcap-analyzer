//! Bundle configuration (`tauri.conf.json`): what every published bundle must carry.

use std::path::Path;

fn config() -> serde_json::Value {
    serde_json::from_str(include_str!("../tauri.conf.json")).expect("tauri.conf.json is valid JSON")
}

/// The project licenses and the third-party notices (Apache-2.0 section 4, MIT, BSD...) ship
/// with the binaries, from files that exist in the repository.
#[test]
fn bundles_ship_the_licenses_and_third_party_notices() {
    let config = config();
    let resources = config["bundle"]["resources"]
        .as_object()
        .expect("bundle.resources is a map");
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for target in [
        "licenses/LICENSE",
        "licenses/NOTICE",
        "licenses/THIRD_PARTY_LICENSES",
    ] {
        let (source, _) = resources
            .iter()
            .find(|(_, t)| t.as_str() == Some(target))
            .unwrap_or_else(|| panic!("bundle.resources has no entry for {target}"));
        let path = crate_dir.join(source);
        let text =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_ne!(text.trim(), "", "{} is empty", path.display());
    }
}

/// Every icon declared for the bundles exists (generated from `icons/source.svg`).
#[test]
fn bundle_icons_exist() {
    let config = config();
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let icons = config["bundle"]["icon"]
        .as_array()
        .expect("bundle.icon is a list");
    assert_ne!(icons.len(), 0, "bundle.icon is empty");
    for icon in icons {
        let path = crate_dir.join(icon.as_str().expect("icon path is a string"));
        assert!(path.is_file(), "missing icon {}", path.display());
    }
}
