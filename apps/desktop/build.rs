//! Tauri build script.
//!
//! `tauri::generate_context!` embeds `ui/dist` at compile time and fails if it does not exist.
//! `cargo tauri build` builds the UI first (`beforeBuildCommand`), but workspace-wide commands
//! (`cargo clippy --workspace`, `cargo nextest run --workspace`) do not: for those, a minimal
//! placeholder page is created when the real build output is missing. It is never shipped,
//! because bundling always goes through `cargo tauri build`.

use std::path::Path;

const PLACEHOLDER: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>NetSift</title></head>\
<body><p>The user interface was not built. Run ./x.sh desktop.</p></body></html>\n";

fn main() {
    let dist = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ui/dist");
    if !dist.join("index.html").exists() {
        std::fs::create_dir_all(&dist).expect("cannot create ui/dist");
        std::fs::write(dist.join("index.html"), PLACEHOLDER)
            .expect("cannot write placeholder ui/dist/index.html");
    }
    tauri_build::build();
}
