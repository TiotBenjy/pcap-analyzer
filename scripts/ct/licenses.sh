#!/usr/bin/env bash
# Third-party licenses of the shipped application (docs/LICENSES.md). Run IN the container by
# `./x.sh licenses [--check]` and by the gate, and as is by the CI (`licenses` job of ci.yml).
#
#   bash scripts/ct/licenses.sh [--check]
#
# 1. cargo-about (pinned below, about.toml): Rust crates of the desktop binary for the four bundle
#    targets, without dev and build dependencies, from the local cargo registry (--frozen);
# 2. ui/scripts/third-party-licenses.ts: adds the production npm packages of the UI (package-lock.json,
#    texts from ui/node_modules, so `npm ci` first), then writes or, with --check, compares
#    ui/src/views/settings/licenses/third-party-licenses.json and
#    apps/desktop/resources/licenses/THIRD-PARTY-NOTICES.txt.
#
# cargo-about comes from PATH when it is the pinned version (CI: prebuilt binary installed by
# taiki-e/install-action), otherwise it is compiled with its `cli` feature, once, into the cache
# volume (/cache/tools) like git-cliff, or into NETSIFT_TOOLS_DIR (CI fallback).
set -euo pipefail
CARGO_ABOUT_VERSION="0.9.3"
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

check=()
case "${1:-}" in
  "") ;;
  --check) check=(--check) ;;
  *) echo "usage: scripts/ct/licenses.sh [--check]" >&2; exit 2 ;;
esac

if [[ "$(cargo about --version 2>/dev/null || true)" == "cargo-about $CARGO_ABOUT_VERSION" ]]; then
  about=(cargo about)
else
  prefix="${NETSIFT_TOOLS_DIR:-/cache/tools}/cargo-about-$CARGO_ABOUT_VERSION"
  if [[ ! -x "$prefix/bin/cargo-about" ]]; then
    echo ">> Installation de cargo-about $CARGO_ABOUT_VERSION dans le cache (une seule fois, ~1 min)…" >&2
    # Separate target dir: does not pollute the target of the current worktree.
    cargo install --locked --quiet --features cli --root "$prefix" \
      --target-dir "${NETSIFT_TOOLS_TARGET:-/cache/target/tools}" "cargo-about@$CARGO_ABOUT_VERSION" >&2
  fi
  about=("$prefix/bin/cargo-about")
fi

[[ -d ui/node_modules ]] || { echo "licenses: ui/node_modules is missing (./x.sh npm ci)" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# Sources of every target's crates (Windows and macOS ones included), then offline only.
cargo fetch --locked --quiet
"${about[@]}" generate --format json --frozen --fail \
  --manifest-path apps/desktop/Cargo.toml --config about.toml --output-file "$tmp/cargo.json" 2>"$tmp/about.log" \
  || { cat "$tmp/about.log" >&2; exit 1; }
node --experimental-strip-types --no-warnings=ExperimentalWarning \
  ui/scripts/third-party-licenses.ts --cargo "$tmp/cargo.json" "${check[@]}"
