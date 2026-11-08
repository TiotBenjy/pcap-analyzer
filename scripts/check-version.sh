#!/usr/bin/env bash
# Checks that the application version has a single source of truth and that every copy agrees.
#
#   scripts/check-version.sh [-C <dir>] [vX.Y.Z]
#
# Source of truth: `[workspace.package] version` in Cargo.toml. Must agree with it:
#   - ui/package.json and ui/package-lock.json (root package);
#   - Cargo.lock entries of the internal crates (netsift-*);
#   - the tag, when given (`vX.Y.Z`, SemVer, optional prerelease suffix such as `-beta.1`).
# Must not exist: a `version =` literal in an internal crate manifest (they all use
# `version.workspace = true`) or a `version` key in apps/desktop/tauri.conf.json (Tauri reads the
# crate version). Prints the version on success, exits 1 with one line per mismatch otherwise.
# Pure bash/awk/grep: runs on the host, in the container and on every CI runner.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${1:-}" == "-C" ]]; then
  [[ -n "${2:-}" ]] || { echo "check-version: -C requires a directory" >&2; exit 2; }
  ROOT="$(cd "$2" && pwd)"
  shift 2
fi
TAG="${1:-}"
[[ $# -le 1 ]] || { echo "usage: scripts/check-version.sh [-C <dir>] [vX.Y.Z]" >&2; exit 2; }

# SemVer 2.0.0 (no leading zeros in numeric fields), build metadata not used here.
SEMVER_RE='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'

errors=()
fail() { errors+=("$1"); }

# --- Source of truth --------------------------------------------------------------
cargo_version="$(awk '
  /^\[/ { in_pkg = ($0 == "[workspace.package]") ; next }
  in_pkg && /^version[[:space:]]*=/ {
    sub(/^version[[:space:]]*=[[:space:]]*"/, ""); sub(/".*$/, ""); print; exit
  }' "$ROOT/Cargo.toml")"
if [[ -z "$cargo_version" ]]; then
  echo "check-version: no version in [workspace.package] of Cargo.toml" >&2
  exit 1
fi
[[ "$cargo_version" =~ $SEMVER_RE ]] || fail "Cargo.toml: '$cargo_version' is not SemVer X.Y.Z[-pre]"

# --- Internal crate manifests: inherit the workspace version ------------------------
for manifest in "$ROOT"/crates/*/Cargo.toml "$ROOT"/apps/*/Cargo.toml; do
  [[ -f "$manifest" ]] || continue
  if awk '/^\[/ { in_pkg = ($0 == "[package]"); next } in_pkg && /^version[[:space:]]*=/ { found = 1 }
          END { exit !found }' "$manifest"; then
    fail "${manifest#"$ROOT"/}: literal version, expected 'version.workspace = true'"
  fi
done

# --- Tauri: no version of its own (it reads the crate version) ------------------------
tauri_conf="$ROOT/apps/desktop/tauri.conf.json"
if [[ -f "$tauri_conf" ]] && grep -qE '^  "version"[[:space:]]*:' "$tauri_conf"; then
  fail "apps/desktop/tauri.conf.json: remove the \"version\" key (Tauri uses Cargo.toml)"
fi

# --- UI ---------------------------------------------------------------------------
ui_version="$(grep -m1 -E '^  "version"[[:space:]]*:' "$ROOT/ui/package.json" \
  | sed -E 's/^[^:]*:[[:space:]]*"([^"]*)".*/\1/' || true)"
[[ "$ui_version" == "$cargo_version" ]] \
  || fail "ui/package.json: '${ui_version:-<none>}' != Cargo.toml '$cargo_version'"

lock="$ROOT/ui/package-lock.json"
if [[ -f "$lock" ]]; then
  # Top-level "version" (2-space indent) and packages[""].version (first 6-space one after it).
  read -r lock_top lock_root < <(awk '
    /^  "version"[[:space:]]*:/ && top == "" { v = $0; sub(/^[^:]*:[[:space:]]*"/, "", v); sub(/".*$/, "", v); top = v }
    /^    "":[[:space:]]*\{/ { in_root = 1; next }
    in_root && /^      "version"[[:space:]]*:/ { v = $0; sub(/^[^:]*:[[:space:]]*"/, "", v); sub(/".*$/, "", v); root = v; in_root = 0 }
    in_root && /^    \}/ { in_root = 0 }
    END { print (top == "" ? "-" : top), (root == "" ? "-" : root) }' "$lock")
  [[ "$lock_top" == "$cargo_version" ]] \
    || fail "ui/package-lock.json: version '$lock_top' != Cargo.toml '$cargo_version'"
  [[ "$lock_root" == "$cargo_version" ]] \
    || fail "ui/package-lock.json: packages[\"\"].version '$lock_root' != Cargo.toml '$cargo_version'"
fi

# --- Cargo.lock: internal crates (path dependencies, no `source`) ----------------------
if [[ -f "$ROOT/Cargo.lock" ]]; then
  internal=0
  while read -r name version; do
    internal=$((internal + 1))
    [[ "$version" == "$cargo_version" ]] \
      || fail "Cargo.lock: $name '$version' != Cargo.toml '$cargo_version' (run cargo update --workspace)"
  done < <(awk '
    function flush() { if (name ~ /^netsift-/ && !has_source) print name, version }
    /^\[\[package\]\]/ { if (started) flush(); started = 1; name = ""; version = ""; has_source = 0; next }
    /^name = /    { name = $3; gsub(/"/, "", name) }
    /^version = / { version = $3; gsub(/"/, "", version) }
    /^source = /  { has_source = 1 }
    END { if (started) flush() }' "$ROOT/Cargo.lock")
  [[ "$internal" -gt 0 ]] || fail "Cargo.lock: no internal netsift-* crate found"
fi

# --- Tag ----------------------------------------------------------------------------
if [[ -n "$TAG" ]]; then
  if [[ "$TAG" != v* ]]; then
    fail "tag '$TAG': expected 'v' followed by the version (v$cargo_version)"
  elif [[ ! "${TAG#v}" =~ $SEMVER_RE ]]; then
    fail "tag '$TAG': not SemVer (vX.Y.Z or vX.Y.Z-pre)"
  elif [[ "${TAG#v}" != "$cargo_version" ]]; then
    fail "tag '$TAG' != Cargo.toml version '$cargo_version'"
  fi
fi

if [[ ${#errors[@]} -gt 0 ]]; then
  printf 'check-version: %s\n' "${errors[@]}" >&2
  exit 1
fi
echo "$cargo_version"
