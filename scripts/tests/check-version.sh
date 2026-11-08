#!/usr/bin/env bash
# Tests for scripts/check-version.sh: runs it on the real tree, then on mutated copies of the
# version files in a temporary directory. No toolchain needed (bash, awk, sed, grep).
#
#   bash scripts/tests/check-version.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK="$ROOT/scripts/check-version.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
failures=0
ok() { pass=$((pass + 1)); }
ko() { failures=$((failures + 1)); echo "FAIL: $1" >&2; }

expect_ok() { # <description> <args...>
  local desc="$1"; shift
  if out="$(bash "$CHECK" "$@" 2>&1)"; then ok; else ko "$desc (unexpected failure: $out)"; fi
}
expect_fail() { # <description> <expected message fragment> <args...>
  local desc="$1" frag="$2"; shift 2
  if out="$(bash "$CHECK" "$@" 2>&1)"; then
    ko "$desc (unexpected success)"
  elif [[ "$out" != *"$frag"* ]]; then
    ko "$desc (message without '$frag': $out)"
  else
    ok
  fi
}

# Fresh copy of the files read by the check, in $TMP/<name>.
fixture() {
  local dir="$TMP/$1"
  mkdir -p "$dir/ui" "$dir/apps/desktop" "$dir/crates"
  cp "$ROOT/Cargo.toml" "$ROOT/Cargo.lock" "$dir/"
  cp "$ROOT/ui/package.json" "$ROOT/ui/package-lock.json" "$dir/ui/"
  cp "$ROOT/apps/desktop/Cargo.toml" "$ROOT/apps/desktop/tauri.conf.json" "$dir/apps/desktop/"
  local c
  for c in "$ROOT"/crates/*/; do
    mkdir -p "$dir/crates/$(basename "$c")"
    cp "$c/Cargo.toml" "$dir/crates/$(basename "$c")/"
  done
  echo "$dir"
}

# --- Real tree ------------------------------------------------------------------------
version="$(bash "$CHECK")" || { echo "FAIL: check-version on the real tree" >&2; exit 1; }
ok
expect_ok "real tree, matching tag" "v$version"
expect_fail "real tree, tag without v" "expected 'v'" "$version"
expect_fail "real tree, discordant tag" "!= Cargo.toml version" "v9.9.9"
expect_fail "real tree, non-SemVer tag" "not SemVer" "v1.2"
expect_fail "real tree, leading zero" "not SemVer" "v01.2.3"

# --- Mutations ------------------------------------------------------------------------
d="$(fixture same)"
expect_ok "untouched copy" -C "$d" "v$version"

d="$(fixture prerelease)"
sed -i -E '/^\[workspace.package\]/,/^\[/ s/^version = ".*"/version = "2.0.0-beta.1"/' "$d/Cargo.toml"
sed -i -E "s/^(  \"version\": )\"[^\"]*\"/\1\"2.0.0-beta.1\"/" "$d/ui/package.json" "$d/ui/package-lock.json"
sed -i -E "s/^(      \"version\": )\"$version\"/\1\"2.0.0-beta.1\"/" "$d/ui/package-lock.json"
awk '/^name = "netsift-/ { n = 1 } n && /^version = / { $0 = "version = \"2.0.0-beta.1\""; n = 0 } { print }' \
  "$d/Cargo.lock" > "$d/Cargo.lock.new" && mv "$d/Cargo.lock.new" "$d/Cargo.lock"
expect_ok "prerelease everywhere" -C "$d" "v2.0.0-beta.1"
expect_fail "prerelease, tag without suffix" "!= Cargo.toml version" -C "$d" "v2.0.0"

d="$(fixture ui)"
sed -i -E "s/^(  \"version\": )\"[^\"]*\"/\1\"9.9.9\"/" "$d/ui/package.json"
expect_fail "ui/package.json differs" "ui/package.json" -C "$d"

d="$(fixture uilock)"
sed -i -E "s/^(      \"version\": )\"$version\"/\1\"9.9.9\"/" "$d/ui/package-lock.json"
expect_fail "package-lock root package differs" "packages[\"\"].version" -C "$d"

d="$(fixture cargolock)"
awk '/^name = "netsift-api"/ { n = 1 } n && /^version = / { $0 = "version = \"9.9.9\""; n = 0 } { print }' \
  "$d/Cargo.lock" > "$d/Cargo.lock.new" && mv "$d/Cargo.lock.new" "$d/Cargo.lock"
expect_fail "Cargo.lock internal crate differs" "Cargo.lock: netsift-api" -C "$d"

d="$(fixture literal)"
sed -i -E 's/^version\.workspace = true/version = "9.9.9"/' "$d/apps/desktop/Cargo.toml"
expect_fail "literal crate version" "literal version" -C "$d"

d="$(fixture tauri)"
sed -i -E "s/^(  \"productName\")/  \"version\": \"$version\",\n\1/" "$d/apps/desktop/tauri.conf.json"
expect_fail "version key in tauri.conf.json" "tauri.conf.json" -C "$d"

d="$(fixture semver)"
sed -i -E '/^\[workspace.package\]/,/^\[/ s/^version = ".*"/version = "1.0"/' "$d/Cargo.toml"
expect_fail "non-SemVer Cargo.toml version" "is not SemVer" -C "$d"

echo "check-version tests: $pass passed, $failures failed"
[[ "$failures" -eq 0 ]]
