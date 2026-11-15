#!/usr/bin/env bash
# Tests for scripts/release.sh (sourced, main is not run): SemVer ordering, release kind (bump or
# publication of the current version), GitHub remote parsing, workspace version rewrite, argument
# validation, and the version bump itself (apply_version) on a throwaway repository: Cargo.lock,
# fuzz/Cargo.lock and the UI lockfile follow the new version. That last part needs cargo and npm
# (gate container, CI runners) and is skipped without them; it never touches this repository.
#
#   bash scripts/tests/release.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/release.sh
source "$ROOT/scripts/release.sh"
set +e

pass=0
failures=0
check() { # <description> <command...>
  local desc="$1"; shift
  if "$@"; then pass=$((pass + 1)); else failures=$((failures + 1)); echo "FAIL: $desc" >&2; fi
}
not() { ! "$@"; }
quiet() { "$@" >/dev/null 2>&1; }

# SemVer 2.0.0 §11 precedence chain, each strictly greater than the previous one.
chain=(0.1.0 0.1.1 0.2.0-alpha 0.2.0-alpha.1 0.2.0-alpha.beta 0.2.0-beta 0.2.0-beta.2
       0.2.0-beta.11 0.2.0-rc.1 0.2.0 0.10.0 1.0.0 10.0.0)
for ((i = 1; i < ${#chain[@]}; i++)); do
  check "${chain[i]} > ${chain[i-1]}" semver_gt "${chain[i]}" "${chain[i-1]}"
  check "not ${chain[i-1]} > ${chain[i]}" not semver_gt "${chain[i-1]}" "${chain[i]}"
done
check "equal versions are not greater" not semver_gt 0.1.0 0.1.0
check "equal prereleases are not greater" not semver_gt 1.0.0-rc.1 1.0.0-rc.1

check "same version: publication of the current one" test "$(release_kind 0.1.0 0.1.0)" = same
check "greater version: bump" test "$(release_kind 0.1.0 0.2.0)" = bump
check "prerelease to release: bump" test "$(release_kind 0.2.0-rc.1 0.2.0)" = bump
check "lower version refused" not quiet release_kind 0.2.0 0.1.0
check "release below its prerelease refused" not quiet release_kind 0.2.0 0.2.0-rc.1

check "ssh remote" test "$(github_slug git@github.com:TiotBenjy/pcap-analyzer.git)" = TiotBenjy/pcap-analyzer
check "https remote" test "$(github_slug https://github.com/TiotBenjy/pcap-analyzer)" = TiotBenjy/pcap-analyzer
check "ssh:// remote" test "$(github_slug ssh://git@github.com/o/r.git)" = o/r
check "non-GitHub remote" test -z "$(github_slug /tmp/bare.git)"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/Cargo.toml" <<'EOF'
[package]
version = "9.9.9"

[workspace.package]
version = "0.1.0"
edition = "2024"

[workspace.dependencies]
version = "1"
EOF
set_workspace_version "$TMP/Cargo.toml" 0.2.0-beta.1
check "workspace version rewritten" grep -q '^version = "0.2.0-beta.1"$' "$TMP/Cargo.toml"
check "other version lines untouched" test "$(grep -c '^version = "9.9.9"$\|^version = "1"$' "$TMP/Cargo.toml")" = 2
printf '[package]\nversion = "1.0.0"\n' > "$TMP/none.toml"
check "missing [workspace.package] fails" not set_workspace_version "$TMP/none.toml" 1.0.1

# Argument validation happens before any git command.
check "rejects non-SemVer" not quiet bash "$ROOT/scripts/release.sh" 1.2 --dry-run
check "rejects unknown option" not quiet bash "$ROOT/scripts/release.sh" 1.2.3 --force
check "--no-push no longer exists" not quiet bash "$ROOT/scripts/release.sh" 1.2.3 --no-push
check "rejects missing version" not quiet bash "$ROOT/scripts/release.sh" --dry-run

# --- apply_version on a throwaway repository ------------------------------------------
# Same layout as this repository: a workspace of netsift-* crates, fuzz/ outside it with its own
# Cargo.lock and path dependencies on them, ui/ with package.json and package-lock.json.
make_repo() { # <dir>
  local d="$1"
  mkdir -p "$d/crates/netsift-a/src" "$d/crates/netsift-b/src" "$d/fuzz/src" "$d/ui"
  cat > "$d/Cargo.toml" <<'EOF'
[workspace]
resolver = "2"
members = ["crates/netsift-a", "crates/netsift-b"]
exclude = ["fuzz"]

[workspace.package]
version = "0.1.0"
edition = "2021"
EOF
  printf '[package]\nname = "netsift-a"\nversion.workspace = true\nedition.workspace = true\n' \
    > "$d/crates/netsift-a/Cargo.toml"
  printf '[package]\nname = "netsift-b"\nversion.workspace = true\nedition.workspace = true\n\n[dependencies]\nnetsift-a = { path = "../netsift-a" }\n' \
    > "$d/crates/netsift-b/Cargo.toml"
  cat > "$d/fuzz/Cargo.toml" <<'EOF'
[package]
name = "netsift-fuzz"
version = "0.0.0"
edition = "2021"

[workspace]
members = ["."]

[dependencies]
netsift-b = { path = "../crates/netsift-b" }
EOF
  touch "$d/crates/netsift-a/src/lib.rs" "$d/crates/netsift-b/src/lib.rs" "$d/fuzz/src/lib.rs"
  printf '{\n  "name": "ui",\n  "version": "0.1.0",\n  "private": true\n}\n' > "$d/ui/package.json"
  printf '{\n  "name": "ui",\n  "version": "0.1.0",\n  "lockfileVersion": 3,\n  "requires": true,\n  "packages": {\n    "": {\n      "name": "ui",\n      "version": "0.1.0"\n    }\n  }\n}\n' \
    > "$d/ui/package-lock.json"
  (cd "$d" && CARGO_NET_OFFLINE=true cargo generate-lockfile --quiet) || return 1
  (cd "$d/fuzz" && CARGO_NET_OFFLINE=true cargo generate-lockfile --quiet) || return 1
  git -C "$d" init -q
  git -C "$d" add -A
  git -C "$d" -c user.name=t -c user.email=t@example.invalid commit -q -m init
}

# Runner of apply_version: cargo at the root of the repository, npm in ui/, offline.
# shellcheck disable=SC2329 # invoked by apply_version
direct() {
  local tool="$1"; shift
  case "$tool" in
    cargo) (cd "$REPO" && CARGO_NET_OFFLINE=true cargo "$@") ;;
    npm)   (cd "$REPO/ui" && npm --offline --no-audit --no-fund "$@") ;;
    *) return 1 ;;
  esac
}

# Version of an internal crate in a Cargo.lock.
locked() { awk -v n="$2" '$0 == "name = \"" n "\"" { getline; gsub(/version = |"/, ""); print; exit }' "$1"; }

if command -v cargo >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
  REPO="$TMP/repo"
  if make_repo "$REPO" >/dev/null 2>&1; then
    check "throwaway repository is consistent" quiet bash "$ROOT/scripts/check-version.sh" -C "$REPO" v0.1.0

    apply_version "$REPO" 0.1.0 direct >/dev/null 2>&1
    check "same version: nothing changes" test -z "$(git -C "$REPO" status --porcelain)"

    apply_version "$REPO" 0.2.0 direct >/dev/null 2>&1
    check "bump: check-version agrees with v0.2.0" quiet bash "$ROOT/scripts/check-version.sh" -C "$REPO" v0.2.0
    check "bump: Cargo.lock follows" test "$(locked "$REPO/Cargo.lock" netsift-b)" = 0.2.0
    check "bump: fuzz/Cargo.lock follows (netsift-a)" test "$(locked "$REPO/fuzz/Cargo.lock" netsift-a)" = 0.2.0
    check "bump: fuzz/Cargo.lock follows (netsift-b)" test "$(locked "$REPO/fuzz/Cargo.lock" netsift-b)" = 0.2.0
    check "bump: fuzz crate keeps its own version" test "$(locked "$REPO/fuzz/Cargo.lock" netsift-fuzz)" = 0.0.0
    check "bump: fuzz/Cargo.lock passes --locked" \
      quiet env CARGO_NET_OFFLINE=true cargo metadata --locked --format-version 1 --manifest-path "$REPO/fuzz/Cargo.toml"
    check "bump: only the version files change" test \
      "$(git -C "$REPO" status --porcelain | awk '{ print $2 }' | sort | tr '\n' ' ')" \
      = "Cargo.lock Cargo.toml fuzz/Cargo.lock ui/package-lock.json ui/package.json "
    check "bump: fuzz/Cargo.lock changes only the netsift-a and netsift-b versions" test \
      "$(git -C "$REPO" diff -U0 -- fuzz/Cargo.lock | grep -c '^[-+]version')" = 4
  else
    failures=$((failures + 1)); echo "FAIL: throwaway repository (cargo generate-lockfile)" >&2
  fi
else
  echo "release tests: cargo or npm missing, apply_version not exercised (run in the gate)"
fi

echo "release tests: $pass passed, $failures failed"
[[ "$failures" -eq 0 ]]
