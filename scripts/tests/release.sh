#!/usr/bin/env bash
# Tests for the pure helpers of scripts/release.sh (sourced, main is not run):
# SemVer ordering, GitHub remote parsing, workspace version rewrite, argument validation.
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

echo "release tests: $pass passed, $failures failed"
[[ "$failures" -eq 0 ]]
