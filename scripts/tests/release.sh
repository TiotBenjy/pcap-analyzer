#!/usr/bin/env bash
# Tests for scripts/release.sh (sourced, main is not run): SemVer ordering, release kind (bump or
# publication of the current version), GitHub remote parsing, workspace version rewrite, argument
# validation, release titles (validation, tag message written and printed, release name read back
# by release.yml), the guards of a rerun (release already merged on main, tag on origin), and the
# version bump itself (apply_version) on a throwaway repository: Cargo.lock,
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
check "--title needs a value" not quiet bash "$ROOT/scripts/release.sh" 1.2.3 --dry-run --title
# Refused before the preconditions (which fail anyway in a worktree): the message is the title's.
# shellcheck disable=SC2329 # invoked by check
title_refused() {
  local out
  out="$(bash "$ROOT/scripts/release.sh" 1.2.3 --dry-run --title "$1" 2>&1)" && return 1
  [[ "$out" == "release: --title : "* ]]
}
check "rejects a multi-line title" title_refused $'Faster\nimports'
check "rejects a blank title" title_refused '   '
check "rejects a too long title" title_refused "$(printf 'x%.0s' {1..81})"

# --- Release titles ---------------------------------------------------------------------
# shellcheck disable=SC2329 # invoked by check
title_ok() { test -z "$(release_title_error "$1")"; }
check "plain title" title_ok "Faster imports, DNS server map"
check "accented title, dashes and quotes" title_ok "Import plus rapide — carte « DNS » l'été"
check "title starting with #" title_ok "#42 fixed"
check "80 characters (multibyte)" title_ok "$(printf 'é%.0s' {1..80})"
check "81 characters (multibyte)" not title_ok "$(printf 'é%.0s' {1..81})"
check "empty title" not title_ok ""
check "line feed" not title_ok $'a\nb'
check "carriage return" not title_ok $'a\rb'
check "tab" not title_ok $'a\tb'
check "escape" not title_ok $'a\e[31mb'
check "DEL" not title_ok $'a\x7fb'
check "C1 control (NEL)" not title_ok $'a\xc2\x85b'
check "right-to-left override" not title_ok $'a\xe2\x80\xaeb'
check "right-to-left mark" not title_ok $'a\xe2\x80\x8fb'
check "first strong isolate" not title_ok $'a\xe2\x81\xa8b'
check "invalid UTF-8" not title_ok $'a\xffb'
check "line separator U+2028" not title_ok $'a\xe2\x80\xa8b'
check "paragraph separator U+2029" not title_ok $'a\xe2\x80\xa9b'
check "Arabic letter mark U+061C" not title_ok $'a\xd8\x9cb'
check "zero-width space U+200B" not title_ok $'a\xe2\x80\x8bb'
check "byte order mark U+FEFF" not title_ok $'\xef\xbb\xbfab'
check "word joiner U+2060" not title_ok $'a\xe2\x81\xa0b'
check "Mongolian vowel separator U+180E" not title_ok $'a\xe1\xa0\x8eb'
check "zero-width joiner U+200D is kept" title_ok $'a\xe2\x80\x8db'
check "en dash U+2013 and ellipsis U+2026 are kept" title_ok "a – b…"
check "trim" test "$(trim $'  \t -n title  ')" = "-n title"
check "shell_quote round trip" test "$(eval "printf '%s' $(shell_quote "It's \"fast\" \$HOME \\ \`x\`")")" = "It's \"fast\" \$HOME \\ \`x\`"
check "tag command without title" test "$(tag_command /r v1.0.0 main)" = "git -C '/r' tag -a --cleanup=whitespace v1.0.0 -m \"NetSift v1.0.0\" main"
check "tag command with title" test "$(tag_command /r v1.0.0 abc "It's fast")" = \
  "git -C '/r' tag -a --cleanup=whitespace v1.0.0 -m \"NetSift v1.0.0\" -m 'It'\\''s fast' abc"

# --- Rerun after a partial failure: release already merged, tag on origin ---------------
# A space and a quote in the path: the printed commands quote it.
GITREPO="$TMP/git repo's"
gc() { git -C "$GITREPO" -c user.name=t -c user.email=t@example.invalid "$@"; }
git init -q -b main "$GITREPO"
gc commit -q --allow-empty -m "feat: start"
check "no release merged yet" test -z "$(release_merged "$GITREPO" 0.1.0)"
gc checkout -q -b chore/release-0.1.0
gc commit -q --allow-empty -m "chore(release): v0.1.0"
gc checkout -q main
gc merge -q --no-ff -m "merge(chore/release-0.1.0): intégration" chore/release-0.1.0
check "merged release: its merge commit" test "$(release_merged "$GITREPO" 0.1.0)" = "$(gc rev-parse main)"
check "another version is not merged" test -z "$(release_merged "$GITREPO" 0.1.1)"
gc commit -q --allow-empty -m "chore(release): v0.2.0"
check "release commit without merge commit" test "$(release_merged "$GITREPO" 0.2.0)" = "$(gc rev-parse main)"
gc commit -q --allow-empty -m "chore(release): v0.3.0-rc.1"
check "a prerelease is not its release" test -z "$(release_merged "$GITREPO" 0.3.0)"

# Tag message written by release.sh (printed recovery command, run as is), name read back by
# release.yml (scripts/ci/release-name.sh).
tagged() { # <tag> <title or empty> : runs the printed command in GITREPO
  (export GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
   eval "$(tag_command "$GITREPO" "$1" main "$2")") >/dev/null 2>&1
}
name_of() { (cd "$GITREPO" && bash "$ROOT/scripts/ci/release-name.sh" "$1" 2>/dev/null); }
HOSTILE="It's \"fast\" \$HOME — #1 \\ \`x\`"
tagged v9.0.0 "Faster imports"
check "release name with title" test "$(name_of v9.0.0)" = "NetSift v9.0.0 — Faster imports"
check "tag message: subject, blank line, title" test \
  "$(gc for-each-ref --format='%(contents)' refs/tags/v9.0.0)" = $'NetSift v9.0.0\n\nFaster imports'
tagged v9.0.1 ""
check "release name without title" test "$(name_of v9.0.1)" = "NetSift v9.0.1"
tagged v9.0.2 "$HOSTILE"
check "title with quotes, \$, # and backslash survives the printed command" \
  test "$(name_of v9.0.2)" = "NetSift v9.0.2 — $HOSTILE"
tagged v9.0.5 "#42 fixed"
check "title starting with # survives the tag message" test "$(name_of v9.0.5)" = "NetSift v9.0.5 — #42 fixed"
gc tag -a -m "NetSift v9.0.3" -m "$(printf 'x%.0s' {1..81})" v9.0.3 main
check "invalid title in the tag: default name" test "$(name_of v9.0.3)" = "NetSift v9.0.3"
gc commit -q --allow-empty -m "feat: subject" -m "Body that is not a title"
gc tag v9.0.4 main
check "lightweight tag: no title from the commit message" test "$(name_of v9.0.4)" = "NetSift v9.0.4"
check "missing tag fails" not quiet name_of v9.9.9
warnings_of() { (cd "$GITREPO" && bash "$ROOT/scripts/ci/release-name.sh" "$1" 2>&1 >/dev/null); }
check "invalid title in the tag: a workflow warning" test "$(warnings_of v9.0.3)" \
  = "::warning::titre du tag v9.0.3 ignoré : titre trop long (81 caractères, 80 au plus)"
check "lightweight tag: a workflow warning" test "$(warnings_of v9.0.4)" \
  = "::warning::v9.0.4 est un tag léger : release sans titre"
check "valid title: no warning" test -z "$(warnings_of v9.0.0)"

git init -q --bare "$TMP/origin.git"
gc remote add origin "$TMP/origin.git"
check "tag absent from origin" test "$(remote_tag_state "$GITREPO" v0.1.0)" = absent
gc tag v0.1.0 main
gc push -q origin refs/tags/v0.1.0
check "tag present on origin" test "$(remote_tag_state "$GITREPO" v0.1.0)" = present
gc remote set-url origin "$TMP/missing.git"
check "unreachable origin is an error" test "$(remote_tag_state "$GITREPO" v0.1.0)" = error

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
