#!/usr/bin/env bash
# Tests for the build cache hygiene: slug formula (x.sh, scripts/lib/cache.sh), orphan
# selection, the container-side script on a fake volume, `./x.sh clean` end to end (local mode,
# NETSIFT_CACHE_ROOT), and the hooks of scripts/wt.sh (stub x.sh in a throwaway repository).
# No toolchain and no container needed: bash, git, flock, coreutils.
#
#   bash scripts/tests/cache.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=scripts/lib/cache.sh
source "$ROOT/scripts/lib/cache.sh"
CT="$ROOT/scripts/ct/cache.sh"
TMP="$(mktemp -d)"
LOCK_PID=""
release_lock() { [[ -n "$LOCK_PID" ]] && pkill -P "$LOCK_PID" 2>/dev/null; LOCK_PID=""; }
cleanup() { release_lock; rm -rf "$TMP"; }
trap cleanup EXIT
set +e

pass=0
failures=0
check() { # <description> <command...>
  local desc="$1"; shift
  if "$@"; then pass=$((pass + 1)); else failures=$((failures + 1)); echo "FAIL: $desc" >&2; fi
}
not() { ! "$@"; }
has_line() { [[ $'\n'"$1"$'\n' == *$'\n'"$2"$'\n'* ]]; } # <text> <exact line>
contains() { [[ "$1" == *"$2"* ]]; }

# --- Slug ------------------------------------------------------------------------------
# Regression vector: the formula names every existing target, it must never change.
check "slug vector" test "$(cache_slug /home/user/netsift)" = "$(echo /home/user/netsift | sha1sum | cut -c1-12)"
check "slug vector (literal)" test "$(cache_slug /work)" = "$(printf '/work\n' | sha1sum | cut -c1-12)"
check "slug is 12 hex" cache_is_slug "$(cache_slug "/a path/with spaces")"
check "tools is not a slug" not cache_is_slug tools
check "uppercase is not a slug" not cache_is_slug 0123456789AB
check "13 chars is not a slug" not cache_is_slug 0123456789abc

mkdir -p "$TMP/wt one"
check "x.sh slug == cache_slug (-C absolute)" \
  test "$(bash "$ROOT/x.sh" -C "$TMP/wt one" slug)" = "$(cache_slug "$TMP/wt one")"
check "x.sh slug == cache_slug (-C relative)" \
  test "$(cd "$TMP" && bash "$ROOT/x.sh" -C "wt one" slug)" = "$(cache_slug "$TMP/wt one")"
check "x.sh slug == cache_slug (own root)" \
  test "$(bash "$ROOT/x.sh" slug)" = "$(cache_slug "$ROOT")"

# --- Selection (pure) ------------------------------------------------------------------
now=1800000000
mkdir -p "$TMP/exists"
S_EXIST=aaaaaaaaaaa1 S_GONE=aaaaaaaaaaa2 S_LIVE=aaaaaaaaaaa3 S_RECENT=aaaaaaaaaaa4
S_OLD=aaaaaaaaaaa5 S_LOCKED=aaaaaaaaaaa6
listing="$(printf '%s\n' \
  "tools			0	$((now - 99999))" \
  "root			0	$((now - 99999))" \
  "$S_EXIST	$TMP/exists	2026-11-08T10:00:00Z	0	$((now - 99999))" \
  "$S_GONE	$TMP/gone	2026-11-01T10:00:00Z	0	$((now - 99999))" \
  "$S_LIVE			0	$((now - 99999))" \
  "$S_RECENT			0	$((now - 60))" \
  "$S_OLD			0	$((now - 99999))" \
  "$S_LOCKED	$TMP/gone2	2026-11-01T10:00:00Z	1	$((now - 99999))" \
  "bbbbbbbbbbb7			0	")"
live="$(printf '%s\n' ffffffffffff "$S_LIVE" eeeeeeeeeeee)"
out="$(cache_select orphans "$now" 7200 "$live" <<<"$listing")"
check "tools kept" has_line "$out" "keep	tools	unmanaged"
check "non-slug kept" has_line "$out" "keep	root	unmanaged"
check "origin exists kept" has_line "$out" "keep	$S_EXIST	origin-exists"
check "origin gone deleted" has_line "$out" "delete	$S_GONE	origin-gone"
check "live worktree kept" has_line "$out" "keep	$S_LIVE	live-worktree"
check "recent without marker kept" has_line "$out" "keep	$S_RECENT	recent"
check "old without marker deleted" has_line "$out" "delete	$S_OLD	unknown"
check "locked kept" has_line "$out" "keep	$S_LOCKED	in-use"
check "no mtime, no marker deleted" has_line "$out" "delete	bbbbbbbbbbb7	unknown"
check "one decision per target" test "$(wc -l <<<"$out")" -eq 9

out="$(cache_select all "$now" 7200 "$live" <<<"$listing")"
check "all: tools kept" has_line "$out" "keep	tools	unmanaged"
check "all: locked kept" has_line "$out" "keep	$S_LOCKED	in-use"
check "all: live deleted" has_line "$out" "delete	$S_LIVE	all"
check "all: origin exists deleted" has_line "$out" "delete	$S_EXIST	all"
check "all: 6 deletions" test "$(grep -c '^delete' <<<"$out")" -eq 6

out="$(cache_select orphans "$now" 7200 "" <<<"$S_LIVE			0	$((now - 99999))")"
check "empty live list" has_line "$out" "delete	$S_LIVE	unknown"

wt_gone="$TMP/wt-gone"
s_gone="$(cache_slug "$wt_gone")"
listing="$(printf '%s\n' \
  "$s_gone			0	1" \
  "aaaaaaaaaaa8	$wt_gone	x	0	1" \
  "aaaaaaaaaaa9	$TMP/other	x	0	1" \
  "tools	$wt_gone		0	1")"
out="$(cache_select_worktree "$wt_gone" <<<"$listing")"
check "worktree: slug match deleted" has_line "$out" "delete	$s_gone	worktree-removed"
check "worktree: origin match deleted" has_line "$out" "delete	aaaaaaaaaaa8	worktree-removed"
check "worktree: other untouched" not contains "$out" aaaaaaaaaaa9
check "worktree: tools untouched" not contains "$out" tools
out="$(cache_select_worktree "$TMP/exists" <<<"$(cache_slug "$TMP/exists")			0	1")"
check "worktree: existing path kept" has_line "$out" "keep	$(cache_slug "$TMP/exists")	origin-exists"
out="$(cache_select_worktree "$wt_gone" <<<"$s_gone			1	1")"
check "worktree: locked kept" has_line "$out" "keep	$s_gone	in-use"

check "human bytes" test "$(cache_human 512)" = "512 B"
check "human KiB" test "$(cache_human 1536)" = "1.5 KiB"
check "human GiB" test "$(cache_human $((3 * 1024 * 1024 * 1024)))" = "3.0 GiB"

# --- Fake volume -----------------------------------------------------------------------
# mk_target <name> [origin path] [age]: a target with a profile dir, a lock file and a payload.
VOL="$TMP/vol"
mk_target() {
  local d="$VOL/target/$1"
  mkdir -p "$d/debug/deps" "$d/debug/.fingerprint"
  touch "$d/debug/.cargo-lock"
  head -c 65536 /dev/zero > "$d/debug/deps/libpayload.rlib"
  [[ -n "${2:-}" ]] && printf 'path=%s\nlast_used=2026-11-08T10:00:00Z\n' "$2" > "$d/.origin"
  if [[ -n "${3:-}" ]]; then find "$d" -exec touch -h -d "$3" {} +; fi
  return 0
}
mk_volume() {
  rm -rf "$VOL"
  mkdir -p "$VOL/target/tools/release" "$VOL/sccache" "$VOL/cargo" "$VOL/npm" "$VOL/tools"
  head -c 4096 /dev/zero > "$VOL/sccache/blob"
  mk_target "$S_EXIST" "$TMP/exists" "3 hours ago"
  mk_target "$S_GONE" "$TMP/gone" "3 hours ago"
  mk_target "$S_OLD" "" "3 hours ago"
  mk_target "$S_RECENT" ""
  mk_target "$S_LOCKED" "$TMP/gone2" "3 hours ago"
  mk_target "$(cache_slug "$ROOT")" "" "3 hours ago" # live checkout without marker
  return 0
}
# Holds the cargo lock of S_LOCKED, like a running build.
hold_lock() {
  local f="$VOL/target/$S_LOCKED/debug/.cargo-lock"
  release_lock
  flock -o "$f" sleep 60 &
  LOCK_PID=$!
  for _ in $(seq 50); do flock -n "$f" true 2>/dev/null || break; sleep 0.1; done
}
mk_volume
hold_lock

out="$(CACHE_ROOT="$VOL" bash "$CT" list)"
check "ct list: 7 dirs" test "$(wc -l <<<"$out")" -eq 7
check "ct list: origin and last_used" contains "$out" "$S_GONE	$TMP/gone	2026-11-08T10:00:00Z	0	"
check "ct list: lock detected" contains "$out" "$S_LOCKED	$TMP/gone2	2026-11-08T10:00:00Z	1	"
check "ct list: unlocked target" contains "$out" "$S_OLD			0	"
old_mtime="$(awk -F'\t' -v n="$S_OLD" '$1 == n { print $5 }' <<<"$out")"
check "ct list: newest mtime" test "$(( $(date +%s) - old_mtime ))" -ge 10000

out="$(CACHE_ROOT="$VOL" bash "$CT" sizes "$S_GONE" tools nope)"
check "ct sizes: only slugs" test "$(wc -l <<<"$out")" -eq 1
check "ct sizes: bytes" test "$(cut -f2 <<<"$out")" -ge 65536

out="$(CACHE_ROOT="$VOL" bash "$CT" rm "$S_GONE@2026-11-08T10:00:00Z" "$S_LOCKED@2026-11-08T10:00:00Z" \
  "$S_OLD@stale" tools@ "cccccccccccc@")"
check "ct rm: deleted" contains "$out" "deleted	$S_GONE	"
check "ct rm: gone" test ! -e "$VOL/target/$S_GONE"
check "ct rm: lock respected" has_line "$out" "skipped	$S_LOCKED	in-use"
check "ct rm: locked kept" test -d "$VOL/target/$S_LOCKED"
check "ct rm: last_used changed" has_line "$out" "skipped	$S_OLD	used-since-listing"
check "ct rm: not a slug" has_line "$out" "skipped	tools	not-a-slug"
check "ct rm: missing" has_line "$out" "skipped	cccccccccccc	missing"
check "ct rm: no trash left" test -z "$(find "$VOL/target" -maxdepth 1 -name '.trash-*')"

out="$(CACHE_ROOT="$VOL" bash "$CT" usage)"
check "ct usage: sccache" contains "$out" $'\nsccache\t'
check "ct usage: target/tools" contains "$out" "target/tools	"
check "ct usage: fs" contains "$out" "fs-avail	"

# --- ./x.sh clean (local mode, no container) -------------------------------------------
xclean() { NETSIFT_CACHE_ROOT="$VOL" bash "$ROOT/x.sh" clean "$@" 2>&1; }
release_lock
mk_volume
hold_lock
out="$(xclean --dry-run)"; rc=$?
check "clean dry-run: ok" test "$rc" -eq 0
check "clean dry-run: lists orphan" contains "$out" "$S_GONE"
check "clean dry-run: lists unknown" contains "$out" "$S_OLD"
check "clean dry-run: keeps the orphan" test -d "$VOL/target/$S_GONE"
check "clean dry-run: keeps the unknown" test -d "$VOL/target/$S_OLD"
check "clean dry-run: report" contains "$out" "sccache"

out="$(xclean)"; rc=$?
check "clean: ok" test "$rc" -eq 0
check "clean: orphan deleted" test ! -e "$VOL/target/$S_GONE"
check "clean: unknown deleted" test ! -e "$VOL/target/$S_OLD"
check "clean: origin exists kept" test -d "$VOL/target/$S_EXIST"
check "clean: recent kept" test -d "$VOL/target/$S_RECENT"
check "clean: locked kept" test -d "$VOL/target/$S_LOCKED"
check "clean: live root kept" test -d "$VOL/target/$(cache_slug "$ROOT")"
check "clean: target/tools kept" test -d "$VOL/target/tools/release"
check "clean: tools kept" test -d "$VOL/tools"
check "clean: freed reported" contains "$out" "KiB"

out="$(xclean --auto)"; rc=$?
check "clean --auto: ok" test "$rc" -eq 0
check "clean --auto: silent when nothing to do" test -z "$out"
mk_target "$S_GONE" "$TMP/gone" "3 hours ago"
out="$(xclean --auto)"
check "clean --auto: reports a deletion" contains "$out" "$S_GONE"
check "clean --auto: deleted" test ! -e "$VOL/target/$S_GONE"
check "clean --auto: no usage report" not contains "$out" "sccache"

out="$(xclean --all)"; rc=$?
check "clean --all: ok" test "$rc" -eq 0
check "clean --all: live deleted" test ! -e "$VOL/target/$S_EXIST"
check "clean --all: live root deleted" test ! -e "$VOL/target/$(cache_slug "$ROOT")"
check "clean --all: locked kept" test -d "$VOL/target/$S_LOCKED"
check "clean --all: tools kept" test -d "$VOL/target/tools/release"
check "clean --all: sccache kept" test -f "$VOL/sccache/blob"
check "clean --all: cargo kept" test -d "$VOL/cargo"
check "clean --all: npm kept" test -d "$VOL/npm"

mk_target "$s_gone" "" "3 hours ago"
mk_target "aaaaaaaaaaa8" "$wt_gone"
mk_target "$S_EXIST" "$TMP/exists"
out="$(xclean --worktree "$wt_gone")"; rc=$?
check "clean --worktree: ok" test "$rc" -eq 0
check "clean --worktree: slug deleted" test ! -e "$VOL/target/$s_gone"
check "clean --worktree: origin match deleted" test ! -e "$VOL/target/aaaaaaaaaaa8"
check "clean --worktree: others kept" test -d "$VOL/target/$S_EXIST"
mk_target "$(cache_slug "$TMP/exists")"
xclean --worktree "$TMP/exists" >/dev/null
check "clean --worktree: existing path kept" test -d "$VOL/target/$(cache_slug "$TMP/exists")"

out="$(xclean --bogus)"; rc=$?
check "clean: unknown option fails" test "$rc" -ne 0
release_lock

# --- scripts/wt.sh hooks (stub x.sh) ---------------------------------------------------
REPO="$TMP/repo"
mkdir -p "$REPO/scripts/lib"
cp "$ROOT/scripts/wt.sh" "$REPO/scripts/"
cp "$ROOT/scripts/lib/cache.sh" "$REPO/scripts/lib/"
cat > "$REPO/x.sh" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$(dirname "$0")/.git/x-calls"
[[ -n "${STUB_FAIL:-}" ]] && exit 1
exit 0
EOF
chmod +x "$REPO/x.sh"
git_q() { git -C "$REPO" -c user.name=t -c user.email=t@t -c init.defaultBranch=main "$@" >/dev/null 2>&1; }
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
git_q init
printf '.worktrees/\n' > "$REPO/.gitignore"
git_q add -A
git_q commit -m init
wt="$REPO/.worktrees/chore/demo"
calls() { cat "$REPO/.git/x-calls" 2>/dev/null; }

bash "$REPO/scripts/wt.sh" new chore/demo >/dev/null 2>&1; rc=$?
check "wt new: ok" test "$rc" -eq 0
check "wt new: auto clean" has_line "$(calls)" "clean --auto"
rm -f "$REPO/.git/x-calls"
bash "$REPO/scripts/wt.sh" rm chore/demo --delete-branch >/dev/null 2>&1; rc=$?
check "wt rm: ok" test "$rc" -eq 0
check "wt rm: target of the removed worktree" has_line "$(calls)" "clean --worktree $wt"

rm -f "$REPO/.git/x-calls"
STUB_FAIL=1 bash "$REPO/scripts/wt.sh" new chore/demo >/dev/null 2>&1; rc=$?
check "wt new: clean failure is only a warning" test "$rc" -eq 0
out="$(STUB_FAIL=1 bash "$REPO/scripts/wt.sh" rm chore/demo 2>&1)"; rc=$?
check "wt rm: clean failure is only a warning" test "$rc" -eq 0
check "wt rm: warning printed" contains "$out" "avertissement"
check "wt rm: worktree removed anyway" test ! -e "$wt"

rm -f "$REPO/.git/x-calls"
NETSIFT_NO_AUTO_CLEAN=1 bash "$REPO/scripts/wt.sh" new chore/demo2 >/dev/null 2>&1
check "wt new: NETSIFT_NO_AUTO_CLEAN" not contains "$(calls)" "clean --auto"

# merge --cleanup: target of the merged worktree, then automatic clean.
git_q -C "$REPO/.worktrees/chore/demo2" commit --allow-empty -m change
rm -f "$REPO/.git/x-calls"
bash "$REPO/scripts/wt.sh" merge chore/demo2 --cleanup --no-check >/dev/null 2>&1; rc=$?
check "wt merge --cleanup: ok" test "$rc" -eq 0
check "wt merge --cleanup: worktree target" has_line "$(calls)" "clean --worktree $REPO/.worktrees/chore/demo2"
check "wt merge --cleanup: auto clean last" test "$(calls | tail -n 1)" = "clean --auto"

echo "cache tests: $pass passed, $failures failed"
[[ "$failures" -eq 0 ]]
