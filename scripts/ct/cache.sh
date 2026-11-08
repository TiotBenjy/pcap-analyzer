#!/usr/bin/env bash
# Build cache hygiene, container side. x.sh pipes this file to `bash -s` in a container that
# mounts only the cache volume at /cache. Decisions are taken on the host (scripts/lib/cache.sh),
# which alone can tell whether a checkout path still exists.
# Tests run it on a plain directory: CACHE_ROOT=<dir> bash scripts/ct/cache.sh <cmd>.
#
#   list [--purge]     first the leftovers of interrupted deletions (target/.trash-*):
#                      "#trash TAB name TAB bytes TAB pending|purged|failed" (deleted with --purge),
#                      then one line per target dir:
#                      name TAB origin path TAB last_used TAB locked (0|1) TAB newest mtime
#   sizes <name...>    name TAB bytes on disk
#   rm <name@last...>  deletes target/<name> if its last_used is still <last> and no build holds
#                      its cargo lock; prints "deleted TAB name TAB bytes",
#                      "failed TAB name TAB bytes" (left in target/.trash-*, purged by the next
#                      clean) or "skipped TAB name TAB reason"
#   usage              category TAB bytes (target/<name>, top-level dirs, fs-avail, fs-size)
set -euo pipefail

CACHE_ROOT="${CACHE_ROOT:-/cache}"
TARGETS="$CACHE_ROOT/target"

is_slug() { [[ "$1" =~ ^[0-9a-f]{12}$ ]]; }

origin_field() { # <dir> <key>: value of "key=" in <dir>/.origin, first line only
  [[ -f "$1/.origin" ]] || return 0
  sed -n "s/^$2=//p" "$1/.origin" 2>/dev/null | head -n 1 | tr -d '\t\r'
}

# A cargo build holds an exclusive flock on <target>/<profile>/.cargo-lock (cargo 1.99 also on
# .cargo-build-lock and .cargo-artifact-lock) while it runs: a lock we cannot take means "in use".
locked() {
  local f
  for f in "$1"/.cargo-*lock "$1"/*/.cargo-*lock "$1"/*/*/.cargo-*lock; do
    [[ -f "$f" ]] || continue
    flock -n "$f" true 2>/dev/null || return 0
  done
  return 1
}

# Newest mtime among the entries cargo touches on each build (cheap: no recursive walk).
newest_mtime() {
  local d="$1"
  stat -c %Y "$d" "$d"/.origin "$d"/* "$d"/*/deps "$d"/*/.fingerprint "$d"/*/incremental \
    2>/dev/null | sort -n | tail -n 1 || true
}

locked_flag() { if locked "$1"; then echo 1; else echo 0; fi; }

# Bytes on disk; 0 when du fails (unreadable subdir: du still prints a total but exits 1, which
# must not abort the whole batch under `set -e` + pipefail).
bytes() {
  local b
  b="$({ du -s -B1 "$1" 2>/dev/null || true; } | cut -f1)"
  echo "${b:-0}"
}

cmd_list() {
  [[ -d "$TARGETS" ]] || return 0
  local d name size state
  for d in "$TARGETS"/.trash-*; do
    [[ -d "$d" && ! -L "$d" ]] || continue
    size="$(bytes "$d")"; state=pending
    if [[ "${1:-}" == "--purge" ]]; then
      if rm -rf "$d" 2>/dev/null; then state=purged; else state=failed; fi
    fi
    printf '#trash\t%s\t%s\t%s\n' "${d##*/}" "$size" "$state"
  done
  for d in "$TARGETS"/*/; do
    d="${d%/}"; name="${d##*/}"
    [[ -d "$d" && ! -L "$d" ]] || continue
    printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$(origin_field "$d" path)" \
      "$(origin_field "$d" last_used)" "$(locked_flag "$d")" \
      "$(newest_mtime "$d")"
  done
}

cmd_sizes() {
  local name
  for name in "$@"; do
    if ! is_slug "$name" || [[ ! -d "$TARGETS/$name" ]]; then continue; fi
    printf '%s\t%s\n' "$name" "$(bytes "$TARGETS/$name")"
  done
}

cmd_rm() {
  local arg name last d trash size
  for arg in "$@"; do
    name="${arg%%@*}"; last="${arg#*@}"; d="$TARGETS/$name"
    if ! is_slug "$name"; then printf 'skipped\t%s\tnot-a-slug\n' "$name"; continue; fi
    if [[ ! -d "$d" ]]; then printf 'skipped\t%s\tmissing\n' "$name"; continue; fi
    if [[ "$(origin_field "$d" last_used)" != "$last" ]]; then
      printf 'skipped\t%s\tused-since-listing\n' "$name"; continue
    fi
    if locked "$d"; then printf 'skipped\t%s\tin-use\n' "$name"; continue; fi
    # Atomic rename right after the checks (nothing slow in between): a build starting from now on
    # gets a fresh, empty target dir. Sized and deleted afterwards, under the trash name.
    trash="$TARGETS/.trash-$name-$$-$RANDOM"
    if ! mv "$d" "$trash" 2>/dev/null; then
      printf 'skipped\t%s\trename-failed\n' "$name"; continue
    fi
    size="$(bytes "$trash")"
    if rm -rf "$trash" 2>/dev/null; then
      printf 'deleted\t%s\t%s\n' "$name" "$size"
    else
      printf 'failed\t%s\t%s\n' "$name" "$size"
    fi
  done
}

cmd_usage() {
  local d
  if [[ -d "$TARGETS" ]]; then
    for d in "$TARGETS"/*/; do
      d="${d%/}"; [[ -d "$d" ]] || continue
      printf 'target/%s\t%s\n' "${d##*/}" "$(bytes "$d")"
    done
  fi
  for d in "$CACHE_ROOT"/*/; do
    d="${d%/}"; [[ -d "$d" && "${d##*/}" != target ]] || continue
    printf '%s\t%s\n' "${d##*/}" "$(bytes "$d")"
  done
  df -B1 --output=avail,size "$CACHE_ROOT" 2>/dev/null | awk 'NR == 2 {
    printf "fs-avail\t%s\nfs-size\t%s\n", $1, $2 }'
}

cmd="${1:-}"; shift || true
case "$cmd" in
  list) cmd_list "$@" ;;
  sizes) cmd_sizes "$@" ;;
  rm) cmd_rm "$@" ;;
  usage) cmd_usage ;;
  *) echo "cache.sh: unknown command '$cmd'" >&2; exit 2 ;;
esac
