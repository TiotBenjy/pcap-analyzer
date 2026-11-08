# shellcheck shell=bash
# Build cache hygiene, host side: helpers shared by x.sh (`./x.sh clean`) and scripts/wt.sh.
# Sourced, never executed. Pure bash + git + coreutils: no toolchain, no container.
# The container side (listing, deletion, disk usage of the volume) is scripts/ct/cache.sh.
#
# Layout of the cache volume (mounted at /cache in the container):
#   target/<slug>/          CARGO_TARGET_DIR of one checkout, slug = cache_slug <host path>
#   target/<slug>/.origin   "path=<host path>" and "last_used=<UTC date>", written by x.sh
#   target/tools/           build dir of the tools installed by scripts/ct (never touched)
#   tools/ sccache/ cargo/ npm/   shared caches (never touched by the cleaner)

# Slug of a checkout path, naming its target dir. Never change the formula: existing targets
# are found by this name (the newline added by echo is part of the hashed input).
cache_slug() { printf '%s\n' "$1" | sha1sum | cut -c1-12; }

# Only directories named like a slug are managed; anything else (tools/, root/...) is kept.
cache_is_slug() { [[ "$1" =~ ^[0-9a-f]{12}$ ]]; }

# Slugs of every checkout of the repository containing <dir> (main checkout + worktrees),
# one per line. Prints nothing outside a git repository.
cache_live_slugs() {
  local p
  git -C "$1" worktree list --porcelain 2>/dev/null | sed -n 's/^worktree //p' \
    | while IFS= read -r p; do cache_slug "$p"; done
}

# Reads one TAB-separated listing row into the named variables, keeping empty fields (TAB is an
# IFS whitespace character: a plain `IFS=$'\t' read` would merge consecutive separators).
cache_read_row() {
  local _row
  IFS= read -r _row || return 1
  IFS=$'\x1f' read -r "$@" <<<"${_row//$'\t'/$'\x1f'}"
}

# Decides which targets to delete.
#   cache_select <orphans|all> <now epoch s> <grace s> <live slugs, newline-separated>
# stdin: listing of scripts/ct/cache.sh `list`, one target per line:
#   name TAB origin path TAB last_used TAB locked (0|1) TAB newest mtime (epoch s)
# stdout: one decision per target: delete|keep TAB name TAB reason
# Rules, in order:
#   - not a slug (tools/, ...)                -> keep  unmanaged
#   - a cargo lock is held (build running)    -> keep  in-use
#   - mode all                                -> delete all
#   - .origin path exists on the host         -> keep  origin-exists
#   - .origin path is gone                    -> delete origin-gone
#   - no .origin, slug of a live checkout     -> keep  live-worktree
#   - no .origin, touched less than grace ago -> keep  recent  (older x.sh, clone in use)
#   - no .origin otherwise                    -> delete unknown
cache_select() {
  local mode="$1" now="$2" grace="$3" live="$4"
  local name origin locked mtime
  while cache_read_row name origin _ locked mtime; do
    [[ -n "$name" ]] || continue
    if ! cache_is_slug "$name"; then
      printf 'keep\t%s\tunmanaged\n' "$name"
    elif [[ "$locked" == "1" ]]; then
      printf 'keep\t%s\tin-use\n' "$name"
    elif [[ "$mode" == "all" ]]; then
      printf 'delete\t%s\tall\n' "$name"
    elif [[ -n "$origin" && -e "$origin" ]]; then
      printf 'keep\t%s\torigin-exists\n' "$name"
    elif [[ -n "$origin" ]]; then
      printf 'delete\t%s\torigin-gone\n' "$name"
    elif [[ $'\n'"$live"$'\n' == *$'\n'"$name"$'\n'* ]]; then
      printf 'keep\t%s\tlive-worktree\n' "$name"
    elif [[ "$mtime" =~ ^[0-9]+$ ]] && (( now - mtime < grace )); then
      printf 'keep\t%s\trecent\n' "$name"
    else
      printf 'delete\t%s\tunknown\n' "$name"
    fi
  done
}

# Targets of one removed checkout: its slug, plus any target whose .origin names it.
#   cache_select_worktree <host path>   (stdin/stdout as cache_select)
# Nothing is selected while <host path> still exists or when a build holds the lock.
cache_select_worktree() {
  local path="$1" slug name origin locked
  slug="$(cache_slug "$path")"
  while cache_read_row name origin _ locked _; do
    cache_is_slug "$name" || continue
    [[ "$name" == "$slug" || "$origin" == "$path" ]] || continue
    if [[ -e "$path" ]]; then
      printf 'keep\t%s\torigin-exists\n' "$name"
    elif [[ "$locked" == "1" ]]; then
      printf 'keep\t%s\tin-use\n' "$name"
    else
      printf 'delete\t%s\tworktree-removed\n' "$name"
    fi
  done
}

# Human-readable size of a byte count (IEC units, one decimal).
cache_human() {
  awk -v b="${1:-0}" 'BEGIN {
    split("B KiB MiB GiB TiB", u, " "); i = 1
    while (b >= 1024 && i < 5) { b /= 1024; i++ }
    if (i == 1) printf "%d %s", b, u[i]; else printf "%.1f %s", b, u[i] }'
}
