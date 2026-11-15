#!/usr/bin/env bash
# Exécuté DANS le conteneur par `./x.sh fuzz ...` (cibles cargo-fuzz de fuzz/, docs/FUZZING.md).
#
#   ./x.sh fuzz                      liste les cibles
#   ./x.sh fuzz build                compile toutes les cibles (sanitizer address, debug-assertions)
#   ./x.sh fuzz corpus               régénère les graines (fuzz/seeds/<cible>) depuis netsift-fixtures
#   ./x.sh fuzz <cible> [durée]      fuzz une cible (60 s par défaut)
#   ./x.sh fuzz all [durée] [jobs]   campagne : toutes les cibles en parallèle (jobs = cœurs - 2),
#                                    journaux et bilan dans .artifacts/fuzz/
#   ./x.sh fuzz tmin <cible> <fichier>   minimise une entrée qui plante
#
# La toolchain nightly et cargo-fuzz sont installés une seule fois dans le volume de cache
# (/cache/tools), à des versions épinglées ; la toolchain stable de l'image n'est pas touchée.
set -euo pipefail

NIGHTLY="nightly-2026-11-10"
CARGO_FUZZ_VERSION="0.13.2"
# Délai par entrée au-delà duquel libFuzzer signale un « timeout » (secondes).
UNIT_TIMEOUT="${FUZZ_TIMEOUT:-25}"
# Plafond mémoire par processus (Mo).
RSS_LIMIT="${FUZZ_RSS_LIMIT_MB:-2048}"

TOOLS="/cache/tools/cargo-fuzz-${CARGO_FUZZ_VERSION}"
if [[ "${NETSIFT_FUZZ_HOST:-0}" == 1 ]]; then
  # Hors conteneur (CI, scripts/ci/fuzz.sh) : nightly et cargo-fuzz installés par le workflow.
  BASE_TARGET="${CARGO_TARGET_DIR:-$PWD/target}"
else
  # Nightly dans un RUSTUP_HOME du cache : celui de l'image n'est pas inscriptible et le
  # conteneur est éphémère.
  export RUSTUP_HOME=/cache/tools/rustup
  export PATH="$TOOLS/bin:$PATH"
  BASE_TARGET="${CARGO_TARGET_DIR:-/cache/target/root}"
  # Pas de sccache : les objets instrumentés évinceraient le cache des builds stables.
  export RUSTC_WRAPPER=""
  unset CARGO_BUILD_RUSTC_WRAPPER || true
fi
# La nightly pour tout cargo lancé par ce script (rust-toolchain.toml épingle la stable).
export RUSTUP_TOOLCHAIN="$NIGHTLY"
# Artefacts nightly/sanitizer à part du target stable du worktree (supprimés avec lui).
export CARGO_TARGET_DIR="$BASE_TARGET/fuzz"

FUZZ_DIR=fuzz
TRIPLE="x86_64-unknown-linux-gnu"
BIN_DIR="$CARGO_TARGET_DIR/$TRIPLE/release"
LOG_DIR=".artifacts/fuzz"

setup() {
  [[ "${NETSIFT_FUZZ_HOST:-0}" == 1 ]] && return 0
  if ! rustup toolchain list 2>/dev/null | grep -q "^${NIGHTLY}"; then
    echo ">> Installation de ${NIGHTLY} dans le cache (une seule fois)…" >&2
    rustup toolchain install "$NIGHTLY" --profile minimal >&2
  fi
  if [[ ! -x "$TOOLS/bin/cargo-fuzz" ]]; then
    echo ">> Installation de cargo-fuzz ${CARGO_FUZZ_VERSION} dans le cache (une seule fois)…" >&2
    cargo binstall -y --root "$TOOLS" "cargo-fuzz@${CARGO_FUZZ_VERSION}" >&2 \
      || cargo install --locked --quiet --root "$TOOLS" --target-dir /cache/target/tools \
           "cargo-fuzz@${CARGO_FUZZ_VERSION}" >&2
  fi
}

targets() { cargo fuzz list --fuzz-dir "$FUZZ_DIR"; }

# --target explicite : le cargo-fuzz précompilé (musl) prendrait sinon sa propre cible par défaut.
build() { cargo fuzz build --fuzz-dir "$FUZZ_DIR" --target "$TRIPLE" "$@"; }

# Graines : générées depuis netsift-fixtures (rien de binaire n'est commité), dans un target à part
# (sans les drapeaux d'instrumentation de cargo-fuzz).
corpus() {
  rm -rf "$FUZZ_DIR/seeds"
  CARGO_TARGET_DIR="$BASE_TARGET/fuzz-gen" \
    cargo run --quiet --manifest-path "$FUZZ_DIR/Cargo.toml" --example gen_corpus -- "$FUZZ_DIR/seeds"
}

ensure_corpus() { [[ -d "$FUZZ_DIR/seeds" ]] || corpus; }

# Options libFuzzer communes à une cible : dictionnaire éventuel, artefacts par cible.
lf_args() {
  local t="$1" args=()
  [[ -f "$FUZZ_DIR/dict/$t.dict" ]] && args+=("-dict=$FUZZ_DIR/dict/$t.dict")
  mkdir -p "$FUZZ_DIR/artifacts/$t"
  args+=("-artifact_prefix=$FUZZ_DIR/artifacts/$t/" "-timeout=$UNIT_TIMEOUT" "-rss_limit_mb=$RSS_LIMIT")
  printf '%s\n' "${args[@]}"
}

run_one() { # <cible> <durée> : processus libFuzzer, corpus vivant puis graines
  local t="$1" d="$2"
  mkdir -p "$FUZZ_DIR/corpus/$t" "$FUZZ_DIR/seeds/$t"
  mapfile -t extra < <(lf_args "$t")
  "$BIN_DIR/$t" "$FUZZ_DIR/corpus/$t" "$FUZZ_DIR/seeds/$t" \
    -max_total_time="$d" -print_final_stats=1 "${extra[@]}"
}

# Dernière ligne de statut libFuzzer d'un journal : exécutions, couverture, features, corpus.
summarize() { # <cible> <journal> <code>
  local t="$1" log="$2" rc="$3" runs cov ft corp status="ok"
  runs="$(grep -oE 'stat::number_of_executed_units: *[0-9]+' "$log" | grep -oE '[0-9]+$' | tail -1)"
  cov="$(grep -oE ' cov: [0-9]+' "$log" | tail -1 | grep -oE '[0-9]+')"
  ft="$(grep -oE ' ft: [0-9]+' "$log" | tail -1 | grep -oE '[0-9]+')"
  corp="$(grep -oE ' corp: [0-9]+' "$log" | tail -1 | grep -oE '[0-9]+')"
  if [[ "$rc" != 0 ]] || grep -qE '^==[0-9]+== ?ERROR|^SUMMARY: |panicked at|deadly signal' "$log"; then
    status="CRASH"
  fi
  printf '%-14s %-6s runs=%-12s cov=%-6s ft=%-7s corpus=%s\n' "$t" "$status" "${runs:-?}" "${cov:-?}" "${ft:-?}" "${corp:-?}"
}

campaign() { # [durée] [jobs]
  local d="${1:-1800}" jobs="${2:-$(( $(nproc) - 2 ))}"
  (( jobs >= 1 )) || jobs=1
  ensure_corpus
  build
  mkdir -p "$LOG_DIR"
  mapfile -t list < <(targets)
  echo ">> Campagne : ${#list[@]} cibles, ${d}s chacune, ${jobs} en parallèle (journaux : $LOG_DIR)"
  local running=0 t
  for t in "${list[@]}"; do
    while (( running >= jobs )); do wait -n || true; running=$(( running - 1 )); done
    ( run_one "$t" "$d" >"$LOG_DIR/$t.log" 2>&1; echo $? >"$LOG_DIR/$t.rc" ) &
    running=$(( running + 1 ))
  done
  wait || true
  local failed=0
  {
    echo "# Campagne du $(date -u +%Y-%m-%dT%H:%MZ), ${d}s par cible, ${NIGHTLY}, cargo-fuzz ${CARGO_FUZZ_VERSION}"
    for t in "${list[@]}"; do
      local rc; rc="$(cat "$LOG_DIR/$t.rc" 2>/dev/null || echo 1)"
      summarize "$t" "$LOG_DIR/$t.log" "$rc"
    done
  } | tee "$LOG_DIR/summary.txt"
  grep -q ' CRASH ' "$LOG_DIR/summary.txt" && failed=1
  return "$failed"
}

# main ne démarre qu'une fois le fichier entièrement lu, et exit empêche toute relecture : modifier
# ce script pendant une campagne ne change pas ce qui tourne.
main() {
  setup
  case "${1:-}" in
    ""|list) echo "Cibles disponibles :"; targets ;;
    setup)   ;;
    build)   shift; build "$@" ;;
    corpus)  corpus; echo ">> Graines écrites dans $FUZZ_DIR/seeds" ;;
    all)     shift; campaign "$@" ;;
    tmin)    shift; t="$1"; f="$2"; build "$t" >/dev/null
             "$BIN_DIR/$t" -minimize_crash=1 -runs=200000 -exact_artifact_path="$f.min" "$f" ;;
    *)       t="$1"; d="${2:-60}"; ensure_corpus; build "$t"
             echo ">> Fuzzing $t pendant ${d}s"; run_one "$t" "$d" ;;
  esac
}

main "$@"
exit $?
