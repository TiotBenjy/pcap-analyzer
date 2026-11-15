#!/usr/bin/env bash
# Mesures de docs/PERFORMANCE.md, dans le conteneur : `./x.sh bench [all|gen|ingest|queries] [options]`.
#
#   gen      génère le jeu de chunks synthétiques (netsift-fixtures big) s'il manque
#   ingest   importe le jeu sur 4 cœurs (taskset, 2 shards = cœurs - 2), puis sur tous les cœurs
#   queries  chronomètre chaque endpoint de vue sur la session importée sur 4 cœurs
#   all      les trois (défaut)
#
# Variables : BENCH_SIZE (défaut 5G), BENCH_CHUNK (500M), BENCH_HOURS (168), BENCH_CPUS (0-3),
# BENCH_SHARDS (2), BENCH_REPEAT (9), BENCH_ONLY (filtre de queries), BENCH_FULL=0 (saute
# l'import sur tous les cœurs).
# Données : captures/bench/mix-<taille>/ (chunks), .artifacts/bench/ (sessions et rapports),
# ignorés par git. Un seul jeu est gardé : changer BENCH_SIZE remplace l'ancien.
set -euo pipefail

STEP="${1:-all}"
SIZE="${BENCH_SIZE:-5G}"
CHUNK="${BENCH_CHUNK:-500M}"
HOURS="${BENCH_HOURS:-168}"
CPUS="${BENCH_CPUS:-0-3}"
SHARDS="${BENCH_SHARDS:-2}"
REPEAT="${BENCH_REPEAT:-9}"
SRC="captures/bench/mix-$SIZE"
OUT=".artifacts/bench"
BIN="$CARGO_TARGET_DIR/release"

build() {
  echo ">> Build release (netsift-fixtures, netsift --features bench)"
  cargo build -q --release -p netsift-fixtures -p netsift-cli --features netsift-cli/bench
}

gen() {
  if [[ -f "$SRC/.complete" ]]; then
    echo ">> Jeu présent : $SRC"
    return
  fi
  # Un seul jeu à la fois (plusieurs Go chacun).
  rm -rf captures/bench/mix-*
  echo ">> Génération de $SIZE de trafic mixte sur ${HOURS} h dans $SRC"
  local t0=$SECONDS
  "$BIN/netsift-fixtures" big --out "$SRC" --size "$SIZE" --chunk "$CHUNK" --hours "$HOURS"
  touch "$SRC/.complete"
  echo ">> Généré en $((SECONDS - t0)) s"
}

ingest() {
  mkdir -p "$OUT"
  rm -rf "$OUT/data-4cpu" "$OUT/data-all"
  echo ">> Import sur les cœurs $CPUS, $SHARDS shards"
  taskset -c "$CPUS" "$BIN/netsift" bench ingest "$SRC" --out "$OUT/data-4cpu" --shards "$SHARDS" \
    | tee "$OUT/ingest-4cpu.md"
  if [[ "${BENCH_FULL:-1}" == 1 ]]; then
    echo ">> Import sur tous les cœurs ($(nproc))"
    "$BIN/netsift" bench ingest "$SRC" --out "$OUT/data-all" | tee "$OUT/ingest-all.md"
    rm -rf "$OUT/data-all"
  fi
}

queries() {
  [[ -d "$OUT/data-4cpu" ]] || { echo "bench: pas de session, lancer d'abord ./x.sh bench ingest" >&2; exit 1; }
  echo ">> Requêtes de vue ($REPEAT appels chronométrés chacune)"
  local only=()
  [[ -n "${BENCH_ONLY:-}" ]] && only=(--only "$BENCH_ONLY")
  "$BIN/netsift" bench queries --data-dir "$OUT/data-4cpu" --repeat "$REPEAT" "${only[@]}" \
    | tee "$OUT/queries.md"
}

case "$STEP" in
  gen) build; gen ;;
  ingest) build; gen; ingest ;;
  queries) build; queries ;;
  all) build; gen; ingest; queries ;;
  *) echo "bench: étape inconnue : $STEP (all, gen, ingest, queries)" >&2; exit 2 ;;
esac
echo ">> Rapports dans $OUT/"
