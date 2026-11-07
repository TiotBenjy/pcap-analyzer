#!/usr/bin/env bash
# NetSift — pilote de la toolchain conteneurisée (Docker ou Podman).
# Aucune toolchain n'est requise sur l'hôte : tout s'exécute dans l'image docker/Dockerfile.
#
#   ./x.sh image                 construit (ou reconstruit) l'image
#   ./x.sh check                 fmt + clippy + tests Rust + lint/tests UI (gate CI local)
#   ./x.sh test [args]           cargo nextest run [args]
#   ./x.sh cargo <args>          cargo arbitraire
#   ./x.sh clippy | fmt | fmt-check | deny
#   ./x.sh npm <args>            npm dans ui/
#   ./x.sh ui <args>             raccourci : npm run <args> dans ui/
#   ./x.sh dev                   backend + Vite (http://localhost:${NETSIFT_UI_PORT:-5173})
#   ./x.sh shots [vue]           captures Playwright multi-largeurs (assertions UI)
#   ./x.sh desktop               build Tauri Linux (AppImage + .deb) -> dist/
#   ./x.sh desktop-win           build Windows via cargo-xwin (expérimental) -> dist/
#   ./x.sh geoip                 télécharge la base GeoIP (DB-IP Lite) dans .data/geoip/
#   ./x.sh fuzz [cible] [durée]  cargo-fuzz (nightly dans le conteneur)
#   ./x.sh shell                 shell interactif dans le conteneur
#   ./x.sh run <cmd...>          commande brute dans le conteneur
#   ./x.sh -C <dir> <sous-cmd>   exécuter la sous-commande avec <dir> comme racine (worktree)
#
# Variables : ENGINE=docker|podman (sinon auto), NETSIFT_UI_PORT, NETSIFT_API_PORT,
#             NO_SCCACHE=1 (désactive sccache), REBUILD=1 (force image).
set -euo pipefail

# --- Résolution de la racine (support de -C <dir>) ---------------------------------
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="$ROOT"
if [[ "${1:-}" == "-C" ]]; then
  [[ -n "${2:-}" ]] || { echo "x.sh: -C requiert un chemin" >&2; exit 2; }
  WORKDIR="$(cd "$2" && pwd)"
  shift 2
fi
CMD="${1:-help}"; shift || true

IMAGE="netsift-dev:latest"
CACHE_VOL="netsift-cache"

# --- Détection du moteur de conteneur ----------------------------------------------
detect_engine() {
  if [[ -n "${ENGINE:-}" ]]; then echo "$ENGINE"; return; fi
  if command -v podman >/dev/null 2>&1; then echo podman; return; fi
  if command -v docker >/dev/null 2>&1; then echo docker; return; fi
  echo "Erreur : ni podman ni docker n'est installé. NetSift n'a besoin que de l'un des deux." >&2
  exit 1
}
# Détection paresseuse : `help` ne doit pas exiger un moteur de conteneur.
if [[ "$CMD" != "help" && "$CMD" != "-h" && "$CMD" != "--help" ]]; then
  ENGINE="$(detect_engine)"
fi

# Podman : mapping d'UID transparent (--userns=keep-id). Docker : --user <uid:gid>.
userargs() {
  if [[ "$ENGINE" == "podman" ]]; then
    echo "--userns=keep-id"
  else
    echo "--user $(id -u):$(id -g)"
  fi
}

# Un slug stable par worktree pour isoler le répertoire target dans le cache partagé.
slug() { echo "$WORKDIR" | sha1sum | cut -c1-12; }

ensure_cache_vol() { "$ENGINE" volume inspect "$CACHE_VOL" >/dev/null 2>&1 || "$ENGINE" volume create "$CACHE_VOL" >/dev/null; }

image_exists() { "$ENGINE" image inspect "$IMAGE" >/dev/null 2>&1; }

build_image() {
  echo ">> Construction de l'image $IMAGE avec $ENGINE (première fois : ~10 min)…"
  "$ENGINE" build -t "$IMAGE" -f "$ROOT/docker/Dockerfile" "$ROOT"
}

ensure_image() { if [[ "${REBUILD:-0}" == "1" ]] || ! image_exists; then build_image; fi; }

# --- Exécution dans le conteneur ---------------------------------------------------
# run_in <extra docker args...> -- <commande dans le conteneur>
run_in() {
  ensure_image; ensure_cache_vol
  local extra=(); while [[ "${1:-}" != "--" ]]; do extra+=("$1"); shift; done; shift
  local scc="sccache"; [[ "${NO_SCCACHE:-0}" == "1" ]] && scc=""
  # -i : stdin toujours transmis (permet `./x.sh run bash -s < script`).
  # -t : uniquement avec un vrai terminal, sinon le pty du conteneur masque le stdin redirigé
  #      et les sorties de scripts/agents sont polluées de séquences de contrôle.
  local tty=(-i); [[ -t 0 && -t 1 ]] && tty=(-it)
  # shellcheck disable=SC2046
  "$ENGINE" run --rm "${tty[@]}" \
    $(userargs) \
    -v "$WORKDIR":/work:z \
    -v "$CACHE_VOL":/cache:z \
    -e CARGO_TARGET_DIR="/cache/target/$(slug)" \
    -e CARGO_HOME=/cache/cargo \
    -e SCCACHE_DIR=/cache/sccache \
    -e RUSTC_WRAPPER="$scc" \
    -e npm_config_cache=/cache/npm \
    -e PLAYWRIGHT_BROWSERS_PATH=/usr/local/pw-browsers \
    -e HOME=/tmp/home \
    -e CI="${CI:-}" \
    -w /work \
    "${extra[@]}" \
    "$IMAGE" bash -lc "$*"
}

# Variante non-TTY (CI, scripts).
run_in_q() { local a=(); while [[ "${1:-}" != "--" ]]; do a+=("$1"); shift; done; shift
  ensure_image; ensure_cache_vol; local scc="sccache"; [[ "${NO_SCCACHE:-0}" == "1" ]] && scc=""
  # shellcheck disable=SC2046
  "$ENGINE" run --rm $(userargs) \
    -v "$WORKDIR":/work:z -v "$CACHE_VOL":/cache:z \
    -e CARGO_TARGET_DIR="/cache/target/$(slug)" -e CARGO_HOME=/cache/cargo \
    -e SCCACHE_DIR=/cache/sccache -e RUSTC_WRAPPER="$scc" \
    -e npm_config_cache=/cache/npm -e PLAYWRIGHT_BROWSERS_PATH=/usr/local/pw-browsers \
    -e HOME=/tmp/home -e CI="${CI:-}" \
    -w /work "${a[@]}" "$IMAGE" bash -lc "$*"
}

# Ports pour dev : dérivés du slug si non fixés, pour que deux worktrees ne se marchent pas dessus.
ui_port()  { echo "${NETSIFT_UI_PORT:-$(( 5173 + (16#$(slug | cut -c1-2) % 40) ))}"; }
api_port() { echo "${NETSIFT_API_PORT:-$(( 7878 + (16#$(slug | cut -c1-2) % 40) ))}"; }

case "$CMD" in
  image)       REBUILD=1 build_image ;;
  shell)       run_in -- "${*:-bash}" ;;
  run)         run_in -- "$*" ;;

  cargo)       run_in -- "cargo $*" ;;
  test)        run_in -- "cargo nextest run $*" ;;
  clippy)      run_in -- "cargo clippy --workspace --all-targets --all-features -- -D warnings $*" ;;
  fmt)         run_in -- "cargo fmt --all $*" ;;
  fmt-check)   run_in -- "cargo fmt --all --check" ;;
  deny)        run_in -- "cargo deny check $*" ;;

  npm)         run_in -- "cd ui && npm $*" ;;
  ui)          run_in -- "cd ui && npm run $*" ;;

  check)
    # Gate identique à la CI. S'arrête à la première erreur.
    run_in_q -- '
      set -e
      echo "== rustfmt =="      && cargo fmt --all --check
      echo "== clippy =="       && cargo clippy --workspace --all-targets --all-features -- -D warnings
      echo "== cargo-deny =="   && (cargo deny check || true)   # avertit sans bloquer au début du projet
      echo "== tests Rust =="   && cargo nextest run --workspace
      echo "== bindings TS =="  && (cargo test -p netsift-api export_bindings 2>/dev/null || true)
      if [ -d ui ] && [ -f ui/package.json ]; then
        echo "== UI : install ==" && (cd ui && npm ci || npm install)
        echo "== UI : typecheck/lint ==" && (cd ui && npm run -s lint && npm run -s typecheck)
        echo "== UI : tests unitaires ==" && (cd ui && npm run -s test -- --run)
      fi
      echo "OK"
    ' ;;

  dev)
    up="$(ui_port)"; ap="$(api_port)"
    echo ">> UI  : http://localhost:${up}"
    echo ">> API : http://localhost:${ap}  (publiée sur loopback uniquement)"
    run_in -p "127.0.0.1:${up}:${up}" -p "127.0.0.1:${ap}:${ap}" \
      -e NETSIFT_UI_PORT="$up" -e NETSIFT_API_PORT="$ap" \
      -v "$ROOT/captures":/captures:ro,z \
      -- "bash scripts/ct/dev.sh" ;;

  shots)       run_in -- "bash scripts/ct/shots.sh $*" ;;
  desktop)     run_in -- "bash scripts/ct/desktop.sh linux" ;;
  desktop-win) run_in -- "bash scripts/ct/desktop.sh windows" ;;
  geoip)       run_in -- "bash scripts/ct/geoip.sh" ;;
  fuzz)        run_in -- "bash scripts/ct/fuzz.sh $*" ;;

  help|*)
    sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
esac
