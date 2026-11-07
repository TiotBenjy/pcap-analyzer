#!/usr/bin/env bash
# Exécuté DANS le conteneur par `./x.sh dev`.
# Compile et démarre l'API Rust, puis Vite (HMR) dont le proxy injecte le jeton ; arrêt propre.
# Après une modification du backend : Ctrl-C puis relancer `./x.sh dev` (le frontend est à chaud).
set -euo pipefail
UI_PORT="${NETSIFT_UI_PORT:-5173}"
API_PORT="${NETSIFT_API_PORT:-7878}"
TOKEN_FILE="$(mktemp)"
head -c 32 /dev/urandom | base64 | tr -d '/+=' > "$TOKEN_FILE"

cleanup() { kill "${API_PID:-}" "${UI_PID:-}" 2>/dev/null || true; rm -f "$TOKEN_FILE"; }
trap cleanup EXIT INT TERM

CAPTURE_ARGS=()
[ -d /captures ] && CAPTURE_ARGS=(--captures-root /captures)

echo ">> Compilation de l'API (la première fois peut prendre quelques minutes)…"
cargo build -p netsift-cli
NETSIFT_BIN="${CARGO_TARGET_DIR:-target}/debug/netsift"

echo ">> Lancement de l'API (port $API_PORT)…"
# En dev on écoute sur 0.0.0.0 DANS le conteneur ; l'hôte ne publie que sur 127.0.0.1 (voir x.sh).
"$NETSIFT_BIN" serve \
  --bind "0.0.0.0:${API_PORT}" \
  --token-file "$TOKEN_FILE" \
  "${CAPTURE_ARGS[@]}" \
  --data-dir .data &
API_PID=$!

for _ in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:${API_PORT}/api/v1/health" >/dev/null 2>&1 && break
  kill -0 "$API_PID" 2>/dev/null || { echo "L'API s'est arrêtée au démarrage." >&2; exit 1; }
  sleep 0.5
done

if [ ! -d ui/node_modules ]; then (cd ui && npm ci); fi

echo ">> Lancement de Vite (port $UI_PORT)…"
NETSIFT_API_URL="http://127.0.0.1:${API_PORT}" \
NETSIFT_API_TOKEN="$(cat "$TOKEN_FILE")" \
  npm --prefix ui run dev -- --host 0.0.0.0 --port "${UI_PORT}" --strictPort &
UI_PID=$!

echo ">> Prêt : http://localhost:${UI_PORT}  (Ctrl-C pour arrêter)"
wait -n "$API_PID" "$UI_PID"
