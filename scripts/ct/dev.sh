#!/usr/bin/env bash
# Exécuté DANS le conteneur par `./x.sh dev`.
# Démarre l'API Rust (rechargée manuellement) et le serveur Vite, gère l'arrêt propre.
set -euo pipefail
UI_PORT="${NETSIFT_UI_PORT:-5173}"
API_PORT="${NETSIFT_API_PORT:-7878}"
TOKEN_FILE="$(mktemp)"
head -c 32 /dev/urandom | base64 | tr -d '/+=' > "$TOKEN_FILE"

cleanup() { kill "${API_PID:-}" "${UI_PID:-}" 2>/dev/null || true; rm -f "$TOKEN_FILE"; }
trap cleanup EXIT INT TERM

echo ">> Compilation et lancement de l'API (port $API_PORT)…"
# En dev on autorise 0.0.0.0 DANS le conteneur ; l'hôte ne publie que sur 127.0.0.1 (voir x.sh).
cargo run -p netsift-cli -- serve \
  --bind "0.0.0.0:${API_PORT}" \
  --token-file "$TOKEN_FILE" \
  --captures-root /captures \
  --data-dir .data &
API_PID=$!

# Attendre que l'API réponde.
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${API_PORT}/api/v1/health" >/dev/null 2>&1; then break; fi
  sleep 1
done

if [ ! -d ui/node_modules ]; then (cd ui && (npm ci || npm install)); fi

echo ">> Lancement de Vite (port $UI_PORT)…"
# Le proxy Vite injecte le jeton et pointe vers l'API (voir ui/vite.config.ts).
NETSIFT_API_URL="http://127.0.0.1:${API_PORT}" \
NETSIFT_API_TOKEN="$(cat "$TOKEN_FILE")" \
  npm --prefix ui run dev -- --host 0.0.0.0 --port "${UI_PORT}" --strictPort &
UI_PID=$!

wait -n "$API_PID" "$UI_PID"
