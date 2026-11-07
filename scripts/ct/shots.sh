#!/usr/bin/env bash
# Exécuté DANS le conteneur par `./x.sh shots [vue]` (et en CI par scripts/ci/shots.sh).
# Démarre l'API en lecture seule, construit l'UI, la sert avec `vite preview` (dont le proxy
# ajoute le jeton), puis Playwright capture chaque vue en 375/768/1280/1920, clair et sombre,
# et applique les assertions anti-débordement et anti-chevauchement de docs/UI_GUIDELINES.md.
set -euo pipefail
VIEW="${1:-all}"
API_PORT="${NETSIFT_API_PORT:-7988}"
DATA_DIR=".artifacts/shots-data"
OUT=".artifacts/screens"
TOKEN_FILE="$(mktemp)"
head -c 32 /dev/urandom | base64 | tr -d '/+=' > "$TOKEN_FILE"
mkdir -p "$OUT" "$DATA_DIR"
if [ "$VIEW" = "all" ]; then rm -f "$OUT"/*.png; else rm -f "$OUT/$VIEW"-*.png; fi

cleanup() { kill "${API_PID:-}" 2>/dev/null || true; rm -f "$TOKEN_FILE"; }
trap cleanup EXIT INT TERM

# TODO(P2): générer une session de fixtures (`netsift demo-session`) une fois netsift-store prêt.

echo ">> Compilation de l'API…"
cargo build -q -p netsift-cli
NETSIFT_BIN="${CARGO_TARGET_DIR:-target}/debug/netsift"

echo ">> API de prévisualisation (port $API_PORT, lecture seule)…"
"$NETSIFT_BIN" serve --bind "127.0.0.1:${API_PORT}" --token-file "$TOKEN_FILE" \
  --data-dir "$DATA_DIR" --read-only &
API_PID=$!
for _ in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:${API_PORT}/api/v1/health" >/dev/null 2>&1 && break
  kill -0 "$API_PID" 2>/dev/null || { echo "L'API s'est arrêtée au démarrage." >&2; exit 1; }
  sleep 0.5
done
curl -fsS "http://127.0.0.1:${API_PORT}/api/v1/health" >/dev/null || { echo "API injoignable." >&2; exit 1; }

echo ">> Build de l'UI…"
cd ui
if [ ! -d node_modules ]; then npm ci; fi
npm run -s build

echo ">> Captures et vérifications visuelles (vue : $VIEW)…"
NETSIFT_API_URL="http://127.0.0.1:${API_PORT}" \
NETSIFT_API_TOKEN="$(cat "$TOKEN_FILE")" \
SHOT_VIEW="$VIEW" \
  npx playwright test tests/visual/shots.spec.ts

echo ">> Captures dans $OUT"
