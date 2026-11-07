#!/usr/bin/env bash
# Exécuté DANS le conteneur par `./x.sh shots [vue]`.
# Construit l'UI, démarre l'API sur une session de fixtures, lance Playwright qui capture
# chaque vue en 375/768/1280/1920, clair et sombre, et applique les assertions anti-débordement
# et anti-chevauchement définies dans docs/UI_GUIDELINES.md.
set -euo pipefail
VIEW="${1:-all}"
API_PORT="${NETSIFT_API_PORT:-7988}"
TOKEN="$(head -c 24 /dev/urandom | base64 | tr -d '/+=')"
OUT=".artifacts/screens"
mkdir -p "$OUT"

cleanup() { kill "${API_PID:-}" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

echo ">> Génération d'une session de fixtures…"
cargo run -p netsift-cli -- demo-session --data-dir .artifacts/demo-data --force

echo ">> API de prévisualisation (port $API_PORT)…"
cargo run -p netsift-cli -- serve --bind "127.0.0.1:${API_PORT}" \
  --token "$TOKEN" --data-dir .artifacts/demo-data --read-only &
API_PID=$!
for _ in $(seq 1 60); do curl -fsS "http://127.0.0.1:${API_PORT}/api/v1/health" >/dev/null 2>&1 && break; sleep 1; done

echo ">> Build de l'UI…"
(cd ui && (npm ci || npm install) && \
  VITE_API_URL="http://127.0.0.1:${API_PORT}" VITE_API_TOKEN="$TOKEN" npm run build)

echo ">> Captures et vérifications visuelles…"
(cd ui && NETSIFT_API_PORT="$API_PORT" NETSIFT_API_TOKEN="$TOKEN" SHOT_VIEW="$VIEW" \
  npx playwright test tests/visual/shots.spec.ts)

echo ">> Captures dans $OUT"
