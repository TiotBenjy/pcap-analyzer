#!/usr/bin/env bash
# Version CI de `./x.sh shots` : s'exécute directement sur le runner (toolchain déjà installée),
# sans conteneur. Génère une session de fixtures, sert l'API, build l'UI, lance les tests visuels.
set -euo pipefail
API_PORT=7988
TOKEN="$(head -c 24 /dev/urandom | base64 | tr -d '/+=')"
mkdir -p .artifacts/screens

cleanup() { kill "${API_PID:-}" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

cargo run -p netsift-cli -- demo-session --data-dir .artifacts/demo-data --force
cargo run -p netsift-cli -- serve --bind "127.0.0.1:${API_PORT}" --token "$TOKEN" \
  --data-dir .artifacts/demo-data --read-only &
API_PID=$!
for _ in $(seq 1 60); do curl -fsS "http://127.0.0.1:${API_PORT}/api/v1/health" >/dev/null 2>&1 && break; sleep 1; done

( cd ui
  VITE_API_URL="http://127.0.0.1:${API_PORT}" VITE_API_TOKEN="$TOKEN" npm run build
  NETSIFT_API_PORT="$API_PORT" NETSIFT_API_TOKEN="$TOKEN" SHOT_VIEW="all" \
    npx playwright test tests/visual/shots.spec.ts )
