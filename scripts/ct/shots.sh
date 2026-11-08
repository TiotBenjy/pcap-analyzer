#!/usr/bin/env bash
# Exécuté DANS le conteneur par `./x.sh shots [vue]` (et en CI par scripts/ci/shots.sh).
# Démarre l'API en lecture seule, construit l'UI, la sert avec `vite preview` (dont le proxy
# ajoute le jeton), puis Playwright capture chaque vue en 375/768/1280/1920, clair et sombre,
# et applique les assertions anti-débordement et anti-chevauchement de docs/UI_GUIDELINES.md.
# Termine par le test de fumée desktop (WebKit + Chromium, globals de Tauri). `desktop` comme
# vue ne lance que ce test.
set -euo pipefail
VIEW="${1:-all}"
API_PORT="${NETSIFT_API_PORT:-7988}"
DATA_DIR=".artifacts/shots-data"
OUT=".artifacts/screens"
TOKEN_FILE="$(mktemp)"
head -c 32 /dev/urandom | base64 | tr -d '/+=' > "$TOKEN_FILE"
mkdir -p "$OUT" "$DATA_DIR"
if [ "$VIEW" = "all" ]; then rm -f "$OUT"/*.png; elif [ "$VIEW" != "desktop" ]; then rm -f "$OUT/$VIEW"-*.png; fi

cleanup() { kill "${API_PID:-}" 2>/dev/null || true; rm -f "$TOKEN_FILE"; }
trap cleanup EXIT INT TERM

echo ">> Compilation de l'API (feature demo)…"
cargo build -q -p netsift-cli --features demo
NETSIFT_BIN="${CARGO_TARGET_DIR:-target}/debug/netsift"

# Données de démonstration : ~50 chunks dumpcap synthétiques (un fichier manquant, un trou
# temporel) et un fichier seul, importés en deux sessions `ready`, recréées à chaque run.
echo ">> Sessions de démonstration…"
"$NETSIFT_BIN" demo-session --data-dir "$DATA_DIR" --force

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

export NETSIFT_API_URL="http://127.0.0.1:${API_PORT}"
NETSIFT_API_TOKEN="$(cat "$TOKEN_FILE")"
export NETSIFT_API_TOKEN

if [ "$VIEW" != "desktop" ]; then
  echo ">> Captures et vérifications visuelles (vue : $VIEW)…"
  SHOT_VIEW="$VIEW" npx playwright test --project=chromium tests/visual/shots.spec.ts
fi

# Test de fumée desktop (ui/tests/desktop) : WebKit et Chromium avec les globals de Tauri
# (Object.prototype gelé, faux pont IPC). Lancé quelle que soit la vue demandée, car il couvre les
# chemins propres au desktop (pont Tauri, dialogue natif, chunk des graphiques) ; seul avec
# `./x.sh shots desktop`.
# shellcheck source=scripts/ct/webkit.sh
source ../scripts/ct/webkit.sh
echo ">> Test de fumée desktop (WebKit, Chromium)…"
npx playwright test --project=desktop-webkit --project=desktop-chromium

echo ">> Captures dans $OUT"
