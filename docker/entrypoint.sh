#!/usr/bin/env bash
# Prépare des caches inscriptibles quel que soit l'UID monté, puis exécute la commande.
set -euo pipefail

export CARGO_HOME="${CARGO_HOME:-/cache/cargo}"
export SCCACHE_DIR="${SCCACHE_DIR:-/cache/sccache}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/cache/target/root}"
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/usr/local/pw-browsers}"
# npm : cache dans le volume, pas dans le home (souvent non inscriptible avec --user).
export npm_config_cache="${npm_config_cache:-/cache/npm}"
# HOME hors du dépôt monté (/work) : sinon npm/cargo y écriraient leurs fichiers.
if [ -z "${HOME:-}" ] || [ "$HOME" = "/work" ] || [ "$HOME" = "/" ]; then export HOME=/tmp/home; fi
mkdir -p "$HOME" 2>/dev/null || true

mkdir -p "$CARGO_HOME" "$SCCACHE_DIR" "$CARGO_TARGET_DIR" "$npm_config_cache" 2>/dev/null || true

# Démarre sccache en serveur si disponible (ignore si indispo).
if command -v sccache >/dev/null 2>&1; then
  export RUSTC_WRAPPER=sccache
  sccache --start-server >/dev/null 2>&1 || true
fi

exec "$@"
