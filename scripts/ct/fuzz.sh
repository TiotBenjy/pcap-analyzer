#!/usr/bin/env bash
# cargo-fuzz dans le conteneur (nécessite une toolchain nightly, installée à la demande).
set -euo pipefail
TARGET="${1:-}"; DURATION="${2:-60}"
if ! rustup toolchain list | grep -q nightly; then
  echo ">> Installation de la toolchain nightly (fuzzing)…"; rustup toolchain install nightly --profile minimal
fi
command -v cargo-fuzz >/dev/null 2>&1 || cargo binstall -y cargo-fuzz || cargo +nightly install cargo-fuzz
if [ -z "$TARGET" ]; then echo "Cibles disponibles :"; cargo +nightly fuzz list; exit 0; fi
echo ">> Fuzzing $TARGET pendant ${DURATION}s"
cargo +nightly fuzz run "$TARGET" -- -max_total_time="$DURATION"
