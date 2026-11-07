#!/usr/bin/env bash
# Exécuté DANS le conteneur par `./x.sh desktop [linux|windows]`.
set -euo pipefail
TARGET="${1:-linux}"
mkdir -p dist

if [ ! -d ui/node_modules ]; then (cd ui && (npm ci || npm install)); fi

case "$TARGET" in
  linux)
    echo ">> Build Tauri (Linux : AppImage + .deb)…"
    cargo tauri build
    # tauri place les bundles sous target/release/bundle/** ; on les copie dans dist/.
    find "${CARGO_TARGET_DIR:-target}" -path '*/release/bundle/*' \
      \( -name '*.AppImage' -o -name '*.deb' \) -exec cp -v {} dist/ \;
    ;;
  windows)
    echo ">> Build Windows via cargo-xwin (expérimental ; le build de référence reste la CI)…"
    # Frontend d'abord, puis binaire Windows. Le bundling NSIS/MSI complet se fait en CI.
    (cd ui && VITE_BUILD=1 npm run build)
    cargo xwin build --release --target x86_64-pc-windows-msvc -p netsift-desktop
    find "${CARGO_TARGET_DIR:-target}" -path '*x86_64-pc-windows-msvc/release/*' -name '*.exe' \
      -maxdepth 6 -exec cp -v {} dist/ \;
    echo ">> .exe copié dans dist/. Pour les installateurs signés, utiliser release.yml (windows-latest)."
    ;;
  *) echo "cible inconnue : $TARGET" >&2; exit 2 ;;
esac
echo ">> Artefacts dans dist/"
