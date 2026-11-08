#!/usr/bin/env bash
# Exécuté DANS le conteneur par `./x.sh desktop [linux|windows]`.
# Le frontend est construit par `beforeBuildCommand` (apps/desktop/tauri.conf.json).
set -euo pipefail
TARGET="${1:-linux}"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
mkdir -p dist

# Base GeoIP embarquée (bundle.resources) : reprend celle de `./x.sh geoip` si le bundle n'en a pas.
GEOIP_SRC="${NETSIFT_DATA_DIR:-.data}/geoip/dbip-country-lite.mmdb"
GEOIP_DST="apps/desktop/resources/geoip/dbip-country-lite.mmdb"
if [ ! -f "$GEOIP_DST" ] && [ -f "$GEOIP_SRC" ]; then
  cp -v "$GEOIP_SRC" "$GEOIP_DST"
fi
[ -f "$GEOIP_DST" ] || echo ">> Pas de base GeoIP (./x.sh geoip) : le bundle n'aura pas de pays."

case "$TARGET" in
  linux)
    echo ">> Build Tauri (Linux : AppImage + .deb)…"
    rm -f dist/*.AppImage dist/*.deb
    # linuxdeploy est lui-même une AppImage : sans FUSE dans le conteneur, on l'extrait à l'exécution.
    export APPIMAGE_EXTRACT_AND_RUN=1
    (cd apps/desktop && cargo tauri build --bundles appimage,deb)
    find "$TARGET_DIR/release/bundle" \( -name '*.AppImage' -o -name '*.deb' \) -exec cp -v {} dist/ \;
    ;;
  windows)
    echo ">> Build Windows via cargo-xwin (expérimental ; le build de référence reste la CI)…"
    (cd ui && npm ci && npm run build)
    cargo xwin build --release --target x86_64-pc-windows-msvc -p netsift-desktop
    find "$TARGET_DIR/x86_64-pc-windows-msvc/release" -maxdepth 1 -name '*.exe' -exec cp -v {} dist/ \;
    echo ">> .exe copié dans dist/. Pour les installateurs signés, utiliser release.yml (windows-latest)."
    ;;
  *) echo "cible inconnue : $TARGET" >&2; exit 2 ;;
esac
echo ">> Artefacts dans dist/ :"
ls -lh dist/
