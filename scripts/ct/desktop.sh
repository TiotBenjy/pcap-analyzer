#!/usr/bin/env bash
# Exécuté DANS le conteneur par `./x.sh desktop [linux|windows]`.
# Le frontend est construit par `beforeBuildCommand` (apps/desktop/tauri.conf.json).
set -euo pipefail
TARGET="${1:-linux}"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
mkdir -p dist

# Base GeoIP embarquée (bundle.resources) : reprend celle de `./x.sh geoip` si le bundle n'en a
# pas ou si elle est plus récente (cp -p garde la date, pour la comparaison suivante).
GEOIP_SRC="${NETSIFT_DATA_DIR:-.data}/geoip/dbip-country-lite.mmdb"
GEOIP_DST="apps/desktop/resources/geoip/dbip-country-lite.mmdb"
if [ -f "$GEOIP_SRC" ] && { [ ! -f "$GEOIP_DST" ] || [ "$GEOIP_SRC" -nt "$GEOIP_DST" ]; }; then
  cp -pv "$GEOIP_SRC" "$GEOIP_DST"
fi
[ -f "$GEOIP_DST" ] || echo ">> Pas de base GeoIP (./x.sh geoip) : le bundle n'aura pas de pays."

case "$TARGET" in
  linux)
    echo ">> Build Tauri (Linux : AppImage + .deb)…"
    rm -f dist/*.AppImage dist/*.deb
    # linuxdeploy est lui-même une AppImage : sans FUSE dans le conteneur, on l'extrait à l'exécution.
    export APPIMAGE_EXTRACT_AND_RUN=1
    # Le bundler met AppRun, linuxdeploy et ses plugins dans `dirs::cache_dir()/tauri`
    # ($XDG_CACHE_HOME/tauri) et ne les télécharge que s'ils manquent. HOME est éphémère dans le
    # conteneur : on les garde dans le volume de cache.
    export XDG_CACHE_HOME=/cache/xdg
    mkdir -p "$XDG_CACHE_HOME"
    # GitHub répond parfois 503/504 sur ces téléchargements : jusqu'à 3 tentatives, seulement pour
    # un échec de téléchargement (la recompilation est incrémentale). Une erreur de build échoue.
    LOG="$(mktemp)"; trap 'rm -f "$LOG"' EXIT
    for attempt in 1 2 3; do
      if (cd apps/desktop && cargo tauri build --bundles appimage,deb) 2>&1 | tee "$LOG"; then
        break
      fi
      if [ "$attempt" -lt 3 ] && grep -qiE 'http status|failed to download' "$LOG"; then
        echo ">> Échec de téléchargement (tentative $attempt/3), nouvel essai dans 15 s…"
        sleep 15
      else
        exit 1
      fi
    done
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
