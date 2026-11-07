#!/usr/bin/env bash
# Version CI du téléchargement GeoIP, vers l'emplacement attendu par le bundle Tauri.
set -euo pipefail
DEST="apps/desktop/resources/geoip"; mkdir -p "$DEST"
YM="$(date +%Y-%m)"
URL="https://download.db-ip.com/free/dbip-country-lite-${YM}.mmdb.gz"
curl -fL --proto '=https' -o "$DEST/dbip-country-lite.mmdb.gz" "$URL"
gunzip -f "$DEST/dbip-country-lite.mmdb.gz"
echo "GeoIP: $DEST/dbip-country-lite.mmdb"
