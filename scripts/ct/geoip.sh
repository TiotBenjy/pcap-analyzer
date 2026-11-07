#!/usr/bin/env bash
# Télécharge la base GeoIP DB-IP IP-to-Country Lite (licence CC BY 4.0) du mois courant.
# Attribution requise, affichée dans « À propos » de l'application.
set -euo pipefail
DEST=".data/geoip"; mkdir -p "$DEST"
YM="$(date +%Y-%m)"
URL="https://download.db-ip.com/free/dbip-country-lite-${YM}.mmdb.gz"
echo ">> Téléchargement $URL"
if curl -fL --proto '=https' -o "$DEST/dbip-country-lite.mmdb.gz" "$URL"; then
  gunzip -f "$DEST/dbip-country-lite.mmdb.gz"
  echo ">> Base GeoIP : $DEST/dbip-country-lite.mmdb"
else
  echo "Echec du téléchargement (réseau ou mois indisponible). L'application fonctionne sans (pays inconnu)." >&2
  exit 1
fi
