#!/usr/bin/env bash
# Télécharge la base GeoIP DB-IP IP-to-Country Lite (licence CC BY 4.0) du mois courant,
# ou du mois précédent si celle du mois n'est pas encore publiée.
# Attribution requise, affichée dans « À propos » de l'application.
# Destination : <data_dir>/geoip/dbip-country-lite.mmdb, l'emplacement par défaut lu par
# l'import (`netsift_geo::default_path`) ; data_dir = .data en dev (NETSIFT_DATA_DIR pour changer).
set -euo pipefail
DEST="${NETSIFT_DATA_DIR:-.data}/geoip"; mkdir -p "$DEST"
FINAL="$DEST/dbip-country-lite.mmdb"
TMP="$(mktemp -d "$DEST/.download.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

for YM in "$(date +%Y-%m)" "$(date -d "$(date +%Y-%m-15) -1 month" +%Y-%m)"; do
  URL="https://download.db-ip.com/free/dbip-country-lite-${YM}.mmdb.gz"
  echo ">> Téléchargement $URL"
  if curl -fL --proto '=https' -o "$TMP/db.mmdb.gz" "$URL"; then
    gunzip -f "$TMP/db.mmdb.gz"
    if [ ! -s "$TMP/db.mmdb" ]; then
      echo "Fichier vide après décompression." >&2
      exit 1
    fi
    # Marqueur de métadonnées MaxMind DB : écarte une page d'erreur ou un fichier tronqué.
    if ! LC_ALL=C grep -qaF "$(printf '\xab\xcd\xefMaxMind.com')" "$TMP/db.mmdb"; then
      echo "Fichier téléchargé invalide (marqueur mmdb absent)." >&2
      exit 1
    fi
    # Remplacement atomique : un import en cours ne lit jamais un fichier partiel.
    mv -f "$TMP/db.mmdb" "$FINAL"
    echo ">> Base GeoIP : $FINAL"
    exit 0
  fi
done
echo "Echec du téléchargement (réseau ou mois indisponible). L'application fonctionne sans (pays inconnu)." >&2
exit 1
