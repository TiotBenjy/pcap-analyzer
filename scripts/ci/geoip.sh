#!/usr/bin/env bash
# Version CI du téléchargement GeoIP (DB-IP IP-to-Country Lite, CC BY 4.0), vers l'emplacement
# embarqué par le bundle Tauri (`bundle.resources`). Mois courant, ou mois précédent si celui du
# mois n'est pas encore publié. Échoue si aucune base valide n'est obtenue : une release ne part
# jamais sans base (ADR-012). Portable : Linux, macOS (date BSD) et Git Bash sous Windows.
set -euo pipefail
DEST="apps/desktop/resources/geoip"; mkdir -p "$DEST"
FINAL="$DEST/dbip-country-lite.mmdb"
TMP="$(mktemp -d "$DEST/.download.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# Mois précédent sans `date -d` (absent de la date BSD de macOS). 10# : "08" n'est pas octal.
YEAR="$(date -u +%Y)"; MONTH="$(date -u +%m)"
CURRENT="$(printf '%04d-%02d' "$((10#$YEAR))" "$((10#$MONTH))")"
if [ "$((10#$MONTH))" -eq 1 ]; then
  PREVIOUS="$(printf '%04d-12' "$((10#$YEAR - 1))")"
else
  PREVIOUS="$(printf '%04d-%02d' "$((10#$YEAR))" "$((10#$MONTH - 1))")"
fi

for YM in "$CURRENT" "$PREVIOUS"; do
  URL="https://download.db-ip.com/free/dbip-country-lite-${YM}.mmdb.gz"
  echo ">> Téléchargement $URL"
  if curl -fsSL --proto '=https' --retry 3 -o "$TMP/db.mmdb.gz" "$URL"; then
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
    mv -f "$TMP/db.mmdb" "$FINAL"
    echo "GeoIP: $FINAL"
    exit 0
  fi
done
echo "Échec du téléchargement de la base GeoIP ($CURRENT et $PREVIOUS)." >&2
exit 1
