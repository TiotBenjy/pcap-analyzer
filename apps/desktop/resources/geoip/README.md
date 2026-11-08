# Base GeoIP embarquée

Ce dossier est copié dans le bundle (`bundle.resources` de `tauri.conf.json`, cible `geoip/`).
Il doit contenir `dbip-country-lite.mmdb` (DB-IP IP to Country Lite, licence CC BY 4.0) au moment
du build :

- en local, `./x.sh geoip` puis `./x.sh desktop` (qui copie `.data/geoip/dbip-country-lite.mmdb` ici) ;
- en CI, `scripts/ci/geoip.sh`.

Le fichier `.mmdb` n'est jamais commité (`.gitignore`). Sans lui, l'application fonctionne et les pays
restent inconnus ; « Paramètres > À propos » indique l'état de la base. Une base placée dans
`<données>/NetSift/geoip/` est prioritaire sur celle du bundle (mise à jour sans réinstaller).
