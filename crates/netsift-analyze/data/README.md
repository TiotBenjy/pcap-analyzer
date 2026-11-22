# Données embarquées de `netsift-analyze`

## `iana-services.csv`

Noms de services IANA des ports TCP et UDP, utilisés par l'onglet Open Ports (colonne « service IANA »)
et embarqués dans le binaire (`include_str!`, module `services`). Aucun accès réseau à l'exécution.

- Source : registre IANA « Service Name and Transport Protocol Port Number Registry »,
  <https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv>.
- Licence : domaine public, dédicace CC0 1.0 (déclaration conjointe IANA / IETF du 10 novembre 2021,
  <https://www.iana.org/help/licensing-terms>). Compatible avec `deny.toml`.
- Contenu : seules les attributions TCP et UDP portant un nom de service sont gardées, le premier nom par
  couple (port, transport) ; les plages attribuées de moins de 128 ports (x11 6000-6063...) sont développées.
- Format : `port,transports,nom` avec `transports` = `b` (TCP et UDP, même nom), `t` (TCP seul) ou
  `u` (UDP seul). Les lignes `#` sont des commentaires (source, date de récupération, licence).

### Régénération

Sur l'hôte (Python 3, bibliothèque standard uniquement), le fichier téléchargé dans un dossier vide à part :

```
mkdir -p /tmp/iana
curl -fsSLo /tmp/iana/services.csv \
  https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv
python3 -I scripts/gen-iana-services.py /tmp/iana/services.csv \
  crates/netsift-analyze/data/iana-services.csv
./x.sh test -p netsift-analyze services
```

Puis committer le fichier régénéré (`chore(analyze): refresh the IANA service table`).

## `ieee-oui.tsv`

Constructeurs des préfixes d'adresses MAC, utilisés par l'onglet Ethernet (colonne « constructeur », barres
des constructeurs) et embarqués dans le binaire (`include_str!`, module `oui`). Aucun accès réseau à
l'exécution. Décision et conditions de réutilisation : ADR-031.

- Source : listes publiques du registre IEEE (IEEE Registration Authority,
  <https://standards.ieee.org/products-programs/regauth/>) : MA-L (préfixes de 24 bits,
  <https://standards-oui.ieee.org/oui/oui.csv>), MA-M (28 bits, `oui28/mam.csv`), MA-S (36 bits,
  `oui36/oui36.csv`) et l'ancien registre IAB (36 bits, `iab/iab.csv`).
- Conditions : l'IEEE ne revendique aucun droit d'auteur sur ces listes et n'en restreint pas la
  diffusion ; il recommande seulement de les obtenir chez lui et de les mettre à jour régulièrement
  (déclaration reprise par le paquet Debian `ieee-data`, fichier `debian/copyright`). Ce sont des faits
  (préfixe attribué, nom de l'organisation). Aucune base GPL (fichier `manuf` de Wireshark, etc.) n'est utilisée.
- Contenu : seuls le préfixe et le nom de l'organisation sont gardés, jamais l'adresse postale ; espaces
  normalisés, caractères de contrôle retirés, noms bornés à 128 caractères, une entrée mal encodée de la
  source (UTF-8 lu comme Latin-1) réparée ; un préfixe attribué deux fois (anciens blocs MA-L) garde les deux
  noms séparés par ` / `. Les entrées « Private » (titulaire non publié) sont gardées.
- Format : `préfixe<TAB>organisation`, le préfixe en 6 (MA-L), 7 (MA-M) ou 9 (MA-S, IAB) chiffres
  hexadécimaux majuscules. Les lignes `#` sont des commentaires (sources, date de récupération, conditions).
  Environ 59 000 entrées, 1,8 Mo.

### Régénération

Sur l'hôte (Python 3, bibliothèque standard uniquement), les fichiers téléchargés dans un dossier vide à part.
Le serveur de l'IEEE refuse certains `User-Agent` (réponse 418) : `curl` sans option passe ; à défaut,
enregistrer les quatre fichiers depuis la page « Download Public Listing » du registre.

```
mkdir -p /tmp/ieee-oui && cd /tmp/ieee-oui
curl -fsSLO https://standards-oui.ieee.org/oui/oui.csv
curl -fsSLO https://standards-oui.ieee.org/oui28/mam.csv
curl -fsSLO https://standards-oui.ieee.org/oui36/oui36.csv
curl -fsSLO https://standards-oui.ieee.org/iab/iab.csv
cd - && python3 -I scripts/gen-ieee-oui.py /tmp/ieee-oui crates/netsift-analyze/data/ieee-oui.tsv
./x.sh test -p netsift-analyze oui
```

Puis committer le fichier régénéré (`chore(analyze): refresh the IEEE OUI table`), par exemple avant
chaque release. Les sessions déjà importées gardent les constructeurs de leur import.
