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
