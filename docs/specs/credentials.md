# Credentials

Référence : `docs/reference/credentials.png`.

## But

Recenser, pour un audit défensif, les éléments d'authentification qui transitent en clair ou de façon
récupérable dans une capture — afin de démontrer quels protocoles exposent des secrets et de prioriser
leur remplacement (chiffrement, désactivation des protocoles hérités). C'est la fonction centrale des
outils forensiques réseau ; NetSift ne fait qu'observer une capture fournie, sans aucune action réseau.

## Modèle

Chaque protocole concerné émet un `Record::Credential` (l'onglet ne fait qu'agréger) :

| Source | Type | Contenu enregistré |
|---|---|---|
| HTTP Basic / Proxy-Auth | `http-basic` | identifiant et secret décodés (base64) |
| Formulaires HTTP | `http-form` | champs ressemblant à un couple identifiant/secret |
| FTP | `ftp` | USER / PASS |
| SMTP AUTH, POP3, IMAP | `mail` | mécanisme et éléments transmis |
| SNMP v1/v2c | `snmp` | community string et version |
| LDAP simple bind | `ldap` | DN et secret |
| Telnet | `telnet` | reconstitution de la saisie (phase 5) |
| NTLM (depuis SMB/HTTP) | `ntlm` | métadonnées (domaine, compte, station) et matériel de défi/réponse |
| Handshakes WiFi (phase 5) | `wifi-eapol` | éléments EAPOL capturés |

Champs communs : protocole, flux, source, destination, horodatage, identifiant (si présent),
état du secret (`plaintext` / `recoverable` / `metadata-only`), et, le cas échéant, un identifiant de mode
de récupération hors ligne (numéro de mode hashcat) pour les types qui le permettent — information d'inventaire,
NetSift ne réalise aucune récupération.

## Traitement des secrets (règles strictes)

- Tout secret est **masqué par défaut** dans l'UI (`SecretValue` : points, bouton Révéler, bouton Copier).
- Les secrets ne sont **jamais écrits dans les logs** ni envoyés nulle part (aucune sortie réseau).
- L'export (CSV, ou format pour outil de récupération hors ligne) est une action explicite par entrée ou par
  sélection, confirmée, et tracée dans un bandeau « contient des données sensibles ».
- Les blobs de handshake exportables sont comptés mais produits uniquement sur action explicite.

## Mise en page

1. Mini-graphe source -> protocole -> destination (comme la référence, mais libellés lisibles et agrégés),
   ou simple liste si peu d'entrées.
2. Quatre `StatCard` : secrets en clair, entrées récupérables hors ligne, exports de handshake disponibles,
   pagination.
3. Liste de cartes repliées : badge de protocole, source -> destination (`Endpoint`), identifiant (ou « indisponible »),
   état du secret (badge : clair = ambre, récupérable = neutre, métadonnées = gris). Carte dépliée : détail complet,
   `SecretValue` pour le secret, actions d'export.

## Critères d'acceptation

- Fixtures : un FTP USER/PASS, un HTTP Basic, une community SNMP -> trois entrées, secrets masqués par défaut.
- Aucun secret présent dans les fichiers de logs après un import (test qui scanne la sortie `tracing`).
- `./x.sh shots credentials` vert ; les captures ne montrent aucun secret en clair (valeurs masquées).
