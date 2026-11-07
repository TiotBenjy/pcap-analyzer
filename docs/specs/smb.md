# SMB

Référence : `docs/reference/smb.png`.

## But

Inventorier les informations d'hôtes exposées par le trafic NetBIOS/SMB d'un réseau (noms, domaines,
version d'OS, rôles annoncés) et recenser les échanges d'authentification observés. Objectif d'audit
défensif : savoir ce qu'une capture révèle d'un parc, au même titre que les outils forensiques établis.

## Données

Analyseur `smb_netbios` :
- NetBIOS Datagram (UDP 138) + mailslot `\\MAILSLOT\\BROWSE` : Host / Local Master / Domain Announcement
  -> `smb_announces` (IP, nom d'hôte, domaine ou destination NetBIOS, version d'OS annoncée -> libellé lisible
  via table de correspondance, rôles annoncés via les bits SV_TYPE_*, commentaire, horodatage).
- SMB1/SMB2/3 sur TCP 139/445 : négociation (dialecte retenu), Session Setup. Lorsqu'un échange d'authentification
  NTLM est présent, l'analyseur enregistre sa **présence** et les métadonnées non secrètes (domaine, nom de compte,
  nom de station, type de message), et émet un `Record::Credential` de type `ntlm` pour l'onglet Credentials, qui
  centralise le traitement des éléments sensibles (voir `specs/credentials.md`). La vue SMB elle-même n'affiche pas
  de secret.

API : `/smb/announces` (table), `/smb/stats` (répartition des OS annoncés), `/smb/auth` (liste des sessions
d'authentification observées avec métadonnées non secrètes, renvoi vers Credentials pour le détail).

## Mise en page

1. Graphique « OS annoncés » (donut) à partir des Host Announcements.
2. Deux onglets : « Annonces d'hôtes » (table : IP, nom annoncé, destination NetBIOS, OS, rôles en puces,
   commentaire) et « Authentifications » (table : client `Endpoint`, serveur `Endpoint`, protocole/dialecte,
   domaine, compte, station, type, horodatage ; lien vers Credentials).

## Améliorations par rapport à la référence

- Emoji et logos d'OS remplacés par du texte et des icônes lucide neutres.
- Séparation nette entre métadonnées (ici) et éléments sensibles (centralisés dans Credentials, masqués par défaut).

## Critères d'acceptation

- Fixture : une annonce d'hôte (nom, workgroup, version d'OS, rôles) -> ligne exacte dans « Annonces ».
- Fixture d'un échange d'authentification NTLM synthétique -> une entrée en « Authentifications » et un
  `Record::Credential` de type `ntlm` ; aucun secret affiché dans la vue SMB.
- `./x.sh shots smb` vert.
