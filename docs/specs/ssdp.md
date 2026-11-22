# SSDP

Tâche ROADMAP P5.5 (`feat/ssdp`, vague 5.A). Référence : `docs/reference/private/ssdp.png` (non publiée).

## Référence

La plateforme d'origine montre un graphe force (émetteurs, USN et types reliés par des arêtes
« SEARCH » / « NOTIFY ») illisible dès quelques dizaines d'hôtes : libellés superposés, couleurs sans
légende. Sous le graphe, une liste de messages (source, flèche, destination, badge de méthode) dont
chaque ligne se déplie sur le message brut en police à chasse fixe. On reprend les **fonctionnalités**
(qui annonce quoi, qui cherche quoi, quels appareils UPnP, message brut), pas le graphe.

## But

Répondre à « quels appareils UPnP se signalent sur ce réseau, avec quel logiciel, où publient-ils leur
description, et qui les cherche ? ». SSDP (Simple Service Discovery Protocol, UPnP Device
Architecture 1.1 / 2.0) révèle passivement l'inventaire des box, télévisions, imprimantes, NAS et
passerelles d'un réseau local, et les clients qui les découvrent.

## Données

### Analyseur `ssdp` (`crates/netsift-analyze/src/ssdp/`)

- Datagrammes UDP dont le port source **ou** destination est 1900 (multicast `239.255.255.250`,
  `ff02::c`, `ff05::c`, ou unicast pour les réponses). Une réponse émise depuis un autre port que 1900
  vers un port éphémère n'est pas reconnue (rare ; documenté comme limite).
- Parseur `ssdp::parser` (pur, sans I/O, fuzzé) : HTTPU (HTTP/1.1 sur UDP) lu avec `httparse`, en
  requête puis en réponse, en tolérant les écarts fréquents du terrain : fin de lignes en LF seul,
  dernière ligne vide absente (datagramme tronqué), espaces après le nom d'en-tête, lignes d'en-tête
  invalides ignorées. Au plus 64 en-têtes ; au-delà, ou si la première ligne n'est pas HTTP, le
  message est `invalid`.
- Types de message (`kind`) :
  - `notify` : `NOTIFY * HTTP/1.1`, avec `NTS` = `ssdp:alive`, `ssdp:byebye` ou `ssdp:update`
    (colonne `nts` : `alive`, `byebye`, `update`, sinon la valeur bornée telle quelle) ;
  - `search` : `M-SEARCH * HTTP/1.1` ;
  - `response` : `HTTP/1.1 <code>` (code conservé, 200 attendu) ;
  - `invalid` : tout autre contenu (autre méthode, binaire, première ligne illisible).
- Champs extraits (chacun borné à 512 octets, texte nettoyé) : cible `NT` (notify) ou `ST` (search,
  response) dans `target`, `USN`, identifiant d'appareil `uuid` (préfixe `uuid:...` de l'USN, en
  minuscules, sinon du `NT`), `SERVER`, `USER-AGENT`, `LOCATION`, `max-age` de `CACHE-CONTROL`, `MX`.
- Message brut : les 2 048 premiers octets du datagramme, décodés en UTF-8 avec remplacement, fins de
  ligne normalisées en LF, caractères de contrôle autres que tabulation et LF remplacés par U+FFFD ;
  drapeau `raw_truncated` et taille d'origine `size`. Jamais interprété : l'UI l'affiche comme texte.
- `LOCATION` est une URL **extraite**, jamais suivie ni chargée (aucun appel réseau, CLAUDE.md) :
  affichée en texte avec un bouton de copie, sans lien.

### Tables (migration `1200_ssdp.sql`, plage réservée 1200-1299)

- `ssdp_messages` : un enregistrement par datagramme (`ts`, extrémités, `multicast`, `kind`, `nts`,
  `status`, `target`, `usn`, `uuid`, `server`, `user_agent`, `location`, `max_age`, `mx`, `size`,
  `raw`, `raw_truncated`, et `software` pour le classement des logiciels).
- `ssdp_devices` : appareils repliés par (`uuid`, adresse émettrice), écrits par le même upsert que le
  message : compteurs `message_count`, `alive_count`, `byebye_count`, `response_count`, `first_ts`,
  `last_ts`, et les dernières valeurs non vides de `SERVER`, `LOCATION` et du type d'appareil
  (`urn:...:device:...` vu en `NT` / `ST`). La règle de fusion est commutative (compteurs additifs,
  min / max des horodatages, valeur la plus récente gagnante, départage par la valeur) : le résultat ne
  dépend ni de l'ordre ni du nombre de shards. Un appareil qui change d'adresse donne deux lignes.
- Index (différés pendant l'import, ADR-023) : `(ts)` pour la liste, `(kind, ts)` et
  `(kind, nts, ts)` pour le filtre de type et les compteurs, `(target, ts)`, `(software, ts)`
  (colonne `software` = `SERVER`, sinon `USER-AGENT`), `(src_ip, ts)` pour les classements, `(uuid, src_ip, ts)` et `(uuid, src_ip, target)` pour le détail
  d'un appareil ; `ssdp_devices (message_count)` pour l'ordre de la liste et `(first_ts, last_ts)` pour
  la plage.

### API (`crates/netsift-api/src/ssdp.rs`)

| Méthode | Route | Réponse |
|---|---|---|
| GET | `/sessions/{id}/ssdp/stats` | `SsdpStats` : compteurs par type (`notify`, `alive`, `byebye`, `update`, `search`, `response`, `invalid`), `devices`, `senders`, top 10 des cibles (`NT` / `ST`), des logiciels (`SERVER`, sinon `USER-AGENT`) et des émetteurs (`Endpoint`) |
| GET | `/sessions/{id}/ssdp/devices?q=&limit=&cursor=` | `Page<SsdpDeviceInfo>` : appareils par nombre de messages décroissant (keyset `(message_count, rowid)`), avec leurs cibles distinctes (au plus 16) ; `q` cherche dans l'UUID, l'adresse, le type, `SERVER`, `LOCATION` |
| GET | `/sessions/{id}/ssdp/messages?kind=&nts=&q=&uuid=&src=&target=&limit=&cursor=` | `Page<SsdpMessageInfo>` : messages par horodatage croissant (keyset `(ts, id)`), message brut compris ; `q` cherche dans la cible, l'USN, `SERVER`, `USER-AGENT`, `LOCATION` |

Valeurs invalides de `kind` / `nts` / `src` : 400 problem+json. `total_estimate` est le compte exact
des lignes filtrées.

### Compteur de module

`MODULES` : `("ssdp", "ssdp_messages")` (nombre de messages) ; sous plage, `ModuleRows::Ssdp` =
messages dont `ts` est dans la plage (`scope: "range"`).

## Filtre temporel (ADR-030)

La vue est dans `timeFilterViews.ts` dès sa création ; ses trois routes passent par l'extracteur
`ApiRange` (`crates/netsift-api/src/range.rs`) et la normalisation commune (plage couvrant la session
-> réponse identique à celle sans plage).

| Route | Règle |
|---|---|
| `/ssdp/messages` | *ponctuel(`ts`)* |
| `/ssdp/stats` | compteurs, cibles, logiciels et émetteurs sur les messages *ponctuel(`ts`)* ; `devices` = appareils qui *chevauchent(`first_ts`, `last_ts`)* |
| `/ssdp/devices` | appareils qui *chevauchent(`first_ts`, `last_ts`)* ; compteurs et cibles **de la session** |

Choix pour les appareils repliés : règle commune « chevauche la plage, compteurs de session », avec la
mention « session entière » sous l'en-tête de la colonne Messages (et dans la carte mobile) quand une
plage est active. Recalculer les appareils sur la plage (regroupement des messages par `uuid`) aurait
imposé un keyset sur un agrégat calculé à la lecture et un tri sans index ; la liste des messages d'un
appareil, elle, suit la plage (bouton « Voir les messages » du détail). Les agrégats lisent des index
couvrants terminés par `ts` (`PointSql`, choix du plan selon la part de la table dans la plage).

## Mise en page

Ordre des blocs (une colonne sous 768 px) :

1. En-tête : titre « SSDP », sous-titre (nom de session), compteur de messages.
2. Bandeau de chiffres (`StatCard`, 2 colonnes sous `sm`, 3 jusqu'à `xl`, 6 au-delà) : Messages,
   NOTIFY (indice « alive / byebye »), M-SEARCH, Réponses, Appareils, Émetteurs.
3. Trois cartes de classement (`BarList`, grille auto-fit de 320 px minimum) : « Types annoncés et
   recherchés » (cibles `NT` / `ST` en mono, troncature au milieu), « Logiciels » (`SERVER` /
   `USER-AGENT`), « Émetteurs » (adresse, drapeau). Un clic sur une ligne de cible ou d'émetteur filtre
   la liste des messages (pastille de filtre retirable).
4. Carte « Appareils » : bande `filters` avec `SearchInput` ; liste dépliable (rangées : type
   d'appareil court, `Endpoint`, logiciel, messages, dernière vue ; cartes empilées sous `md`). Détail
   déplié : UUID (copie), type complet, `LOCATION` en texte mono avec copie (jamais un lien), logiciel,
   première et dernière vue (`Timestamp`), compteurs alive / byebye / réponses, cibles annoncées en
   pastilles, bouton « Voir les messages » (filtre la liste des messages sur l'appareil et y fait
   défiler).
5. Carte « Messages » : bande `filters` avec `SearchInput`, contrôle segmenté du type (Tous, NOTIFY,
   M-SEARCH, Réponses, Invalides ; sous 640 px, une liste déroulante), pastilles des filtres actifs
   (appareil, émetteur, cible). Liste virtualisée et paginée (`ExpandableList`, 200 lignes par page) :
   heure, badge de type (NOTIFY alive / byebye, M-SEARCH, 200, Invalide), source -> destination
   (`Endpoint`, port grisé), cible en mono tronquée. Détail déplié : message brut dans un bloc à chasse
   fixe, défilable horizontalement à l'intérieur du bloc, échappé (texte React, jamais de HTML), avec
   bouton de copie et la mention « tronqué à 2 048 octets » le cas échéant.

États : chargement (squelettes), erreur (réessayer), session en import ou en échec (`SessionGate`),
aucune donnée SSDP (« Aucun message SSDP »), plage vide (état vide commun « Rien
dans la plage » avec « Effacer la plage »).

## Améliorations par rapport à la référence

- Graphe illisible remplacé par un tableau groupé par appareil et trois classements. Le graphe
  « facultatif borné » de la ROADMAP n'est **pas** livré dans cette tâche : les classements et le
  détail par appareil répondent aux mêmes questions ; à reprendre s'il est demandé (suivi).
- Type de message en badge texte sobre, sans couleurs arbitraires ; source et destination en
  `Endpoint` (drapeau, nom résolu en infobulle).
- Bouton flottant « To Details » supprimé (les blocs se suivent, le détail d'appareil renvoie aux
  messages).
- `LOCATION` jamais chargée ni rendue cliquable ; message brut toujours affiché en texte.

## Critères d'acceptation

- Fixture synthétique `netsift_fixtures::ssdp` : NOTIFY `ssdp:alive` et `ssdp:byebye`, M-SEARCH
  (IPv4 et IPv6), réponses 200 OK unicast, quatre appareils et plusieurs USN par appareil, un appareil
  IPv6, un message invalide (binaire) et un message aux en-têtes surdimensionnés (bornes).
- Tests du parseur : messages valides des trois types, écarts tolérés, malformés (binaire, première
  ligne invalide, trop d'en-têtes), bornes (champ et message brut tronqués, caractères de contrôle).
- Tests de l'analyseur sur la fixture (snapshot `insta` des enregistrements), du store (repli des
  appareils commutatif, pages, plage) et de l'API (compteurs égaux entre liste, `stats` et module,
  filtres, validation, plage ponctuelle et chevauchement, plage couvrant la session identique à sans
  plage, pages keyset sans doublon ni trou, snapshot `insta`).
- UI (Vitest) : rendu des blocs, filtre de type, dépliage du message brut (texte échappé), pastilles
  de filtre, mention « session entière » sous plage.
- `./x.sh shots ssdp all`, `ssdp-range` (plage active) et `ssdp-raw` (premier message déplié) verts à
  375, 768, 1280 et 1920 px, en `en` et `fr`, sans débordement ni chevauchement.
- Moins de 300 ms par requête (index couvrants ; mesure sur une session synthétique volumineuse).

## Notes d'implémentation

- Analyseur : `crates/netsift-analyze/src/ssdp/` (`parser.rs` pur et fuzzé par la cible `udp_services`,
  `analyzer.rs` sans état) ; store : `crates/netsift-store/src/ssdp.rs` (upsert commutatif des appareils
  avec un horodatage par valeur texte) ; API : `crates/netsift-api/src/ssdp.rs` ; UI :
  `ui/src/views/ssdp/` (listes dépliables de `views/http/ExpandableList`).
- Fixture : `netsift_fixtures::ssdp` (`ssdp_showcase`, `ssdp_round`), aussi ajoutée à la session de
  démonstration (vitrine puis annonces toutes les 10 s) pour les captures.
- Mesure (`ssdp::tests::timings`, ignoré, mode release, 500 000 messages de 2 000 appareils, machine de
  développement) : `/stats` 182 ms sur la session, 8 ms sur 1 h, 194 ms sur la moitié de la session ;
  page de messages 2 à 13 ms ; filtre de type avec recherche 72 ms au pire ; page d'appareils avec leurs
  cibles 11 ms. Chaque agrégat lit un index couvrant (`stats_queries_read_indexes_only`).
- Limite : une réponse émise depuis un port autre que 1900 vers un port éphémère n'est pas vue.
