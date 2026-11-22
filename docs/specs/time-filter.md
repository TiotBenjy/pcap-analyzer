# Filtre temporel global

Tâche ROADMAP P5.2 (suivi de P4.2 : « zoom avec refetch » de l'Overview). Décision transverse : ADR-030.
Découpage : P5.2a (cette branche) puis P5.2b (vues agrégées), voir « Découpage ».

## Référence

Aucune capture de référence : la plateforme d'origine n'a pas de filtre temporel transverse. La
disposition ci-dessous est une proposition (section « Mise en page »).

## But

Répondre à « que s'est-il passé entre 14:03 et 14:20 ? » dans toutes les vues : la plage choisie dans la
Vue d'ensemble (zoom du graphique de trafic ou saisie) restreint chaque vue d'analyse, ses listes et ses
statistiques, reste visible hors de l'Overview, se partage par l'URL et s'efface en un clic.

## Convention (API)

### Paramètres

- Toute route de données d'une session filtrée (lot a ou b dans « Sémantique par route ») accepte `from_us` et `to_us` : entiers
  signés, microsecondes depuis l'époque Unix (UTC), **bornes incluses** à la microseconde, comme
  `timeseries` et la plage de Save PCAP (`export-pcap.md`). Chacun est facultatif : borne absente = début
  (ou fin) de la session.
- En interne (stockage en `i64` ns, `ARCHITECTURE.md`) la plage devient l'intervalle semi-ouvert
  `R = [F, T)` avec `F = from_us * 1000` et `T = (to_us + 1) * 1000` : un horodatage `t` en ns est dans la
  plage si `F <= t < T`. Aucun arrondi à la seconde, sauf pour les volumes lus dans `timeseries`
  (seaux d'une seconde, voir `/summary`).
- Type commun : `netsift_store::TimeRange { from_ns, to_ns }` (semi-ouvert), avec deux fragments de
  [`Conditions`] constants : `point(col)` (`col >= ? AND col < ?`) et `overlap(first, last)`
  (`first < ? AND last >= ?`), plus le cas particulier des flux (« Index »). Côté API, un extracteur
  unique (`crates/netsift-api/src/range.rs`) lit, valide et normalise la plage pour toutes les routes ; aucune
  route ne relit `from_us` / `to_us` elle-même (sauf `timeseries`, qui garde sa sémantique de
  période du graphique).

### Validation (problem+json, `type` `bad-request`, statut 400)

| Cas | Détail |
|---|---|
| valeur non entière, hors `i64` | message de désérialisation (`ApiQuery`, comme aujourd'hui) |
| `from_us > to_us` | `range: the end is before the start` (message existant de `timeseries`) |
| `abs(valeur) > i64::MAX / 1000 - 1` (dépassement en ns) | `range: out of bounds` |

`from_us == to_us` est valide (une microseconde). Une plage disjointe de la session est valide : listes
vides, compteurs à 0, jamais d'erreur. Les routes non filtrées ignorent les deux paramètres (serde
ignore les champs inconnus) : l'UI ne les leur envoie pas.

### Normalisation

L'extracteur borne la plage à la période de la session (`first_ts` / `last_ts` des statistiques de
`meta`, celles de `/summary`). Si la plage bornée couvre toute la session, elle est **abandonnée** : la
route répond exactement comme sans filtre, par ses tables précalculées (`dns_pairs`, `server_ranks`,
`network_*`, `conversation_categories`...). C'est ce qui garde le chemin sans filtre et la plage
« toute la session » sous les temps mesurés de `PERFORMANCE.md`. Une session sans statistiques (import
arrêté brutalement) n'est jamais normalisée : la plage est appliquée telle quelle.

### Pagination keyset

- La plage est un filtre comme les autres : elle entre dans le `WHERE` composé par `Conditions`, jamais
  dans le curseur. Un curseur n'est valable qu'avec les mêmes filtres, plage comprise (déjà vrai pour
  les autres filtres ; non vérifié côté serveur : un curseur rejoué avec une autre plage donne une page
  cohérente avec la nouvelle plage, à partir de la clé du curseur).
- Les listes triées par horodatage (`dns/messages`, `http/transactions` par défaut, `tls/sessions`,
  `credentials`, `smb/auth`) parcourent l'index de la colonne horodatée sur `[F, T)` : la page coûte
  autant qu'aujourd'hui.
- Listes triées sur une autre clé (taille, statut) : le plan se choisit à la sélectivité de la plage
  (parcourir l'index de tri en filtrant, ou lire la plage puis trier ; « Coût ») ; dans les deux cas le
  curseur reste `(clé de tri, id)`. Les listes des vues agrégées (lot b) paginent sur leurs tables
  matérialisées par plage, avec les mêmes index de tri que les tables de session.
- Les totaux (`total`, `total_estimate`) et toutes les statistiques d'une vue (`stats`, `top`, compteurs,
  donuts, cartes) suivent la même plage que sa liste.

## Sémantique par route

Notations : *ponctuel(c)* = `F <= c < T` ; *chevauche(a, b)* = `a < T AND b >= F` (l'élément a été actif
pendant la plage). Un élément replié (une ligne pour plusieurs observations : flux, conversation,
identifiant replié, annonce SMB, port ouvert) qui chevauche la plage est compté **en entier** : ses
compteurs (octets, paquets, `seen_count`, `announce_count`) sont ceux de la session, faute de
répartition dans le temps au stockage. Seule la série temporelle (`timeseries`) donne un volume exact
par seconde. Sous plage active, l'en-tête de chaque colonne d'un tel compteur porte la mention
« session entière » (Credentials : « Vu » ; SMB : « Annonces » ; Pictures : aucune, ses occurrences sont
recalculées), pour qu'aucune valeur de session ne passe pour une valeur de la plage.

Colonne « Lot » : **a** = P5.2a (socle et vues à enregistrements horodatés), **b** = P5.2b (vues
agrégées), **—** = non filtrée (voir « Découpage »).

### Session, sources, exports

| Route | Règle | Lot |
|---|---|---|
| `GET /sessions/{id}` | non filtrée : fiche de la session | — |
| `GET /sessions/{id}/chunks` | non filtrée : la vue Sources décrit les fichiers, pas le trafic | — |
| `GET /sessions/{id}/anomalies` | non filtrée (même raison ; une anomalie sans horodatage n'aurait pas de place) | — |
| `GET /sessions/{id}/events` | non filtrée (progression d'import) | — |
| `GET /sessions/{id}/exports`, `POST .../exports/pcap` | non filtrées : l'export a sa propre sélection `range` ; l'UI la préremplit avec la plage active | — |

### Overview

| Route | Règle | Lot |
|---|---|---|
| `/timeseries` | inchangée : `from_us` / `to_us` y sont la période du graphique (déjà en place) ; sous plage active, l'UI demande la plage | a |
| `/summary` | les champs actuels restent ceux de la session ; sous plage, un objet `range` s'ajoute : `from_us`, `to_us` (plage bornée), `duration_us`, `packets` et `bytes` (somme des seaux d'une seconde de `timeseries` qui coupent la plage, comme le graphique), `flow_count` (flux qui chevauchent `[first_ts, last_ts]`), `host_count` (hôtes qui chevauchent `[first_ts, last_ts]`). `chunk_count`, `linktypes`, `anomaly_count` : session. `modules` : voir « Compteurs de modules » ; n'attend jamais la base d'une plage | a |
| `/modules` | compteurs des modules des vues agrégées (`connections`, `hosts`, `network`, `openPorts`, `servers`) ; sous plage, lus dans la base de la plage (la première requête attend sa construction, annulée avec son client comme les vues) ; sans plage, ceux de la session | b |

### DNS

| Route | Règle | Lot |
|---|---|---|
| `/dns/messages` | *ponctuel(`ts`)* (heure de la requête, sinon de la réponse) ; `pair=` inchangé | a |
| `/dns/pairs` | paires regroupées sur les messages de la plage (`GROUP BY pair_id`) : `messages`, `errors`, `names`, `top_names`, `first_ts`, `last_ts` calculés sur ces messages ; l'identifiant de paire reste `dns_pairs.id` (clé de dépliage et départage du keyset) ; une paire sans message dans la plage est absente | a |
| `/dns/servers` | serveurs regroupés depuis les mêmes paires | a |
| `/dns/stats` | tous les compteurs, percentiles de latence et pays des serveurs sur les messages de la plage | a |

### HTTP et HTTP Headers

| Route | Règle | Lot |
|---|---|---|
| `/http/transactions` | *ponctuel(`ts`)* (requête, sinon réponse) | a |
| `/http/stats` | mêmes transactions | a |
| `/http/headers` | en-têtes des transactions *ponctuel(`ts`)* | a |
| `/http/headers/stats` | méthodes, nombre d'en-têtes et noms les plus fréquents sur ces transactions | a |
| `/http/transactions/{tid}` | non filtrée : détail par identifiant | — |

### TLS

| Route | Règle | Lot |
|---|---|---|
| `/tls/sessions` | *ponctuel(`ts`)* (premier message de la poignée de main) | a |
| `/tls/stats` | mêmes sessions | a |
| `/tls/certificates` | certificats d'au moins une session de la plage ; `sessions` = sessions de la plage ; `problems_only` juge l'expiration sur la période de capture, comme sans plage | a |
| `/tls/sessions/{flow}`, `/tls/certificates/{sha256}`, `.../der`, `.../pem` | non filtrées : détail ou fichier par identifiant | — |

### SMB, Credentials, Pictures

| Route | Règle | Lot |
|---|---|---|
| `/smb/announces` | *chevauche(`first_ts`, `last_ts`)* ; `announce_count` de la session | a |
| `/smb/stats` | répartition des OS sur les mêmes annonces | a |
| `/smb/auth` | `smb_sessions` *chevauche(`first_ts`, `last_ts`)* | a |
| `/credentials`, `/credentials/export` | *chevauche(`first_ts`, `last_ts`)* ; `seen_count` de la session ; l'export suit les filtres de la liste, plage comprise (une sélection `ids=` explicite n'est pas refiltrée) | a |
| `/credentials/stats`, `/credentials/paths` | mêmes entrées | a |
| `/credentials/{entry}` | non filtrée : détail par identifiant | — |
| `/objects` | objets portés par au moins une transaction HTTP *ponctuel(`ts`)* (`resp_sha256`) ; `occurrences`, `first_ts`, `last_ts` recalculés sur ces transactions | a |
| `/objects/stats` | mêmes objets | a |
| `/objects/{sha256}`, `.../thumb`, `.../preview` | non filtrées : fichier par identifiant | — |

### Connections, Open Ports, Servers, Network (vues agrégées)

| Route | Règle | Lot |
|---|---|---|
| `/connections` | conversations recalculées depuis les flux qui *chevauchent(`first_ts`, `last_ts`)*, regroupés par (client, serveur) : octets, paquets, flux, part DNS, protocoles, premier et dernier horodatage des flux retenus, **chaque flux compté en entier** ; l'identifiant reste `conversations.id` (une conversation absente de la session, import interrompu, reçoit un identifiant au-delà) ; filtres et tris inchangés (mêmes index, table de la base de la plage) | b |
| `/connections/stats` | octets envoyés et reçus par pays depuis les mêmes conversations (trafic par hôte de la plage) | b |
| `/connections/top` | matrice du chord sur les conversations recalculées | b |
| `/connections/{conversation}/flows` | flux de la conversation qui chevauchent la plage (index de la conversation, sans base de la plage) | b |
| `/open-ports` | ports ouverts qui *chevauchent(`first_ts`, `last_ts`)* (vus répondre au moins une fois entre le premier et le dernier instant de la plage), regroupés par hôte ; `first_ts` / `last_ts` d'un port : session ; clients (par port et par hôte) comptés sur les flux de la plage | b |
| `/open-ports/stats` | mêmes ports | b |
| `/servers` | preuves recalculées sur les enregistrements de la plage (chaque branche de `server_evidence_source` filtrée par sa colonne horodatée : `dns_messages.ts`, `dhcp_messages.ts`, `http_transactions.resp_ts` ; chevauchement pour les tables repliées `open_ports`, `ntp_responses`, `kerberos_replies`, `smb_sessions`, `smb_announces`), rangs recalculés ; preuve « port ouvert » : flux et clients de la plage ; réponses NTP, réponses KDC et annonces SMB : compteurs de session des lignes retenues | b |
| `/network/graph` | graphe reconstruit par l'étape `network` sur les hôtes actifs, les conversations et le trafic par hôte de la plage | b |
| `/network/node/{ip}` | octets, paquets, pairs, protocoles, voisins, ports ouverts et rôles sur les tables de la plage ; MAC, noms, premier et dernier horodatage : session ; un hôte sans activité dans la plage répond 404 | b |

Une vue de lot **b** livrée avant P5.2b n'applique pas la plage et le dit (« Mise en page »).

### Compteurs de modules (`/summary`, `/modules`)

Sous plage, chaque entrée de `modules` porte `scope: "range" | "session" | "pending"` : `range` quand le
compteur est celui de la plage (même règle que la liste de la vue), `session` sinon. Lot **a** (et les vues
ARP, Ethernet, SSDP, filtrées dès leur création) : `credentials`, `dns`, `http`, `httpHeaders`, `pictures`,
`smb`, `tls`, `arp`, `ethernet`, `ssdp` passent en `range`, comptés dans la session par leur index. Lot **b**
(P5.2b) : `connections` (conversations), `hosts` (hôtes actifs, égal à `range.host_count`), `network` (hôtes
du graphe), `openPorts` (ports ouverts) et `servers` (couples rôle, serveur) se comptent dans la base de la
plage, dont la construction peut durer plusieurs secondes : `/summary` ne l'attend jamais et les renvoie en
`pending` avec le compteur de session ; `GET /sessions/{id}/modules` les donne (`scope: "range"`) en attendant
la base, annulé si le client part. L'Overview garde ainsi ses temps de P5.2a à chaque zoom. Sans plage :
`scope` absent (ou `session`).

## Coût

### Mesures

Jeu du banc de `PERFORMANCE.md` régénéré à l'identique et importé le 2026-11-22 (`./x.sh bench ingest`,
8 894 735 paquets sur 7 jours, 843 955 flux, 392 565 messages DNS, 143 978 transactions HTTP, 168 642
sessions TLS, 992 434 en-têtes, 129 706 ports ouverts, 2 988 paires DNS ; même machine). Plages de 1 h,
24 h et 6 jours centrées sur la session. Requêtes SQL seules (sans l'API), chronométrées par `sqlite3`
3.50.2 sur une copie de la session (`netsift bench sql` ouvre en lecture seule : impossible d'y essayer des
index), une exécution à chaud. Ordres de grandeur, à refaire par `./x.sh bench queries` sur l'API.

Enregistrements dans la plage :

| Plage | flux actifs | messages DNS | transactions HTTP | sessions TLS |
|---|---|---|---|---|
| 1 h | 4 692 | 2 210 | 757 | 949 |
| 24 h | 122 857 | 57 202 | 20 812 | 24 492 |
| 6 j | 726 364 | 337 642 | 123 919 | 145 411 |

Index actuels, la condition de plage simplement ajoutée (ms) :

| Requête | 1 h | 24 h | 6 j |
|---|---|---|---|
| flux actifs (`count`, chevauchement) | 140 | 159 | 259 |
| DNS : compteurs par protocole, rcode, qtype | 4 | 113 | **745** |
| DNS : latence médiane | 1 | 51 | **307** |
| DNS : paires regroupées (`GROUP BY pair_id`, page) | 10 | 219 | **1 621** |
| HTTP : compteurs, hôtes et user agents distincts | 2 | 58 | **347** |
| HTTP : par statut | 1 | 38 | 231 |
| HTTP : page triée par taille | 1 | 34 | 208 |
| HTTP Headers : noms d'en-têtes (jointure aux transactions) | 4 | 131 | **811** |
| TLS : suites x versions | 0 | 23 | 158 |
| hôtes actifs (`hosts`, chevauchement) | 67 | 81 | 92 |
| identifiants actifs (chevauchement) | 24 | 32 | 38 |
| ports ouverts actifs regroupés par hôte (page) | 18 | 21 | 31 |
| volumes de la plage (`timeseries`) | 1 | 8 | 41 |
| Connections : conversations regroupées depuis les flux (page) | 156 | **441** | **1 966** |

Avec les index proposés (section « Index ») :

| Requête | 1 h | 24 h | 6 j |
|---|---|---|---|
| flux actifs, index `(first_ts, last_ts)` | 1 | 11 | 57 |
| DNS : par protocole et erreur / rcode / qtype | 3 / 21 / 21 | 31 / 25 / 25 | 53 / 39 / 52 |
| DNS : latence p95 | 9 | 32 | 149 |
| DNS : page de paires (sondage `(pair_id, ts)` des 2 988 paires) | 10 | 13 | 29 |
| DNS : agrégats complets des paires (noms distincts compris) | 31 | 53 | 183 |
| DNS : 5 noms les plus fréquents des 50 paires de la page | | | 28 |
| HTTP : par statut / top hôtes / top user agents | 7 / 10 / 11 | 8 / 12 / 12 | 13 / 18 / 17 |
| HTTP Headers : noms (heure dénormalisée, index `(name_lc, transaction_id, ts)`) | 58 | | 120 |
| TLS : suites x versions | 12 | 15 | 29 |

Constats :

- **Vues à enregistrements horodatés** (DNS, HTTP, HTTP Headers, TLS, SMB, Credentials, Pictures) : toutes
  sous 200 ms à 6 jours, à condition que chaque agrégat soit servi par un index **couvrant terminé par la
  colonne horodatée** (lecture de l'index seul, sans les lignes : les lignes DNS portent leurs réponses
  JSON, d'où 745 ms). Avec l'index de l'horodatage seul, SQLite choisit de lire la plage puis les lignes une
  à une : bon pour une plage étroite, catastrophique pour une plage large.
- Choix du plan : la condition de plage s'écrit `+ts >= ? AND +ts < ?` (le `+` interdit l'index de `ts`)
  dans les agrégats, ce qui fait choisir l'index couvrant sans `INDEXED BY` (règle d'ADR-023 : jamais
  d'`INDEXED BY` sur un index différé). Pour les pages de listes triées sur une autre clé que
  l'horodatage (taille, statut), le plan se choisit à la sélectivité comme le filtre de catégorie de
  Connections (ADR-023) : compter la plage par l'index de `ts` (moins de 5 ms), puis parcourir l'index
  de tri si la plage couvre une grande part de la table, lire la plage et trier sinon.
- Le planificateur prend aujourd'hui `flows_last_ts` pour une plage au milieu de la session (la moitié de
  la table lue pour 1 h) ; l'index `(first_ts, last_ts)` et l'écriture en deux branches ci-dessous règlent
  le cas.
- **Vues agrégées** (Connections, Open Ports, Servers, Network) : le regroupement des flux d'une plage
  large ne tient pas dans 300 ms (441 ms à 24 h, 2 s à 6 jours pour la seule page des conversations) ;
  aucun index ne l'évite, le coût est le `GROUP BY` lui-même.

### Agrégats précalculés

| Table précalculée (étape) | Vue | Sous plage |
|---|---|---|
| `dns_pairs` (`dns`) | DNS | recalcul à la lecture : identifiants et extrémités lus dans `dns_pairs`, compteurs par sondage de l'index `(pair_id, ts, ...)` de chaque paire (29 ms à 6 j) ; noms distincts et top 5 seulement pour les paires de la page (lot a) |
| `timeseries_minute` / `_hour` (`timeseries`) | Overview | déjà utilisables pour toute plage (`resample`) ; volumes du résumé : 41 ms à 6 j (lot a) |
| `conversations`, `conversation_categories`, `host_traffic` (`connections`) | Connections, Network | regroupement des flux actifs : 290 ms (24 h) à 1 690 ms (6 j) pour les conversations, autant pour le trafic par hôte (lot b) |
| `open_ports`, `open_port_hosts` (`ports`) | Open Ports | ports actifs regroupés par hôte : 31 ms à 6 j ; clients comptés sur les flux actifs : coût du regroupement des flux (lot b) |
| `server_evidence`, `server_roles`, `server_ranks` (`servers`) | Servers, rôles du résumé et du graphe | l'étape coûte 0,9 s sur la session entière ; la vue recalculée à la lecture coûtait 1 094 ms avant P4.8 (lot b) |
| `network_*` (`network`) | Network | l'étape coûte 2,7 s sur la session entière, après le regroupement des conversations (lot b) |

Retenu pour le lot b (P5.2b, détails dans « Notes d'implémentation (P5.2b) ») : **matérialisation par
plage**, une base par plage dans `sessions/<id>/ranges/` plutôt qu'un fichier `ranges.db` commun. Proposition
initiale, gardée pour l'historique : à la première
requête d'une famille sous une plage, les tables dérivées de la famille sont construites pour cette plage par
le code des étapes de fin d'import, paramétré par la plage (conversations et trafic par hôte depuis les flux
actifs, puis ports par hôte, preuves et rangs de serveurs, tables du graphe), dans une base annexe de la
session (`sessions/<id>/ranges.db`, attachée en lecture ; dossier temporaire pour un serveur `--read-only`),
gardée pour les 4 dernières plages (LRU) ; les pages, statistiques et filtres suivants les lisent comme les
tables de session (moins de 1 ms par page mesuré sur la table de conversations matérialisée). Une seule
construction à la fois par (session, plage, famille), les requêtes concurrentes l'attendent. La première
requête dépasse 300 ms pour une plage large (estimation : 0,3 s à 24 h, 2 à 5 s à 6 jours, Network compris) :
la requête attend simplement la construction (pas de réponse 202 ni de tâche de fond) et l'UI montre son
état de chargement ; c'est l'exception à la règle des 300 ms d'`ARCHITECTURE.md` actée par ADR-030.

## Index

Une migration par plage de numéros concernée (`GIT_WORKFLOW.md`) : `0003_core_time_ranges.sql`,
`0101_dns_time_ranges.sql`, `0202_http_time_ranges.sql`, `0302_tls_time_ranges.sql`. Sur une session
existante, elles s'appliquent à la première ouverture (ADR-013 ; un serveur `--read-only` répond 409 comme
pour toute migration) ; pendant un import, ces index sont différés puis construits par l'étape `indexes`
(ADR-023).

Principe : **un agrégat filtrable par la plage est servi par un index couvrant terminé par la colonne
horodatée** ; les index de tri du keyset ne changent pas (leur départage est le rowid ; y ajouter une
colonne casserait l'ordre `(clé, id)` et imposerait un tri), un index couvrant s'ajoute à côté quand un
index de tri sert aussi aux statistiques.

| Table | Index | Sert |
|---|---|---|
| `flows` | `flows_first_ts` remplacé par `(first_ts, last_ts)` | flux actifs (comptage du résumé, branche A) |
| `flows` | `flows_long (last_ts, first_ts) WHERE last_ts - first_ts > 3600000000000` (partiel) | branche B : flux de plus d'une heure |
| `hosts` | `hosts_first_ts` remplacé par `(first_ts, last_ts)` | hôtes actifs du résumé (lecture de l'index seul) |
| `dns_messages` | `dns_messages_proto_error` -> `(proto, is_error, has_query, has_response, ts)` ; `dns_messages_rcode` -> `(rcode, ts)` ; `dns_messages_qtype` -> `(qtype, has_query, ts)` ; `dns_messages_latency` -> `(latency_ns, ts) WHERE latency_ns IS NOT NULL` | `/dns/stats` |
| `dns_messages` | nouveau `(pair_id, ts, is_error, qname)` (`dns_messages_pair_ts` reste pour la liste d'une paire) | paires et serveurs regroupés |
| `http_transactions` | `method_group`, `status_class`, `content_type`, `host`, `user_agent` : `ts` ajouté en dernière colonne ; nouveau `(status_key, ts)` (l'index de tri `status_key` reste) | `/http/stats`, `/http/headers/stats` (méthodes) |
| `http_headers` | colonne `ts` (copie de l'heure de la transaction, écrite par le writer ; remplie par la migration 0202 elle-même sur une session existante, 1,1 s sur le banc) ; `http_headers_name` -> `(name_lc, transaction_id, ts)` | noms d'en-têtes sous plage (120 ms à 6 j au lieu de 811) |
| `tls_sessions` | `tls_sessions_suite_version` et `tls_sessions_cert_status` : `ts` ajouté en dernière colonne ; `tls_sessions_sni` -> `(sni, ts)` | `/tls/stats` |

Flux actifs, en deux branches disjointes réunies par `UNION ALL` (`Δ` = 1 h, constante du code) :

```sql
-- A : flux commencés dans la plage ou moins de Δ avant (index (first_ts, last_ts))
first_ts >= :F - Δ AND first_ts < :T AND last_ts >= :F
-- B : flux commencés plus de Δ avant la plage, donc longs de plus de Δ (index partiel flows_long)
last_ts - first_ts > Δ AND last_ts >= :F AND first_ts < :F - Δ
```

Sans la branche B, une plage en fin de session lirait tous les flux commencés avant elle (index de
`first_ts` seul) ; les flux de plus d'une heure sont rares (aucun sur le banc, dont le plus long dure 59 s :
la fixture d'acceptation en ajoute un). Les autres tables repliées (hôtes, identifiants, annonces et sessions
SMB, ports ouverts) restent sous 100 ms par simple condition de chevauchement (moins de 130 000 lignes).

Coût mesuré sur le banc pour l'ensemble testé : 3,3 s de construction d'index (étape `indexes` : 18,8 s
aujourd'hui), plus 1,9 s pour l'heure des en-têtes (remplissage et index) ; session 1 650 -> 1 751 Mo
(+6 %). C'est aussi le temps de la première ouverture d'une session existante (environ 5 s, publié comme
les autres migrations).

## Mise en page (UI)

Aucune référence : proposition.

### État et URL

- La plage vit dans l'URL de la session : search params `from_us` et `to_us` de la route
  `/sessions/$sessionId` (`validateSearch` : deux entiers, les deux requis côté UI, alors que l'API accepte
  une borne seule ; valeur invalide, borne seule ou plage inversée -> ignorée, jamais d'écran d'erreur ; les
  autres paramètres passent tels quels). Elle est conservée en changeant d'onglet par le middleware
  `retainSearchParams(['from_us', 'to_us'])` de TanStack Router (sidebar, cartes de modules, liens internes),
  et suit le retour arrière (chaque plage validée est une entrée d'historique).
- Une plage appartient à **une** session. Le middleware ne connaît pas la destination d'une navigation et
  recopie donc la plage aussi vers une autre session (« Ouvrir » de l'assistant d'import, etc.) : la
  session de la plage est notée par routeur (`useRangeGuard` du layout de session), une plage vue avec
  une autre session est ignorée dès le premier rendu (aucune requête ne la porte) puis retirée de l'URL
  (entrée d'historique remplacée). Revenir en arrière vers la première session retrouve sa plage.
- Un seul hook, `useTimeRange()` (`ui/src/app/timeRange.ts`), lit la plage et expose `set`, `clear` ;
  les fonctions de `ui/src/api/*.ts` reçoivent la plage et ajoutent `from_us` / `to_us` aux routes
  filtrées. La plage entre dans **toutes** les clés TanStack Query des routes filtrées (dernier élément
  de la clé, `null` sans plage) : changer de plage refait les requêtes, revenir à une plage déjà vue
  relit le cache. Les clés des routes non filtrées n'en dépendent pas.
- Registre des vues qui appliquent la plage : `ui/src/app/timeFilterViews.ts`, une ligne triée par vue
  (point d'enregistrement, `GIT_WORKFLOW.md`). Une vue absente du registre ignore la plage.
- La validation et la saisie réutilisent le code de Save PCAP : `ui/src/views/exports/range.ts` devient
  `ui/src/lib/timeRange.ts` (`parseTimestamp`, contrôle « fin avant début », bornes incluses, fin sans
  fraction = toute sa seconde), utilisé par le dialogue d'export et par celui de la plage.

### Poser la plage (Overview)

- Graphique de trafic : le zoom (`dataZoom` inside + slider, comme aujourd'hui) devient la plage dès qu'il
  se stabilise (400 ms sans nouvel événement) ; la fenêtre est alignée sur les seaux affichés (au moins la
  seconde), pour que les volumes du résumé égalent ceux du graphique. La série est alors **redemandée
  au serveur** sur la plage (`timeseries?from_us&to_us`, 500 points, 200 sous 640 px) : zoomer gagne en
  résolution jusqu'à la seconde, au lieu d'étirer la série chargée. Le zoom de la nouvelle série repart à
  100 %.
- Contrôles de la carte (bande `actions`, après Linéaire / Log) : « Dézoomer » (double la plage autour de
  son centre, bornée à la session ; désactivé sans plage), « Plage… » (dialogue de saisie),
  « Réinitialiser le zoom » devient « Toute la session » (efface la plage).
- Dialogue « Plage horaire » : deux champs Début / Fin en heure locale ISO (comme Save PCAP), préremplis
  avec la plage active ou la période de la session ; erreurs en ligne (format, fin avant début) ;
  Appliquer, Effacer, Annuler. Même dialogue depuis la pastille d'en-tête, donc depuis toute vue.
- Bandeau résumé sous plage : Durée et, en indice, « Capturé <période> » : la plage bornée à la période
  capturée, c'est-à-dire là où des paquets existent (la pastille, elle, montre la plage telle que posée,
  qui peut commencer avant le premier paquet) ; plage hors de la session -> « Aucun paquet ». Paquets,
  Volume (de la plage), Hôtes et Flux actifs dans la plage ; Chunks inchangé. Indice « Dans la plage ».

### Afficher la plage hors Overview

- Pastille dans l'en-tête de l'application (`AppShell`, entre le titre et l'indicateur d'import), visible
  sur toute route de session dès qu'une plage est active : icône `CalendarRange` 16 px, plage en texte
  (`formatTimestamp` ; heures seules quand la session et la plage tiennent dans un même jour, sinon la date une
  fois si la plage tient dans un jour), bouton
  icône « Effacer la plage » (`X`, cible 32 px). Un clic sur le texte ouvre le dialogue de saisie.
  Infobulle et `aria-label` : plage complète à la microseconde avec le fuseau.
- Sur une vue absente du registre (Sources, et les vues de lot b avant P5.2b), la pastille est estompée,
  avec l'infobulle « Cette vue n'est pas filtrée par la plage » ; la vue elle-même est inchangée.
- Les vues filtrées n'ajoutent rien d'autre : leurs compteurs et états vides suivent la plage ; un état
  vide sous plage dit « Rien dans la plage » et propose « Effacer la plage ».
- Sous 640 px : la pastille ne montre que les heures (`14:03 - 14:20`, ou les dates seules si la plage
  dépasse un jour), le titre de vue de l'en-tête se tronque d'abord ; à 375 px, bouton menu, titre tronqué,
  pastille, indicateur d'import et thème tiennent sur la ligne de 48 px sans débordement.

### Compteurs

- Cartes de modules de l'Overview : compteur de la plage pour `scope: "range"` (« 1 234 dans la plage »),
  compteur de session avec la mention « session entière » pour `scope: "session"`. Une carte `pending`
  (vue agrégée sous plage) montre un squelette à la place du compteur jusqu'à la réponse de `/modules`
  (demandée seulement sous plage), puis le compteur de la plage ; si `/modules` échoue, le compteur de
  session avec « session entière ». Une carte à 0 dans la
  plage est estompée comme une carte à 0 (règle de `overview.md`), mais reste un lien : la vue affiche son
  état vide « Rien dans la plage ».
- La sidebar n'a pas encore de compteurs (`AppShell` n'en transmet aucun) ; quand ils viendront, ils
  liront les mêmes compteurs.

### Save PCAP

Plage active : le dialogue s'ouvre sur « Plage horaire », préremplie avec la plage ; sans plage, inchangé.

## Améliorations par rapport à la référence

Fonction absente de la référence. Zoom de l'Overview à la résolution de la seconde (au lieu d'un zoom sur
500 points chargés), plage partageable par l'URL.

## Critères d'acceptation

API (fixture synthétique `netsift-fixtures` « trafic réparti » : trois rafales de trafic mixte DNS, HTTP
avec image, TLS avec certificat, SMB, identifiants FTP et HTTP Basic, à 10 min d'intervalle, plus un flux
TCP long qui couvre les trois) :

- validation : 400 problem+json pour `from_us > to_us`, valeur non entière, dépassement ; plage disjointe
  -> 200 et listes vides ; plage couvrant la session -> réponse identique octet pour octet à celle sans
  plage (toutes les routes filtrées) ;
- pour chaque famille (DNS, HTTP, HTTP Headers, TLS, SMB, Credentials, Objects ; puis en P5.2b
  Connections, Open Ports, Servers, Network) : la plage de la rafale du milieu ne renvoie que ses
  enregistrements, et le `total` de la liste, les compteurs de `stats` et le compteur de module du résumé
  sont égaux entre eux ; le flux long apparaît dans les trois plages (chevauchement) ;
- bornes : un enregistrement à `to_us` exactement (fraction de microseconde comprise) est inclus, un à
  `to_us + 1 µs` exclu ; idem pour `from_us` ;
- pagination : pages successives sous plage sans doublon ni trou (tri par horodatage et par une autre
  clé) ; snapshots `insta` des réponses de la rafale du milieu ;
- `/summary` sous plage : `range.packets` / `range.bytes` égaux aux totaux de `timeseries` sur la même
  plage ; sous 300 ms sur le banc pour une plage de 6 jours, compteurs de modules compris (estimation sur les
  mesures ci-dessus : environ 270 ms ; au-delà, les compteurs de modules passent dans une route à part,
  `GET /sessions/{id}/modules`, demandée en parallèle) ;
- banc (`./x.sh bench queries`, nouvelles requêtes sous plage de 1 h, 24 h et 6 jours) : aucune requête du
  lot livré au-dessus de 300 ms ; chiffres reportés dans `PERFORMANCE.md`.

UI (Vitest) :

- `useTimeRange` : lecture et validation des search params, conservation en changeant d'onglet, effacement ;
- clés de requête : plage présente dans la clé des routes filtrées, absente des autres ;
- Overview : zoom stabilisé -> plage dans l'URL et requête `timeseries` sur la plage ; Dézoomer,
  Toute la session ; dialogue de saisie (erreurs, Appliquer, Effacer) ;
- pastille : texte, effacement, état estompé sur une vue non filtrée ; Save PCAP prérempli.

Visuel : `./x.sh shots` verts en `en` et `fr` pour `overview`, `overview-range` (plage active, dialogue
fermé), `overview-range-dialog`, et une vue filtrée par famille avec plage active (`dns-range`,
`http-range`, `tls-range`, `credentials-range` ; en P5.2b `connections-range`, `network-range`), à 375,
768, 1280 et 1920 px : pastille sans chevauchement ni débordement.

## Découpage

Décidé le 2026-11-22 : **P5.2 est scindée en deux tâches** (ROADMAP).

- **P5.2a `feat/time-filter`** (cette branche) — socle et vues à enregistrements horodatés :
  - API : extracteur de plage (`range.rs`), `TimeRange` et fragments de `Conditions` du store,
    normalisation, erreurs ; migrations d'index 0003, 0101, 0202 (avec le remplissage de l'heure des en-têtes) et 0302
    (heure des en-têtes) ;
  - routes filtrées : `/summary` (objet `range`, `scope` des compteurs), DNS (4 routes), HTTP et
    HTTP Headers (4), TLS (3), SMB (3), Credentials (4), Objects (2) ;
  - UI : search params et `retainSearchParams`, `useTimeRange`, plage dans les clés de requête, registre
    `timeFilterViews.ts`, pastille d'en-tête, dialogue de saisie (code de `range.ts` mis en commun), zoom
    de l'Overview avec refetch serveur, Dézoomer / Toute la session, bandeau résumé sous plage, cartes de
    modules, Save PCAP prérempli ;
  - banc : requêtes sous plage ajoutées à `netsift bench queries`, chiffres dans `PERFORMANCE.md`.
- **P5.2b `feat/time-filter-aggregates`** (après P5.2a) — vues agrégées : Connections (4 routes),
  Open Ports (2), Servers (1), Network (2), compteurs de modules `connections`, `hosts`, `network`,
  `openPorts`, `servers` ; matérialisation par plage (section « Agrégats précalculés ») et sa règle de
  performance (ADR-030). Elle commence par une courte mesure de la matérialisation (Network et Servers
  surtout) et complète cette spec.

Entre les deux, les vues de lot b affichent la session entière, signalé par la pastille estompée et la
mention « session entière » des cartes de modules : rien de faux n'est affiché.

Les nouveaux onglets de la phase 5 (ARP, Ethernet, SSDP, SIP, FTP, Telnet, WiFi, MQTT...) appliquent la
convention dès leur création (ADR-030) : routes filtrées, ligne dans `timeFilterViews.ts`, critère
d'acceptation sous plage. P5.18 (rapports) s'appuie sur le même extracteur.

## ADR

ADR-030 (`docs/DECISIONS.md`).

## Notes d'implémentation (P5.2a)

- API : `crates/netsift-api/src/range.rs` (extracteur `ApiRange`, `RangeParams::resolve`), store :
  `crates/netsift-store/src/range.rs` (`TimeRange`, fragments de `Conditions`, `PointSql` pour le plan des
  agrégats, `ModuleRows` pour les compteurs du résumé, flux et hôtes actifs). Les agrégats fixes lient la
  plage aux indices réservés `?98` / `?99` (un paramètre nommé écrit avant `?1` en prendrait l'indice).
- Tests : `crates/netsift-api/src/range/tests.rs` sur la fixture `netsift_fixtures::spread` (trois rafales à
  10 min d'intervalle, une connexion de plus de deux heures), snapshot `middle_burst` ;
  `upgrade_tests::a_session_of_the_previous_build_answers_time_ranges_after_its_opening`.
- UI : `ui/src/lib/timeRange.ts` (type, analyse, `withRange`, `rangeKey`, saisie commune avec Save PCAP),
  `ui/src/app/timeRange.ts` (`useTimeRange`, `useViewRange`), registre `ui/src/app/timeFilterViews.ts`,
  `components/TimeRangeChip.tsx`, `components/TimeRangeDialog.tsx`. Les hooks de requête des vues filtrées
  lisent eux-mêmes la plage (`useViewRange`) : les vues ne la manipulent pas. Un état vide sans action propre
  affiche « Rien n'a été enregistré entre ces heures » et « Effacer la plage » sous plage.
- Compteurs repliés sous plage, dans un tableau : en-tête court (« Vu », « Trames ») avec « Session entière »
  en seconde ligne, par `WholeSessionHeader` ou, dans une `DataTable`, `wholeSessionHeader`
  (`components/WholeSession.tsx`) ; exemples : annonces SMB, compteurs Ethernet, liaisons ARP. Sur une carte
  ou dans un détail, la mention suit le compteur entre parenthèses : « 147 fois (session entière) » (cartes
  SMB), « Vu 296 fois (session entière) » (cartes et détail Credentials).
- Un agrégat fixe qui reçoit une plage sans porter ses bornes `?98` / `?99` est une erreur, jamais une
  réponse non filtrée.
- Mesures : `docs/PERFORMANCE.md`, section « Filtre temporel (P5.2a) ».

## Notes d'implémentation (P5.2b)

- **Base d'une plage** (`crates/netsift-store/src/ranges.rs`, `ranges/build.rs`, `ranges/fold.rs`) : un
  fichier SQLite par plage, `sessions/<id>/ranges/<début ns>_<fin ns>_<empreinte>.db`, qui contient les
  tables dérivées des quatre vues **sous les noms et avec le schéma de la session** (DDL et index recopiés de
  son `sqlite_master`) : `hosts`, `conversations`, `host_traffic`, `conversation_categories`, `open_ports`,
  `open_port_hosts`, `server_evidence`, `server_roles`, `server_ranks`, `network_*`, plus une copie de `meta`
  (étapes `connections`, `ports`, `servers`, `network` marquées faites) et deux tables propres
  (`open_port_clients`, `open_port_host_clients`). Une vue l'ouvre en `main` en lecture seule, la session
  attachée sous le nom `session` (URI `mode=ro`) : un nom non qualifié trouve d'abord la table de la plage,
  sinon celle de la session, donc **les requêtes des vues sont inchangées** (seule exception : les clients des
  ports, lus dans `open_port_clients` quand la connexion est une base de plage). Un fichier par plage plutôt
  qu'un `ranges.db` commun : publication atomique (construction dans `<nom>.db.partial` puis renommage),
  éviction par suppression, aucune écriture dans un fichier lu par une autre requête. Le fichier partiel porte
  le pid et un aléa (`<nom>.<pid>-<aléa>.db.partial`) ; seul un partiel vieux d'une heure est supprimé (laissé
  par un processus arrêté), jamais celui d'une construction en cours d'un autre processus.
- **Construction** (code des étapes, paramétré par la plage) : hôtes et ports ouverts qui chevauchent la plage
  copiés tels quels ; une lecture en continu des flux actifs (deux branches de `count_active_flows` pour une
  plage étroite, toute la table dans l'ordre de stockage au-delà d'un vingtième des flux) agrège en mémoire les
  conversations (identifiant de la session gardé), le trafic par hôte, les comptes par paire de catégories
  (règle de l'étape `connections`) et les flux et clients distincts de chaque port ouvert ; la lecture joint
  chaque flux aux catégories de ses extrémités et au port ouvert atteint par clé primaire de la base de la
  plage (rien n'est chargé en entier) ; mémoire bornée par des passes (un million de flux actifs par passe au
  plus, conversations réparties par hachage de leurs extrémités, ports et clients ajoutés à la fin de chaque
  passe, trafic par hôte écrit au-delà de 200 000 hôtes) ; preuves de serveurs par la requête de
  `server_evidence_source` filtrée branche par branche ; rôles comme `server_roles_source` (les serveurs des
  preuves, plus tout serveur DHCP d'une réponse de la plage : la vue garde la jambe relais d'une réponse
  relayée que les preuves écartent) ; rangs par l'étape `servers` ; tables du graphe par l'étape `network` telle quelle. Un `GROUP BY`
  SQL des flux coûtait 8 s à 6 jours sur le banc (tri et insertions dans le désordre des identifiants).
- **Cache** (`RangeCache`, un par processus dans l'état de l'API) : une seule construction à la fois par
  fichier (les requêtes concurrentes l'attendent), au plus 2 constructions simultanées tous fichiers confondus,
  4 plages gardées par session (les moins récemment utilisées supprimées, date de modification du fichier
  mise à jour à chaque lecture). Une plage est bornée à la période capturée avant de nommer son fichier (deux
  plages qui ne diffèrent qu'hors de la session partagent une base ; une plage disjointe donne une base vide).
  Le fichier publié est revérifié sous le verrou avant de lancer une construction (course avec le
  renommage) ; une garde libère les requêtes en attente et retire la construction si elle panique ; le dossier
  `ranges/` n'est jamais recréé avec ses parents (une session supprimée entre-temps ne revient pas).
- **Invalidation** : l'empreinte du nom de fichier hache la version de la construction, les migrations
  appliquées, les étapes de fin d'import faites et les statistiques de la session : une session migrée ou dont
  une étape est rejouée obtient de nouveaux fichiers, les anciens sortent du cache par l'éviction. Une session
  ne se réimporte pas sur place (un import crée une session) ; `ranges/` est supprimé avec la session.
- **Annulation** : l'extracteur `AggregateRange` (API) lève le drapeau d'annulation de la requête quand le
  gestionnaire est abandonné (client parti, nouvelle plage dans l'UI qui annule la requête précédente) ; une
  construction s'interrompt (`sqlite3_interrupt` et contrôles entre étapes) quand toutes les requêtes qui
  l'attendent sont annulées, sans rien laisser sur le disque ; une requête qui reste la reprend.
- **Serveur `--read-only`** : jamais d'écriture dans le dossier de données ; les bases de plage vont dans un
  dossier temporaire du processus (créé à la première plage, supprimé à l'arrêt), avec les mêmes règles.
  Une session qui attend des migrations répond 409 comme avant.
- **Sémantique retenue** (tableau « Connections, Open Ports, Servers, Network ») : quand la base de la plage
  permet une valeur de la plage, c'est elle qui est servie (clients des ports, preuves ponctuelles des
  serveurs, ports ouverts et rôles du panneau de nœud, trafic par hôte). Restent des valeurs de session : les
  octets et paquets d'un flux actif (compté en entier), `first_ts` / `last_ts` d'un port ouvert, les
  compteurs des preuves repliées (réponses NTP, réponses KDC, annonces SMB), MAC, noms et dates d'un hôte.
- **UI** : les quatre vues sont dans `timeFilterViews.ts` ; leurs hooks envoient la plage (dialogue des flux
  et panneau de nœud compris). Mentions sous plage : « Les flux actifs dans la plage sont comptés en entier. »
  sous le titre de Connections et de Network (`components/WholeFlowsNote.tsx`) ; « (session entière) » après
  la période d'un port dans l'infobulle de son badge (Open Ports) ; Servers : « Session entière » en petit sur
  une seconde ligne sous un nombre d'occurrences qui contient une preuve repliée (ligne du serveur et ligne de
  la preuve dans le détail), comme les colonnes SMB et Ethernet, les badges de preuves gardant leur libellé.
- **Tests** : `crates/netsift-store/src/ranges/tests.rs` (contenu d'une base, plage couvrante égale aux tables
  de session, LRU à 4, plages bornées, empreinte, construction partagée par 8 requêtes, annulation seule et
  avec une requête restante, URI, fichiers partiels) ; `crates/netsift-api/src/range/aggregate_tests.rs` sur la
  fixture `spread` (rafale du milieu : liste, stats, top, flux d'une conversation et compteur de module
  cohérents ; entre deux rafales seul le flux long ; ports, serveurs et graphe ; pagination sans trou ni
  doublon ; une construction par plage et 4 plages gardées ; requêtes concurrentes ; serveur inscriptible et
  suppression de la session ; snapshot `middle_burst_aggregates`), routes agrégées ajoutées aux tests de
  plage couvrante et disjointe ; `/summary` sans construction et `/modules` ;
  `crates/netsift-api/src/range/equivalence_tests.rs` : sur des sessions importées (démo et vitrine des
  serveurs, `spread`), la base d'une plage couvrante (bornée à la période, donc construite) égale la session
  table par table (les 17 tables copiées, `meta` hors marqueurs d'étapes) ; jambe relais DHCP dans les tests
  du store ; `AppProto::ALL` tient dans le masque de libellés (`netsift-engine`). Aucune migration : pas de
  test d'upgrade propre (l'empreinte couvre une session migrée).
- **Mesures** : `docs/PERFORMANCE.md`, section « Filtre temporel (P5.2b) ».

## Décisions (2026-11-22)

Validées avec la spec (utilisateur et orchestrateur) :

1. Découpage en P5.2a (cette spec, socle et vues à enregistrements horodatés) et P5.2b (vues agrégées).
2. Zoom implicite : la plage suit le zoom du graphique dès qu'il se stabilise (400 ms), avec refetch
   serveur ; Dézoomer, Plage…, Toute la session.
3. Vues agrégées (P5.2b) : la première requête d'une plage attend la matérialisation, sans 202 ; exception
   écrite à la règle des 300 ms (ADR-030). Après revue (décision de l'utilisateur) : les compteurs de modules
   des vues agrégées passent dans une route à part, `/modules`, pour que `/summary` n'attende jamais la base.
4. Compteurs d'éléments repliés : valeurs de session conservées, mention « session entière » dans l'en-tête
   de colonne sous plage active.
5. Sources (chunks, anomalies) non filtrée ; expiration des certificats jugée sur la période de capture ;
   seuil des flux longs `Δ` = 1 h ; la plage est le premier état de filtre porté par l'URL (les autres
   filtres de vue ne changent pas dans cette tâche).
