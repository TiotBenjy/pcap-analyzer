# ARP

Tâche ROADMAP P5.3. Référence : `docs/reference/private/arp.png` (non publiée).

## Référence

La plateforme d'origine montre un graphe des adresses MAC reliées par leurs échanges ARP (diffusion
`FF:FF:FF:FF:FF:FF` comprise), trois bascules avec compteurs (Request, Reply, Gratuitous) qui filtrent le
graphe, une légende Router / Broadcast et un bouton « How to confirm ARP spoofing ». Le graphe est peu
lisible (cinq nœuds en gros caractères, arêtes sans sens ni volume) et ne répond pas à la question
principale : quelle adresse IP a changé de propriétaire, et quand.

On reprend les fonctions (compteurs par type, filtres, aide à la confirmation d'une usurpation) et on
remplace le graphe par des tableaux (choix laissé par la ROADMAP) : la correspondance IP <-> MAC dans le
temps, les conflits expliqués et la liste des messages.

## But

Répondre à « quelles machines ont annoncé quelles adresses, quand, et une adresse a-t-elle été revendiquée
par plusieurs cartes réseau ? » : compter requêtes, réponses, ARP gratuits et sondes, dresser la table
IP <-> MAC avec première et dernière activité, signaler les conflits (une IP, plusieurs MAC) et les signes
d'usurpation (réponses non sollicitées, ARP gratuits, une MAC qui revendique plusieurs adresses), en texte
court et factuel.

## Données

### Analyseur `arp` (`crates/netsift-analyze/src/arp.rs`)

Entrée : chaque paquet décodé dont la couche réseau est ARP (`Network::Arp`, `ArpInfo` de
`netsift-dissect`, déjà décodé ; aucun nouveau parseur). Un `Record::Arp(ArpMessage)` par paquet.

Type de message (`kind`, disjoint) :

| `kind` | Règle |
|---|---|
| `probe` | opération 1, IP émettrice `0.0.0.0` (sonde de détection de conflit, RFC 5227) |
| `gratuitous` | opération 1 ou 2, IP émettrice = IP cible (annonce, RFC 5227 et RFC 5944) |
| `request` | opération 1, autres cas |
| `reply` | opération 2, autres cas |
| `other` | autre opération (RARP 3/4, InARP 8/9...) ou protocole autre qu'IPv4 |

- **Réponse non sollicitée** (`unsolicited`) : une réponse (`reply`) qu'aucune requête de sa cible pour
  son IP émettrice n'a précédée dans les 10 s. L'analyseur garde, borné à 16 384 entrées, l'heure de la
  dernière requête par couple (demandeur, adresse demandée) ; carte pleine : les requêtes de plus de 10 s
  sont oubliées, et si cela libère moins d'un quart de la place, toutes (pas de balayage à chaque paquet
  d'un flot forgé). Les réponses des 10 premières secondes de
  trafic ARP ne sont jamais marquées (la requête peut précéder le début de la capture). Les paquets sans
  couche IP (ARP compris) vont tous au même shard (`shard_hash` = 0) dans l'ordre de capture : l'état est
  complet. Si cette répartition changeait, le marquage deviendrait plus large, jamais faux en sens inverse
  (une réponse précédée de sa requête n'est jamais marquée sur le même shard). Vérifié par
  `arp_state_survives_shards_and_chunk_borders` (`netsift-engine/tests/ingest.rs` : 1, 4 et 7 shards,
  fichier unique et chunks coupés entre une requête et sa réponse).
- **Correspondance** (`binds`) : un message `request`, `reply` ou `gratuitous` dont l'IP émettrice est une
  IPv4 non nulle et la MAC émettrice une adresse unicast non nulle annonce que cette IP est joignable à
  cette MAC. Il alimente la table des correspondances.
- Pas de résolution de constructeur (OUI) : c'est l'onglet Ethernet (P5.4).

### Tables (migration `1000_arp.sql`, plage 1000-1099)

| Table | Contenu | Règle d'écriture |
|---|---|---|
| `arp_messages` | un message par ligne : `ts`, `frame`, `operation`, `kind`, MAC et IP émettrices et cibles (texte canonique, `NULL` si absentes), `unsolicited`, `binds` | insertion |
| `arp_bindings` | une ligne par couple (IP, MAC) annoncé : `first_ts`, `last_ts`, `messages`, `requests`, `replies`, `gratuitous`, `unsolicited` | upsert commutatif (somme, min, max) écrit avec chaque message `binds` |

Index : `arp_messages (ts)` (liste, pagination keyset `(ts, id)`), `(kind, unsolicited, ts)` (compteurs
sous plage, filtre de type), `(ts) WHERE unsolicited = 1` (filtre « non sollicitées », partiel),
`(sender_ip, ts)`, `(target_ip, ts)`, `(sender_mac, ts)` (filtre d'adresse),
`(binds, sender_ip, sender_mac, ts)` (émetteurs les plus actifs sous plage) ; `arp_bindings (first_ts)`
et la clé `(ip, mac)` (conflits, `EXISTS` par IP). Pas d'étape de fin d'import : la table des
correspondances est tenue par le writer.

### API (`crates/netsift-api/src/arp.rs`)

| Méthode | Route | Réponse |
|---|---|---|
| GET | `/sessions/{id}/arp/stats` | `ArpStats` : compteurs par type, réponses non sollicitées, correspondances, adresses IP distinctes, conflits, premier et dernier message, 10 émetteurs les plus actifs |
| GET | `/sessions/{id}/arp/messages` | `Page<ArpMessageInfo>` ; filtres `kind` (liste séparée par des virgules), `ip` (émettrice ou cible, adresse exacte), `mac` (émettrice, adresse exacte), `unsolicited=true` ; tri par heure puis `id` |
| GET | `/sessions/{id}/arp/bindings` | `Page<ArpBindingInfo>` ; filtres `q` (sous-chaîne de l'IP ou de la MAC), `conflicts=true` ; tri par première activité puis `rowid`, indicateur `conflict` par ligne |
| GET | `/sessions/{id}/arp/conflicts` | `ArpConflicts` : 100 IP au plus revendiquées par plusieurs MAC (16 MAC au plus chacune) avec leurs signes, et le total |

`total_estimate` des listes : calculé sur la première page (sans curseur), absent ensuite (`fetchAll` ne le
lit pas ; on évite un comptage par page).

Signes d'un conflit (calculés à la lecture sur les correspondances de l'IP, limités aux 16 premières
MAC par première activité, celles que la réponse liste) :

| Signe | Règle | Texte (résumé) |
|---|---|---|
| `simultaneous` | deux MAC actives sur des périodes qui se chevauchent | deux cartes répondent en même temps : doublon d'adresse, paire de secours (VRRP, HSRP) ou usurpation |
| `successive` | aucune période ne se chevauche | l'adresse a changé de carte : bail DHCP réattribué, carte remplacée ou usurpation qui a pris le relais |
| `gratuitous` | une des MAC a envoyé un ARP gratuit pour cette IP | une annonce force la mise à jour des caches voisins ; normale au démarrage ou lors d'une bascule |
| `unsolicited` | une des MAC a envoyé des réponses non sollicitées pour cette IP | réponses sans requête : méthode habituelle d'empoisonnement de cache |
| `multiple_ips` | une des MAC revendique aussi d'autres adresses | une même carte qui répond pour plusieurs IP (dont la passerelle) : routeur en proxy ARP ou intermédiaire |

Le compteur de module de `/summary` est `arp` (table `arp_messages`).

### Filtre temporel (ADR-030, `docs/specs/time-filter.md`)

| Route | Règle |
|---|---|
| `/arp/messages` | *ponctuel(`ts`)* |
| `/arp/stats` | compteurs par type et émetteurs : messages *ponctuel(`ts`)* ; correspondances, adresses et conflits : correspondances qui *chevauchent(`first_ts`, `last_ts`)* |
| `/arp/bindings` | correspondances qui chevauchent la plage ; `messages`, `requests`, `replies`, `gratuitous`, `unsolicited` de la session (en-tête « session entière » sous plage) ; `conflict` jugé entre correspondances qui chevauchent la plage |
| `/arp/conflicts` | idem, sur les correspondances qui chevauchent la plage |
| `/summary` (`modules.arp`) | messages *ponctuel(`ts`)*, `scope: "range"` |

Les compteurs de type et le total de `/arp/messages` sans filtre sont égaux au compteur de module.

### Coût (session de 10 M paquets)

ARP représente d'ordinaire moins de 1 % des paquets d'un LAN (requêtes de cache toutes les quelques
minutes par couple d'hôtes), soit au plus 100 000 messages ; on dimensionne pour 1 M (balayage ARP d'un
/16, tempête de diffusion). Les correspondances sont bornées par le nombre de couples (IP, MAC) distincts
(quelques milliers sur un LAN, au pire de l'ordre du nombre de messages lors d'un balayage usurpant des
adresses aléatoires).

- Liste des messages : parcours de l'index `(ts)` (ou `(sender_ip, ts)`, `(target_ip, ts)`,
  `(sender_mac, ts)` filtrés) sur `[F, T)`, une page de 1 000 lignes coûte quelques ms avec deux jointures
  par clé à `hosts`.
- Compteurs par type : `GROUP BY kind, unsolicited` sur l'index couvrant `(kind, unsolicited, ts)` ; sous
  plage, `PointSql` choisit entre l'index de `ts` (plage étroite) et l'index couvrant (`+ts`, plage large).
  Au pire, lecture de l'index seul : environ 1 M d'entrées, de l'ordre de 50 à 100 ms.
- Émetteurs les plus actifs : sans plage, tri des correspondances (petite table) ; sous plage,
  `GROUP BY sender_ip, sender_mac` sur l'index couvrant `(binds, sender_ip, sender_mac, ts)` : même
  ordre de grandeur que les compteurs tant que les couples distincts sont peu nombreux (cas réel) ; le
  pire cas, une plage large sur 1 M de messages forgés tous de couples distincts, approche 500 ms (le
  regroupement coûte alors autant de groupes que de lignes). Accepté : ce n'est pas un trafic ARP réel.
- Correspondances et conflits : lecture de `arp_bindings` (chevauchement) et sondage de la clé `(ip, mac)` ;
  quelques ms pour quelques milliers de lignes, environ 100 ms pour 100 000.

Aucune requête de la vue ne dépasse 300 ms dans ces hypothèses (sauf le pire cas forgé ci-dessus).

## Mise en page

Une seule colonne de cartes, de haut en bas :

1. **En-tête** : titre « ARP », sous-titre (nom de session), compteur de messages.
2. **Bande de chiffres** (`StatCard`, 2 colonnes, 3 à partir de 640 px, 5 à partir de 1280 px) : messages,
   correspondances IP <-> MAC, adresses IP, conflits, réponses non sollicitées.
3. **Rangée** (1 colonne, 3 colonnes à partir de 1280 px) :
   - carte **Conflits d'adresses** (2 colonnes) : un bloc par IP revendiquée par plusieurs MAC :
     `Endpoint` de l'IP, nombre de MAC, puces des signes ; une ligne par MAC (adresse mono + `CopyButton`,
     première et dernière activité, messages, ARP gratuits, réponses non sollicitées, autres adresses
     revendiquées) ; une phrase par signe ; bouton « Voir les messages » qui pose le filtre d'adresse de la
     liste. Sans conflit : état vide « Aucune adresse revendiquée par plusieurs MAC » ; avec des réponses
     non sollicitées, une note les signale (bouton « Voir » qui active le filtre correspondant). Sous la
     liste, une section dépliable « Confirmer une usurpation » (quatre étapes courtes) dès qu'il y a un
     conflit ou une réponse non sollicitée ;
   - carte **Émetteurs les plus actifs** : `BarList` (IP et MAC, messages) ; un clic pose le filtre
     d'adresse de la liste des messages.
4. **Correspondances IP <-> MAC** : bande `filters` avec `SearchInput` (IP ou MAC, sous-chaîne) et bascule
   « Conflits seulement » ; `DataTable` (mode `cards` sous 768 px) : IP (`Endpoint`), MAC (mono, copie),
   première et dernière activité (`Timestamp`), barre d'étendue (position et longueur de la période
   d'activité dans la période des messages affichés ; omise de 768 à 1024 px, gardée dans les cartes),
   messages (requêtes, réponses et gratuits en infobulle), puce « Conflit ». Un clic sur une ligne pose
   le filtre d'adresse (IP et MAC) de la liste des messages.
5. **Messages** : bande `filters` avec `FilterBar` (bascules Requêtes, Réponses, Gratuits, Sondes, Autres
   avec leurs compteurs, plus « Non sollicitées seulement ») et la puce du filtre d'adresse actif
   (effaçable) ; `DataTable` (cartes sous 768 px) : heure, type (puce), IP et MAC émettrices, IP et MAC
   cibles (MAC cible omise de 768 à 1024 px, gardée dans les cartes), puce « Non sollicitée ». La bascule
   « Autres » n'apparaît que s'il y en a. 5 000 lignes chargées au plus, mention quand la liste est coupée.

Sous plage active : chiffres de la plage ; colonnes Première, Dernière et Messages de la table des
correspondances avec « Session entière » en seconde ligne de l'en-tête (libellé sur deux lignes dans les
cartes) ; dans la carte des conflits, « Session entière » devant la période et les compteurs de chaque
MAC (valeurs des correspondances repliées) ; état vide « Rien n'a été enregistré entre ces heures » avec « Effacer la plage ».
Les filtres de la vue sont locaux (comme les autres vues : seule la plage est portée par l'URL,
`time-filter.md`, décision 5).

## Améliorations par rapport à la référence

- Graphe illisible remplacé par une table IP <-> MAC datée et une liste de conflits expliqués.
- Compteurs des sondes RFC 5227 et des réponses non sollicitées, en plus des trois types de la référence.
- Aide « confirmer une usurpation » intégrée à la carte des conflits, texte court et factuel.
- Toute IP par `Endpoint`, toute MAC copiable ; aucun emoji (la référence en utilise pour les nœuds).

## Critères d'acceptation

- Fixture synthétique (`netsift_fixtures::arp`) : requêtes et réponses entre trois hôtes, une sonde, un
  ARP gratuit, et une IP (la passerelle) revendiquée par une seconde MAC par des réponses non sollicitées
  -> types et indicateurs exacts (tests de l'analyseur, snapshot `insta`).
- API : compteurs, filtres (`kind`, `ip`, `mac`, `unsolicited`, `q`, `conflicts`), conflit et ses signes,
  plage (rafale du milieu seulement, bornes incluses, total égal au compteur de module), pagination keyset
  sans doublon ni trou, snapshot `insta` des statistiques.
- `./x.sh shots arp all` et `./x.sh shots arp-range all` verts aux 4 largeurs, captures relues.
