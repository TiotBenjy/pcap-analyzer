# Ethernet

Tâche ROADMAP P5.4 (vague 5.A). Constructeurs : ADR-031. Filtre temporel : ADR-030.

## Référence

`docs/reference/private/ethernet.png` (non publiée) : bulles « Devices manufacturers » (une bulle par
constructeur, plus « Broadcast », « IPv6 Multicast (RFC 2464) », « Other »), puis un tableau « Source
Address » -> « Target Address » : une ligne par adresse source, ses destinations empilées dans la cellule,
chacune suivie du constructeur entre parenthèses. Bouton flottant « To Details ».

## But

Répondre à « quels équipements parlent sur le lien, de quels constructeurs, à qui, dans quels VLAN et avec
quels protocoles de couche 2 ? » : inventaire des adresses MAC (constructeur, adresse aléatoire ou
administrée localement, diffusion, multicast), volumes, paires source -> destination, EtherTypes (IPv4, ARP,
IPv6, LLDP, 802.3/LLC...) et VLAN 802.1Q / Q-in-Q.

## Données

### Analyseur `ethernet` (`crates/netsift-analyze/src/ethernet.rs`)

- Trames des captures Ethernet et Linux cooked (SLL, SLL2 : adresse source seule) ; les trames 802.11
  relèvent de l'onglet WiFi, les captures raw IP et loopback n'ont pas d'adresse MAC.
- Agrégats bornés par shard, jamais une ligne par trame, vidés en deltas additifs (carte pleine à
  16 384 entrées, une heure de temps paquet, fin) comme `connections` : coût d'écriture proportionnel au
  nombre d'adresses et de paires, pas au nombre de trames (quelques hachages par trame dans le shard).
- Par adresse : trames et octets émis et reçus, première et dernière trame, piles VLAN (16 au plus) ;
  constructeur IEEE résolu au vidage (`netsift_analyze::oui`, ADR-031) et classe d'après les bits de
  l'adresse (unicast / multicast / diffusion, administrée localement, groupe connu : multicast IPv4
  `01:00:5e`, IPv6 `33:33`, réservé 802.1 `01:80:c2:00:00:0x`).
- Par paire orientée (source -> destination) : trames, octets, dates, EtherTypes et piles VLAN (16 au plus).
- Par EtherType : clé `0x0600-0xffff` (EtherType), `0-255` (DSAP d'un en-tête 802.2 LLC sans EtherType,
  trames 802.3 : spanning tree, NetBIOS...), `-1` (en-tête de liaison tronqué).
- Par pile VLAN (`10`, `100.20` = étiquette de service 100, client 20) : trames, octets, dates, TPID de
  l'étiquette externe (`0x8100`, `0x88a8`, `0x9100`).
- Un datagramme IP réassemblé compte pour une trame (longueur filaire de tous ses fragments), comme la
  série temporelle de `core`.

### Tables (migration `1100_ethernet.sql`, plage 1100-1199)

`eth_macs` (clé : adresse), `eth_pairs` (clé : source, destination), `eth_types`, `eth_vlans` ; upserts
additifs et commutatifs (`crates/netsift-store/src/ethernet.rs`). Index secondaires différés à la fin de
l'import (ADR-023) : tris de la liste des adresses (trames, octets, dates), barres des constructeurs
(`kind, local, vendor, first_ts, last_ts`), tris et filtre par destination des paires. Pas d'étape de fin
d'import : les tables sont petites (une ligne par adresse ou paire) et lues directement.

### API (`crates/netsift-api/src/ethernet.rs`)

| Route | Réponse |
|---|---|
| `GET /sessions/{id}/ethernet/stats` | compteurs (adresses, unicast, locales, groupe, constructeurs, paires, VLAN, trames, octets, trames étiquetées), 12 barres de constructeurs + reste, EtherTypes (64 au plus), VLAN (200 au plus) |
| `GET /sessions/{id}/ethernet/macs` | page keyset d'adresses ; `sort` = `frames` (défaut), `bytes`, `first_seen`, `last_seen`, `mac` ; filtres `q` (adresse sous toute notation `08:00:27`, `08-00-27`, `080027`, ou nom du constructeur), `class` = `unicast` / `local` / `group`, `vendor` (nom, `~local`, `~unknown`), `vlan` |
| `GET /sessions/{id}/ethernet/pairs` | page keyset de paires ; `sort` = `frames` (défaut), `bytes`, `first_seen`, `last_seen` ; filtres `q` (adresses ou constructeurs des deux bouts), `mac` (source ou destination), `vlan`, `ethertype` (`0x0800`, `2048`, `0x42` pour un DSAP) |

Les noms usuels des EtherTypes et des SAP LLC sont donnés par l'API (`IPv4`, `LLDP`, `Spanning tree`...),
en anglais : ce sont des noms de protocoles. Compteur de module (Vue d'ensemble, navigation) : nombre
d'adresses (`eth_macs`).

### Filtre temporel

Toutes les routes acceptent `from_us` / `to_us`. Les tables sont repliées sans répartition dans le temps :
on applique la règle d'ADR-030 « chevauche la plage, compteurs de session ». Une adresse, une paire, un
EtherType ou un VLAN est retenu si `[first_ts, last_ts]` chevauche la plage ; ses trames et octets restent
ceux de la session et l'en-tête de ces colonnes porte la mention « session entière » sous plage ; les
compteurs de lignes (adresses, constructeurs, paires, VLAN) suivent la plage.

Des agrégats par minute (une ligne par adresse ou paire et par minute active) donneraient des volumes
exacts, mais multiplient les lignes par la durée d'activité (un LAN de 2 000 paires actives sur deux jours :
plus de 5 M lignes, contre 2 000), donc le coût du writer et des requêtes, pour une vue dont la question
est l'inventaire plus que le volume. Les volumes exacts d'une plage restent dans la Vue d'ensemble
(`timeseries`). À revoir si un besoin de volumes par adresse et par plage apparaît (Hosts, P5.12).

## Mise en page

1. En-tête de page : titre, nom de la session, compteur d'adresses.
2. Rangée de `StatCard` : adresses MAC (sous-titre : unicast / groupe), constructeurs, adresses locales
   (aléatoires possibles), paires, VLAN.
3. Grille `minmax(320px, 1fr)` de deux cartes :
   - « Constructeurs » : `BarList` des adresses unicast par constructeur (12 + « Autres »), lignes
     « Administrées localement » et « Constructeur inconnu » estompées ; un clic filtre la liste des adresses ;
   - « EtherTypes » : `BarList` des trames par EtherType (code mono + nom), valeur = trames, détail =
     octets ; mention « session entière » dans le titre sous plage.
4. « VLAN » (si au moins une trame étiquetée) : `DataTable` (pile, type 802.1Q / 802.1ad, trames,
   octets, première et dernière trame) ; un clic filtre les adresses et les paires sur ce VLAN.
5. « Adresses MAC » : bande `filters` de la carte (`SearchInput`, `SegmentedControl` Toutes / Unicast /
   Locales / Groupe, puces des filtres actifs constructeur et VLAN avec retrait), action de tri ;
   `DataTable` en mode `cards` sous 768 px : adresse (mono, copie, badges Diffusion / Multicast / groupe
   connu / Locale), constructeur, trames émises et reçues, octets, VLAN, dernière activité ;
   « Charger plus » (keyset). Un clic sur une ligne filtre les paires sur cette adresse.
6. « Paires » : bande `filters` (`SearchInput`, puce de l'adresse choisie) ; `DataTable cards` :
   source -> destination (adresse + constructeur), trames, octets, EtherTypes, VLAN, dernière activité ;
   « Charger plus ».

Par largeur : 375 px une colonne, cartes empilées ; 768 px deux colonnes de cartes statistiques, tableaux
en lignes ; 1280 px et plus, grille complète. Aucune largeur fixe au-delà de 320 px.

## Améliorations par rapport à la référence

- Barres horizontales triées (valeur entière, libellé tronqué avec infobulle) au lieu des bulles ombrées.
- Diffusion, multicast et groupes connus présentés comme des classes d'adresses (badges), pas comme des
  « constructeurs » ; adresses administrées localement (machines virtuelles, adresses aléatoires des
  téléphones) signalées comme telles plutôt que rangées dans « Other ».
- Registre précisé (MA-L, MA-M, MA-S) en infobulle du constructeur.
- Volumes, dates, VLAN et EtherTypes par adresse et par paire ; tri, recherche, filtres reliés (constructeur,
  VLAN, adresse), pagination serveur au lieu d'une cellule qui empile toutes les destinations.
- Navigation interne au lieu du bouton « To Details ».

## Critères d'acceptation

- Fixture synthétique `netsift_fixtures::ethernet::ethernet_showcase` : constructeurs MA-L, MA-M et MA-S,
  adresses locales (QEMU, aléatoire), diffusion, multicast IPv4 et IPv6, groupes 802.1 (STP en 802.3/LLC,
  LLDP), VLAN 802.1Q et Q-in-Q, EtherTypes IPv4, IPv6, LLDP, expérimental ; intégrée aux sessions de
  démonstration.
- Tests : table OUI (recherche, plus long préfixe MA-L/MA-M/MA-S/IAB, adresses locales et de groupe),
  analyseur (instantané `insta`, fusion indépendante des vidages, bornes), store (fusion, filtres, tris,
  keyset, plage), API (compteurs, filtres, plage, pagination keyset, 400, instantané des statistiques),
  vue (Vitest).
- `./x.sh shots ethernet all` et `./x.sh shots ethernet-range all` : pas de débordement ni de
  chevauchement à 375, 768, 1280 et 1920 px, en anglais et en français.
- Chaque requête de la vue < 300 ms sur une session de 10 M paquets (tables à une ligne par adresse ou
  paire, index des tris).
