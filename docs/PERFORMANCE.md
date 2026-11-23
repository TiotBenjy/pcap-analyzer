# Performance

Mesures des tâches P4.2 (`perf/large-sessions`) puis P4.8 (`perf/followups`, section
« Suite P4.8 ») face aux cibles de `docs/ARCHITECTURE.md`
(section « Performance » et règle « toute requête d'une vue < 300 ms sur 10 M paquets »).

## Outillage

```
./x.sh bench                  # génère le jeu (s'il manque), importe, chronomètre les vues
./x.sh bench gen|ingest|queries
BENCH_SIZE=300M ./x.sh bench  # jeu réduit pour itérer vite (un seul jeu gardé à la fois)
BENCH_ONLY=dns ./x.sh bench queries   # une vue (nom de vue ou fragment de chemin)
```

- **Jeu de données** : `netsift-fixtures big --size 5G --chunk 500M --hours 168`
  (`crates/netsift-fixtures/src/mix.rs`), 11 chunks dumpcap pcapng dans `captures/bench/mix-5G/`,
  ignoré par git. Trafic mixte synthétique et déterministe sur 7 jours : recherches DNS (45 % des
  échanges), poignées de main TLS 1.2/1.3 (20 %), transactions HTTP (15 %, dont 1,2 % d'images),
  téléchargements de 20 Ko à 3 Mo acquittés tous les deux segments (0,8 %, la majorité des octets),
  NTP, SNMP, NBNS et annonces SMB (6 %), connexions FTP/POP3/HTTP Basic (2 %), connexions TCP sans
  données (8 %) ; 1 000 postes, 200 000 serveurs publics à popularité log-uniforme, 5 % d'IPv6.
  Résultat : 8 894 735 paquets, 5,0 Go de trames.
- **Import** : `netsift bench ingest` (feature `bench` de `netsift-cli`, jamais dans une release)
  importe comme `netsift ingest`, échantillonne le temps CPU de chaque thread
  (`/proc/self/task/*/stat`, toutes les 50 ms) et lit le pic de mémoire résidente (`VmHWM` de
  `/proc/self/status`) ; le writer chronomètre ses insertions par type d'enregistrement et ses
  commits (`WriterStats::insert_time`, `commit_time`), le rapport de fin d'import chaque étape
  (`FinalizeReport::timings`). « 4 cœurs » = `taskset -c 0-3` et 2 shards (cœurs - 2).
- **Requêtes** : `netsift bench queries` appelle chaque endpoint de vue par le routeur axum, en
  mémoire (sans socket), sur la session importée sur 4 cœurs : un appel non chronométré, puis 9
  chronométrés ; médiane, p95 et maximum. Les identifiants (curseurs, transaction, session TLS,
  certificat, identifiant, hôte) sont lus dans les listes.
- **Affichage** : `./x.sh bench ui` sert la session avec l'API release (`netsift serve --read-only`)
  et l'UI de production (`vite preview`) ; Playwright (`ui/tests/perf/overview.spec.ts`, projet `perf`)
  ouvre la vue Sources de la session dans un contexte neuf, clique sur « Overview » et chronomètre les
  réponses de `summary` et `timeseries`, puis le graphique dessiné et le résumé affiché (7 essais, clic
  1 s après l'ouverture et clic immédiat). Depuis P4.8, « dessiné » attend un tracé de série (chemin SVG
  de plus de 2 000 caractères) : avant, cinq chemins quelconques suffisaient, et un graphique vide
  (axes seuls) comptait comme dessiné.
- **Plans** : `netsift bench sql --data-dir <dir> "<SQL>"...` donne la médiane et l'`EXPLAIN QUERY PLAN`
  d'instructions sur une session (lecture seule, `--pragma` pour essayer un réglage).
- Rapports : `.artifacts/bench/ingest-4cpu.md`, `ingest-all.md`, `queries.md`, `ui-overview.md`.

## Machine

Intel Core Ultra 7 155H (6 cœurs P avec hyperthreading, 8 cœurs E, 2 cœurs LP E : 22 threads),
30 Gio de RAM, NVMe WD SN810, Fedora 43 (noyau 7.2), conteneur Podman, Rust 1.99.1, build
`release` (LTO thin). `taskset -c 0-3` donne 4 threads logiques sur 3 cœurs P (0, 1-2 et 3).

## Mesures initiales (2026-11-15, `03efb56`)

### Import de 5 Go sur 4 cœurs

| Mesure | Valeur | Cible |
|---|---|---|
| durée totale | 577,7 s | < 120 s |
| débit | 9,2 Mo/s | ≥ 80 Mo/s |
| lecture + analyse / fin d'import | 550,2 s / 27,5 s (DNS 13,2 s, réseau 2,9 s) | |
| pic mémoire (VmHWM) | 172 Mio | < 1,5 Gio |
| session | 1 675 Mo, 6,26 M lignes écrites | |
| paquets / flux / hôtes | 8 894 735 / 843 955 / 79 210 | |

Temps CPU par thread : writer SQLite 540,6 s (94 % de la durée), shards 31,6 s (5 %), lecteur 8,7 s,
décodeur 3,1 s. Le writer est le seul goulot : les shards attendent la place dans son canal.

Temps d'insertion par type d'enregistrement (writer) : `hosts` 171,9 s (1,28 M lignes pour
79 210 hôtes, 134 µs par ligne), `http_transactions` 95,7 s (144 k transactions, 665 µs chacune,
en-têtes compris), `flows` 34,0 s, `conversations` 29,5 s, `tls_sessions` 17,6 s,
`dns_messages` 16,4 s, `open_ports` 6,5 s, `host_traffic` 4,8 s (1,28 M lignes), `timeseries` 3,8 s ;
commits 175,1 s (1 061 transactions, 165 ms chacune).

Causes trouvées :

- `hosts` : la limite des sous-requêtes d'union JSON (`LIMIT ?8`) était un paramètre lié ; une fois
  l'instruction rendue au cache (paramètres effacés), SQLite la préparait de nouveau à chaque exécution
  (`SQLITE_STMTSTATUS_REPREPARE`) : environ 100 µs par ligne au lieu de 4 ;
- `hosts`, `host_traffic`, `open_ports` : les analyseurs `core`, `connections` et `ports` vidaient leurs
  agrégats toutes les 60 s de temps paquet ; sur une capture étalée (7 jours), une ligne par hôte et par
  minute ;
- `http_transactions` : les deux index trigram FTS5 étaient alimentés par déclencheur, et le
  `SAVEPOINT` que le writer pose autour de chaque transaction HTTP force FTS5 à écrire un segment, puis
  à les fusionner, à chaque transaction ;
- commits : une partie de leur temps vient de ces mêmes écritures FTS5.

Sur tous les cœurs (20 shards), le même jeu réduit à 300 Mo donnait 10,9 Mo/s contre 11,9 Mo/s sur
4 cœurs : le nombre de cœurs n'y change rien tant que le writer sature.

### Requêtes de vue (session de 8,9 M paquets)

18 requêtes sur 76 dépassent 300 ms (médiane de 9 appels, connexion SQLite neuve à chaque appel, comme
l'API) :

| Vue | Requête | Médiane (ms) |
|---|---|---|
| overview | `/summary` | 405 |
| overview | `/timeseries?points=500` (et variantes) | 276 à 279 |
| connections | `/connections?limit=50` (première page, toutes les clés de tri) | 384 à 388 |
| connections | `?from=<hôte>` / `?to=<serveur>` / `?category=public` | 621 / 1 487 / 1 233 |
| connections | `/connections/stats` | 406 |
| open-ports | `?q=ssh` / `?category=public` / `/stats?category=public` | 617 / 479 / 724 |
| open-ports | `/open-ports` / `/stats` | 177 / 248 |
| dns | `/dns/messages?q=ab` (recherche courte, `LIKE`) | 320 |
| dns | `/dns/stats` / `/dns/messages` (chaque page) | 266 / 112 |
| http | `/http/stats` | 404 |
| http | `/http/transactions?method=POST` (aucune correspondance) | 423 |
| http | `/http/transactions` (première page) | 184 |
| http-headers | `/http/headers?name=user-agent` / `?q=curl` | 450 / 568 |
| tls | `/tls/stats` | 402 |
| servers | `/servers` | 1 094 |
| network | `/network/graph` (mode hôtes) | 255 |

Les pages suivantes (curseur) restent sous 5 ms, comme les détails (transaction, session TLS,
certificat, identifiant, nœud), SMB, Credentials, Pictures et le graphe par pays.

## Corrections (par ordre d'impact sur l'import, puis sur les vues)

Effet mesuré à chaque étape sur le même jeu (import sur 4 cœurs) :

| Étape | Commits | Import 5 Go | Effet principal |
|---|---|---|---|
| départ | `03efb56` | 577,7 s | writer 94 %, `hosts` 172 s, HTTP 96 s, commits 175 s |
| instruction d'hôte jamais préparée de nouveau ; agrégats vidés toutes les heures ; index FTS HTTP en fin d'import ; séries cumulées | `f46c1c4`, `901ad77`, `3a9ce12` | 269,4 s | `hosts` 172 → 10,5 s (1,28 M → 0,58 M lignes), HTTP 96 → 24 s, commits 175 → 104 s |
| réglages du writer (cache 256 Mio, WAL 128 Mio, transactions 200 000 lignes ou 1 s) | `823145d` | 190,7 s | commits 104 → 45 s (466 → 117 transactions) |
| index secondaires construits en fin d'import (étape `indexes`) | `823145d` | 95,8 s | insertions 118 → 43 s, commits 45 → 7 s ; +20 s d'index en fin d'import |

Vues (session de 8,9 M paquets) :

- résumé : totaux lus dans `meta` (`3a9ce12`), rôles de serveurs matérialisés (`0d8604c`) : 405 → 22 ms ;
- série temporelle : tables par minute et par heure (`3a9ce12`), bornes lues aux deux bouts de la clé
  (`470acfb`) : 276 → 91 → 39 ms ;
- filtres : seules les conditions actives sont composées (`f72f94f`), sous-requêtes sur `hosts` au lieu
  de jointures, en-têtes HTTP par `EXISTS` corrélé, codes HTTP sur leur colonne indexée ;
- agrégats : index couvrants TLS et comptages par index (`470acfb`), statuts HTTP par `status_key`.

## Mesures après corrections (2026-11-15, `fa6ae6f`)

### Import

| Mesure | Avant | Après | Cible |
|---|---|---|---|
| durée totale, 4 cœurs | 577,7 s | **94,9 s** | < 120 s |
| débit total, 4 cœurs | 9,2 Mo/s | **55,9 Mo/s** | |
| débit pendant la lecture, 4 cœurs | 9,6 Mo/s | **104,2 Mo/s** | ≥ 80 Mo/s |
| fin d'import | 27,5 s | 44,0 s (index 19,3 s, DNS 11,5 s, FTS HTTP 7,7 s, réseau 2,6 s) | |
| pic mémoire (VmHWM), 4 cœurs | 172 Mio | 375 Mio | < 1,5 Gio |
| tous les cœurs (20 shards) | non mesuré à 5 Go | 101,4 s, 93 Mo/s en lecture, 438 Mio | |
| taille de la session | 1 675 Mo | 1 643 Mo | |

Disque et mémoire hors du pic résident : la construction des index en fin d'import écrit dans le WAL
environ la taille des index (le WAL est replié dans la base à la fin de l'import), et leurs tris
passent par des fichiers temporaires (`temp_store = FILE`) ; prévoir quelques centaines de Mo de plus
que la session sur 5 Go. Deux imports simultanés (`max_imports` = 2) ont chacun leur cache de pages
de 256 Mio.

Le writer reste le goulot (95 % d'occupation, shards à 32 %). Pendant la lecture, ses insertions
prennent 43 s (`tls_sessions` 7,3 s, `conversations` 7,2 s, `http_transactions` 6,2 s, `hosts` 6,0 s,
`dns_messages` 4,6 s, `flows` 3,2 s, `open_ports` 3,1 s) et ses commits 7,2 s. Sur 20 shards, les
agrégats partiels se multiplient (0,99 M lignes `hosts` au lieu de 0,58 M) : l'import est un peu plus
lent qu'avec 2 shards.

Le débit de 80 Mo/s est atteint pendant la lecture et l'analyse, pas sur la durée totale : les étapes de
fin d'import (44 s, sans progression publiée) ramènent la moyenne à 56 Mo/s. 5 Go passent en moins de
2 minutes.

### Requêtes de vue

4 requêtes sur 76 dépassent encore 300 ms (18 avant). Toutes celles qui changent de plus de 10 ms :

| Vue | Requête | Avant (ms) | Après (ms) |
|---|---|---|---|
| overview | `/summary` | 405 | 20 |
| overview | `/timeseries?points=500` / `points=2000` | 276 / 279 | 39 / 43 |
| connections | `/connections?limit=50` (première page) | 388 | 4 |
| connections | `?from=<hôte>` / `?to=<serveur>` | 621 / 1 487 | 269 / 102 |
| connections | `?category=public` | 1 233 | **483** |
| connections | `?protocol=dns` | 157 | 194 |
| connections | `/connections/stats` | 406 | 286 |
| open-ports | `/open-ports` / `?port=443` / `?q=ssh` | 177 / 99 / 617 | 82 / 55 / 189 |
| open-ports | `?category=public` | 479 | **343** |
| open-ports | `/stats` / `/stats?category=public` | 248 / 724 | 123 / 293 |
| dns | `/dns/messages` (chaque page) / `?errors=true` / `?protocols=nbns` | 112 / 151 / 109 | 5 / 110 / 51 |
| dns | `?q=ab` | 320 | 268 |
| http | `/http/stats` | 404 | 172 |
| http | `/http/transactions` (première page) / `?status=404` / `?method=POST` | 184 / 208 / 423 | 4 / 5 / 2 |
| http | `?q=news` | 212 | **343** |
| http-headers | `/http/headers` / `?name=user-agent` / `?q=curl` | 184 / 450 / 568 | 4 / 78 / 200 |
| tls | `/tls/stats` | 402 | 174 |
| servers | `/servers` / `?role=dns` | 1 094 / 197 | **571** / 8 |
| network | `/network/graph` / `?protocols=https` | 255 / 34 | 21 / 13 |

Une session importée avant ces changements reçoit les migrations et les étapes de fin d'import à sa
première ouverture (ADR-013, ADR-014) : sur la session de départ, les séries cumulées et les index de
recherche HTTP ont été construits par cette ouverture, sans erreur.

### Affichage de l'Overview (Chromium sans GPU, conteneur)

| Affichage de l'Overview | Médiane (ms) | p95 (ms) |
|---|---|---|
| clic 1 s après l'ouverture : réponses de `summary` et `timeseries` | 129 | 150 |
| clic 1 s après l'ouverture : graphique dessiné, résumé affiché | 616 | 659 |
| clic immédiat : réponses | 156 | 215 |
| clic immédiat : graphique dessiné, résumé affiché | 642 | 701 |

Avant les séries cumulées et la correction des bornes, le graphique était dessiné en 697 ms et les
réponses arrivaient en 225 ms. La cible de 500 ms n'est pas atteinte : les réponses arrivent en
130 à 160 ms, puis environ 480 ms passent dans le navigateur (vue Overview, ECharts SVG de 13 séries
empilées de 500 points). Précharger le chunk ECharts à l'ouverture de la session a été essayé et
retiré : moins de 30 ms de gain.

## Suite P4.8 (2026-11-15, `perf/followups`)

Même machine, même jeu (`captures/bench/mix-5G`, régénéré à l'identique : 8 894 735 paquets), mêmes
commandes : `BENCH_FULL=0 ./x.sh bench ingest`, `./x.sh bench queries`, `./x.sh bench ui`. Avant :
`918ea73` (fin de P4.2) ; après : `f13fc22`. Plans examinés avec `netsift bench sql`, rendu de l'Overview
profilé par le profileur CPU de Chromium (CDP) et des repères posés dans la page.

### Requêtes de vue

Plus aucune requête au-dessus de 300 ms (4 avant). Toutes celles qui changent de plus de 10 ms :

| Vue | Requête | Avant (ms) | Après (ms) | Correctif |
|---|---|---|---|---|
| servers | `/servers` | 588 | **7** | rang stocké (`server_ranks`) |
| connections | `?category=public` | 478 | **4** | comptes stockés (`conversation_categories`), plan choisi par sélectivité |
| open-ports | `?category=public` | 341 | **44** | ports par hôte stockés (`open_port_hosts`) |
| open-ports | `/open-ports` (sans filtre) | 82 | 39 | idem |
| http | `/http/transactions?q=news` | 337 | **132** | hôtes joints après le choix de la page |
| connections | `/connections/stats` | 288 | 148 | un seul passage pour les deux sens |

Correctifs, par effet mesuré :

- **`/servers`** (`fdbf13f`) : la requête classait à chaque lecture toutes les lignes de `server_evidence`
  (fonctions de fenêtre, index automatique sur la CTE). L'étape `servers` (version 3) stocke le rang de
  chaque serveur dans son rôle et le nombre de serveurs du rôle (`server_ranks`, migration 0802) ; sans
  filtre de catégorie, la vue lit les `limit` premiers rangs de tous les rôles par l'index des rangs, puis leurs
  preuves par index. Avec un filtre de catégorie (les rangs changent), le classement à la lecture reste.
- **`/connections?category=`** (`fdbf13f`) : le comptage sondait deux listes d'hôtes pour chacune des
  677 000 conversations (330 ms), la page en construisait deux (140 ms). L'étape `connections` stocke le
  nombre de conversations par paire de catégories de leurs extrémités (`conversation_categories`, 0402,
  quelques dizaines de lignes) : le total d'un filtre de catégorie seul y est lu. Ces comptes choisissent
  aussi le plan de la page : sondage de `hosts` par clé primaire dans l'ordre de tri quand les catégories
  couvrent beaucoup de conversations (page en 0,3 ms pour `public`), recherche par index des conversations
  de leurs hôtes sinon. Avec le plan unique d'avant, une catégorie rare (`multicast`) parcourait toute la
  table pour une page vide (750 ms) ; avec le mauvais des deux nouveaux plans, 1,3 à 2,7 s.
- **`/open-ports?category=`** (`fdbf13f`) : la page groupait tous les ports ouverts par hôte puis triait
  (125 ms) et le comptage sondait la liste des hôtes de la catégorie (110 ms). L'étape `ports` stocke le
  nombre de ports et la catégorie de chaque hôte (`open_port_hosts`, 0402) : la page parcourt l'index
  `(ports, ip, category)` dans l'ordre et s'arrête à sa taille, le comptage lit l'index de catégorie. Le
  reste (40 ms) compte les clients des ports de la page dans `flows`.
- **`/http/transactions?q=`** (`8746c37`) : 12 000 transactions contiennent « news » ; la liste joignait
  `hosts` pour les deux extrémités de chacune avant de trier (190 ms). La page est maintenant choisie sur
  `http_transactions` seule, puis ses lignes sont lues avec leurs hôtes par identifiant. Restent le
  comptage (56 ms, une recherche par clé primaire par correspondance) et le tri des correspondances.
- **`/connections/stats`** (`4402b98`) : un seul `GROUP BY` sur `host_traffic` pour les deux sens.

L'ouverture de la session importée avant ces changements (migrations 0402 et 0802, étapes `servers` v3,
`connections` et `ports` rejouées, ADR-013 et ADR-014) a pris 2,6 s.

### Fin d'import et progression

| Mesure | Avant | Après |
|---|---|---|
| durée totale, 4 cœurs | 94,0 s | 93,8 s |
| lecture + analyse | 49,8 s | 49,3 s |
| fin d'import | 44,2 s, sans progression | 44,5 s, phase `finalizing` publiée |
| étapes | index 18,8 s, DNS 12,0 s, FTS HTTP 7,8 s, réseau 2,7 s, servers 0,7 s, séries 0,4 s, objets 0,1 s | index 18,5 s, DNS 11,9 s, FTS HTTP 7,6 s, réseau 2,7 s, servers 0,9 s, connections 0,6 s, séries 0,4 s, ports 0,2 s, objets 0,1 s |
| pic mémoire (VmHWM) | 377 Mio | 399 Mio |
| taille de la session | 1 643 Mo | 1 651 Mo |

Les trois étapes ajoutées coûtent 1 s en tout (rang des serveurs 0,2 s, comptes par catégorie 0,6 s,
ports par hôte 0,2 s). La fin d'import publie maintenant sa progression (`0965af1`) : le writer note
l'étape en cours et le nombre d'étapes faites (`FinalizeWatch`), le moteur les publie à chaque
intervalle dans une phase `Phase::Finalizing` (et toujours une fois à leur fin), l'événement SSE porte
`phase = finalizing`, `step`, `steps_done` et `steps_total`, et l'assistant d'import comme l'indicateur
de l'en-tête affichent l'étape et « Étape n sur N » (en et fr). La durée des étapes n'a pas été réduite
(voir les suivis).

### Affichage de l'Overview (Chromium sans GPU, conteneur)

Avec le critère « tracé de série dessiné » (le critère de P4.2 donnait le même jour 623 et 632 ms avant) :

| Affichage de l'Overview | Avant (`918ea73`) | Chargement hors React | Après (`f13fc22`) |
|---|---|---|---|
| clic 1 s après l'ouverture : réponses | 142 | 136 | 134 |
| clic 1 s après l'ouverture : graphique dessiné, résumé affiché | 635 | 325 | **298** |
| clic immédiat : réponses | 158 | 179 | 155 |
| clic immédiat : graphique dessiné, résumé affiché | 645 | 370 | **319** |

(médianes en ms de 7 essais ; p95 après : 316 et 330 ms). Ce que le profil a montré : sur les 480 ms
passées dans le navigateur, environ 240 ms d'attente sans calcul, puis 130 ms de `setOption` d'ECharts,
30 ms de redimensionnement, le reste dans React et dans les requêtes de Playwright.

- **Attente** (`f13fc22`) : le moteur de rendu ECharts était un composant `React.lazy` monté à l'arrivée
  des données ; il suspendait alors, et React ne révèle un contenu suspendu qu'au moins 300 ms après
  l'apparition de son repli (« fallback throttling »). Le moteur est maintenant chargé hors de React, au
  repos dès qu'une session s'ouvre et au montage d'un graphique (en parallèle de ses données), puis rendu
  directement : 635 → 325 ms.
- **Rendu** (`f13fc22`) : la première notification du `ResizeObserver`, à la même taille, redessinait
  toutes les séries ; les valeurs par défaut du thème étaient dessinées seules avant l'option (désormais
  `lazyUpdate`) ; le côté de la légende est lu sur l'élément à la création : 325 → 298 ms.
- Essayés et écartés : moins de points (250 au lieu de 500 : `setOption` inchangé, son coût est fixe sur
  un premier rendu à froid) ; un `dataset` ECharts commun aux séries à la place d'un tableau de points
  par série (plus rapide de 35 ms, mais les séries n'étaient plus tracées : l'ancien critère du banc le
  comptait pourtant comme dessiné, d'où le critère plus strict).

Le renderer SVG est gardé, l'aspect est inchangé (`./x.sh shots` en `en` et `fr`, relues).

## Filtre temporel (P5.2a, 2026-11-22, `feat/time-filter`)

Même machine, jeu régénéré à l'identique (`./x.sh bench ingest`, 8 894 735 paquets sur 7 jours), puis
`./x.sh bench queries` : les routes filtrées (`docs/specs/time-filter.md`, ADR-030) sont mesurées sous des
plages de 1 h, 24 h et 6 jours centrées sur la session (`{r1h}`, `{r24h}`, `{r6d}` de `netsift bench queries`).

- **Première ouverture** de la session importée avant P5.2 (migrations 0003, 0101, 0202 et 0302 : index
  couvrants terminés par l'horodatage, index partiel des flux longs, heure des 992 434 lignes d'en-têtes HTTP) :
  7,2 s, une fois.
- **Aucune requête au-dessus de 300 ms**, sans plage comme sous plage. Sous plage (médianes en ms) :

| Requête | 1 h | 24 h | 6 j |
|---|---|---|---|
| `/summary` (objet `range`, compteurs de modules) | 101 | 131 | 260 |
| `/timeseries?points=500` | 4 | 9 | 34 |
| `/dns/stats` | 35 | 149 | 271 |
| `/dns/pairs` / `/dns/servers` / `/dns/messages` | 28 / 17 / 5 | 38 / 29 / 7 | 87 / 74 / 19 |
| `/http/stats` | 117 | 192 | 293 |
| `/http/transactions` (temps / taille) | 4 / 5 | 6 / 9 | 9 / 15 |
| `/http/headers/stats` / `/http/headers` | 100 / 4 | 115 / 5 | 162 / 9 |
| `/tls/stats` / `/tls/sessions` / `/tls/certificates` | 14 / 3 / 195 | 115 / 5 / 224 | 266 / 14 / 120 |
| `/smb/stats` / `/smb/announces` | 3 / 3 | 3 / 4 | 3 / 3 |
| `/credentials` / `stats` / `paths` | 21 / 41 / 44 | 26 / 50 / 60 | 35 / 74 / 119 |
| `/objects/stats` / `/objects` | 3 / 4 | 3 / 10 | 3 / 41 |

- Ce qui a compté : les agrégats lisent un **index couvrant terminé par l'horodatage** (jamais les lignes,
  `+ts` dans la condition) pour une plage large, l'index de l'horodatage pour une plage étroite (plan choisi
  par deux comptages d'index, `range::PointSql`) ; paires DNS par sondage `(pair_id, ts)` de chaque paire
  (le regroupement des messages coûtait 1,6 s à 6 jours) ; heure dénormalisée des lignes d'en-têtes (811 ms
  -> 120 ms pour les noms d'en-têtes à 6 jours) ; certificats d'une plage large sondés par certificat.
- Effet de bord sans plage : `/dns/stats` 265 -> 155 ms (totaux et protocoles en un passage, percentiles de
  latence en une lecture de l'index).
- Corrigé pendant la mesure : un paramètre nommé de la plage écrit avant le `?1` d'une instruction en prenait
  l'indice et remplaçait sa `LIMIT` (réponses de 1 à 3 Mo sur le banc) ; la plage utilise désormais les
  indices réservés `?98` / `?99`.
- Hors périmètre (P5.2b) : Connections, Open Ports, Servers et Network sous plage (regroupement des flux :
  0,3 s à 24 h, 1,7 s à 6 jours pour les seules conversations, mesuré dans la spec).

## SSDP (P5.5, 2026-11-22, `feat/ssdp`)

- Requêtes de la vue sur 500 000 messages de 2 000 appareils (`ssdp::tests::timings`, ignoré, mode
  release, store seul) : `/ssdp/stats` 182 ms sur la session, 8 ms sur 1 h, 194 ms sur la moitié ; page de
  messages 2 à 13 ms ; filtre de type avec recherche 72 ms au pire ; page d'appareils 11 ms. Chaque agrégat
  lit un index couvrant terminé par `ts`, le coût est donc linéaire en nombre de messages de la plage :
  environ 3 à 4 s pour `/ssdp/stats` sur 10 M messages SSDP, ce qu'une capture d'attaque par réflexion
  SSDP peut contenir (au-delà des 300 ms ; agrégats précalculés à prévoir si le cas se présente).
- Stockage : un enregistrement par datagramme avec son texte brut borné à 2 048 octets, soit au plus
  environ 2 Kio par message sur disque, plus les index (300 à 400 octets de brut pour un message courant) ;
  10 M messages de taille maximale pèseraient environ 20 Go.

## FTP (P5.8, 2026-11-23, `feat/ftp`)

- Requêtes de la vue sur 100 000 sessions, 400 000 transferts et 2 M lignes de transcription
  (`ftp::tests::timings`, ignoré, mode release, store seul) : `/ftp/stats` 194 ms sur la session, 7 ms sur
  1 h, 212 ms sur la moitié ; page de sessions avec son total 9 à 15 ms, avec recherche et filtre de
  connexion 12 à 66 ms ; page de transferts filtrée par sens 1 à 8 ms ; détail d'une session (transcription
  de 2 000 lignes au plus et transferts) 1 ms. Les compteurs de sessions (`count(DISTINCT ...)` sur les
  sessions qui chevauchent la plage) sont linéaires en sessions : environ 2 s pour 1 M de sessions FTP,
  au-delà des 300 ms (agrégats précalculés à prévoir si le cas se présente).
- `/objects` sous plage (Pictures, Documents) avec les transferts FTP (`ftp::tests::objects_timings`,
  ignoré, mode release, 200 000 images HTTP et 50 000 fichiers FTP) : la seconde condition `EXISTS` sur
  `ftp_transfers` coûtait jusqu'à +60 % sur la page et +100 % sur les statistiques (moitié de la session :
  page et total 291 ms, statistiques 1,2 s, contre 197 ms et 600 ms avec HTTP seul). Les comptes et les
  statistiques réunissent désormais les empreintes de la plage une fois (`o.sha256 IN (... UNION ALL
  ...)`, index sur `ts`), la page garde les `EXISTS` corrélés qui s'arrêtent avec elle : page et total
  40 ms sur la session, 110 ms sur 1 h, 178 ms sur la moitié ; statistiques 133 ms, 17 ms et 497 ms
  (au-dessus des 300 ms sur une plage large, déjà le cas avant FTP avec 600 ms).
- Import : une ligne `ftp_lines` par commande ou réponse (au plus 2 000 et 256 Kio par session), une ligne
  par transfert ; le contenu d'un transfert est tenu en mémoire jusqu'à sa fin (budget de 128 Mio partagé
  par les shards, ADR-032), écrit une fois dans `blobs/` s'il est complet.

## Filtre temporel (P5.2b, 2026-11-22, `feat/time-filter-aggregates`)

Même machine, jeu régénéré à l'identique (8 894 735 paquets sur 7 jours, 843 955 flux, 676 978 conversations),
`./x.sh bench queries` (9 appels chronométrés, plus le premier appel compté à part, colonne « 1re ») sous les
plages `{r1h}`, `{r24h}`, `{r6d}`. Le banc supprime d'abord `sessions/<id>/ranges/` : la première requête d'une
plage (`/connections?limit=50`, première route agrégée mesurée) construit sa base. Mesure finale après revue,
machine presque au repos (charge moyenne de 3 à 6 sur 22 threads).

| Plage | Flux actifs | Construction (1re requête) | Requêtes suivantes des vues agrégées (médianes, ms) |
|---|---|---|---|
| 1 h | 4 692 | 0,6 s | `/connections` 6, `stats` 9, `top` 5, `/open-ports` 8, `stats` 23, `/servers` 8, `/network/graph` 10, `node` 5 |
| 24 h | 122 857 | 2,4 s | `/connections` 6, `stats` 33, `top` 5, `/open-ports` 8, `stats` 39, `/servers` 9, `/network/graph` 15, `node` 6 |
| 6 j | 726 364 | 11,0 à 11,6 s | `/connections` 7-8, `stats` 130, `top` 5, `/open-ports` 8, `stats` 106, `/servers` 11, `/network/graph` 23, `node` 7 |

- **Overview** : `/summary` n'attend plus la base d'une plage (compteurs des vues agrégées `pending`, servis
  par `/modules`) : 103 / 136 / 267 ms sous plage, premier appel compris (108 / 128 / 259 ms), soit les temps
  de P5.2a (101 / 131 / 260 ms). Chaque zoom de l'Overview répond donc comme avant P5.2b ; seules les cartes
  des cinq vues agrégées attendent la construction.
- **Mémoire** : pic de mémoire résidente du processus (`VmHWM`, mesuré par le banc) de 223 Mio après la
  construction de 6 jours (13 Mio avant les plages). Un premier essai avec `mmap_size` de 1 Gio sur la session
  attachée montait à 819 Mio (pages du fichier comptées dans la mémoire résidente), sans gain de temps : retiré.
  Deux constructions simultanées (`MAX_BUILDS`) restent sous 500 Mio ; avec un import en cours (environ 400 Mio
  au pic sur ce banc), le total reste sous la cible de 1,5 Go : `MAX_BUILDS` n'est pas réduit pendant un import.
- La lecture des flux actifs joint chaque flux aux catégories de ses extrémités et au port ouvert atteint par
  clé primaire (mémoire bornée, revue) : environ 1,5 s de plus à 6 jours que le chargement initial de tous
  les hôtes et ports en mémoire (9,4 s mesurés sous charge avant revue).
- Répartition de la construction à 6 jours (essai instrumenté avant revue, sous charge) : copie des hôtes et
  des ports ouverts actifs 0,8 s, lecture des flux actifs et agrégation 2,0 s, insertion de 600 000
  conversations 2,4 s, leurs 7 index 1,1 s, preuves de serveurs 0,5 s, étape `network` 2,4 s. Taille des bases :
  15 Mo (1 h), 36 Mo (24 h), 122 Mo (6 jours) ; hôtes et ports ouverts actifs, copiés, font l'essentiel des
  petites.
- Ce qui a compté : agréger en Rust en une lecture des flux au lieu d'un `GROUP BY` SQL (8 s pour les seules
  conversations) ; lire toute la table des flux dans l'ordre de stockage pour une plage large plutôt que
  l'index du début (3 s de lectures ligne à ligne à 6 jours) ; catégories et clients des ports dans la même
  lecture (l'étape `connections` relancée coûtait 2 s) ; 128 Mio de cache pour la base en construction.
- Écart à l'estimation de la spec (0,3 s à 24 h, 2 à 5 s à 6 jours) : 2,4 s et 11 s. Suivis : tables du graphe
  construites à la première requête Network seulement (environ 2,4 s épargnées aux autres vues ; non simple,
  le fichier publié est immuable), index des conversations construits à la demande d'un tri.
- `/dns/servers` sous plage : 173 ms (24 h) et 1,39 s (6 jours) sur la branche, **identique sur main**
  (189 ms et 1,39 s, même jeu, même machine au repos) : régression de P5.2a indépendante de cette tâche (74 ms
  notés à sa fusion), à reprendre à part.

## Suivis restants (chiffres de la dernière mesure)

1. **Fin d'import : 44,5 s**, publiée mais pas réduite : index secondaires 18,5 s (environ 90 index, un
   tri chacun), DNS 11,9 s (appariement des requêtes de groupe, `dns_pairs`, reconstruction trigram, noms
   d'hôtes ; à découper avec un chronométrage par sous-étape), FTS HTTP 7,6 s (1,3 M en-têtes), réseau
   2,7 s. Pistes : supprimer les index qu'aucune requête n'utilise, construire les index d'une table en
   un parcours (non disponible dans SQLite), ne reconstruire que l'index trigram utile.
2. **Writer pendant la lecture : 41 s d'insertions + 5 s de commits** : `tls_sessions` 7,4 s,
   `conversations` 7,2 s (upsert avec union JSON des protocoles), `http_transactions` 6,3 s, `hosts` 5,9 s
   (0,58 M upserts pour 79 k hôtes). Non traité dans P4.8.
3. Requêtes entre 150 et 300 ms : `/open-ports/stats?category=public` 289 (comptes par (catégorie,
   transport, port) à stocker), `/dns/messages?q=ab` 258 (recherche de moins de trois caractères par
   `LIKE`), `/dns/stats` 251 (compteurs par parcours de `dns_messages`), `/connections?from=` 247 (sous-chaîne
   d'adresse ou de nom : parcours), `/http/headers?q=curl` 199, `/connections?protocol=dns` 181,
   `/open-ports?q=ssh` 181, `/tls/stats` 173, `/http/stats` 170.
4. Affichage de l'Overview : 298 ms dans Chromium sans GPU (cible 500 ms atteinte) ; `setOption` à froid
   (environ 90 ms, indépendant du nombre de points) reste le plus gros poste ; mesure à refaire dans
   WebKitGTK (desktop).
5. Non traités, sans mesure qui les justifie : double décodage (décodeur puis table de flux : 2,8 s de
   CPU pour tout l'import, 3 %), index d'offsets pour l'export d'un fichier unique, percentiles de
   latence DNS par `OFFSET` (partie des 251 ms de `/dns/stats`), `paths()` des identifiants (58 ms).
