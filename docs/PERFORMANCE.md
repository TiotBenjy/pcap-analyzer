# Performance

Mesures de la tâche P4.2 (`perf/large-sessions`) face aux cibles de `docs/ARCHITECTURE.md`
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
  1 s après l'ouverture et clic immédiat).
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

## Suivis restants (chiffres de la dernière mesure)

1. **Affichage de l'Overview : 616 ms** (cible 500 ms), dont environ 480 ms de rendu côté navigateur à
   profiler (nombre de points, séries vides, rendu SVG d'ECharts, travail React) ; mesure à refaire
   dans WebKitGTK (desktop).
2. **Fin d'import : 44 s** sans progression : index secondaires 19 s (environ 90 index), DNS 11,5 s
   (appariement des requêtes de groupe, `dns_pairs`, reconstruction trigram, noms d'hôtes), FTS HTTP
   7,7 s (1,3 M en-têtes) ; une phase `finishing` détaillée dans `Progress` reste à faire (ADR-014).
3. **Writer pendant la lecture : 43 s d'insertions + 7 s de commits** pour 5 Go : `tls_sessions`
   (plusieurs tables par session), `conversations` (upsert avec union JSON des protocoles), `hosts`
   (0,58 M upserts pour 79 k hôtes, 0,99 M sur 20 shards : agrégats vidés plus rarement ou fusionnés
   entre shards avant le writer).
4. **`/servers` : 571 ms** : la requête des preuves classe toutes les lignes de `server_evidence` par
   rôle (fonctions de fenêtre, jointure `e`/`r` sans index) ; rang à précalculer pour le cas sans filtre
   de catégorie, ou index temporaire.
5. **`/connections?category=public` : 483 ms** et **`/open-ports?category=public` : 343 ms** : le
   comptage parcourt les 677 k conversations (ou les 337 k ports) avec deux sondes par ligne ; comptes
   par paire de catégories précalculés, ou total estimé au-delà d'un seuil (`total_estimate`).
6. **`/http/transactions?q=news` : 343 ms** (212 avant) : le plan part maintenant de l'index trigram
   reconstruit, puis trie les 12 k correspondances ; à comparer avec un parcours par date et sonde
   (`+t.id IN`), et `PRAGMA mmap_size` sur les connexions de lecture (chaque requête ouvre une connexion
   à cache vide ; risque de `SIGBUS` si le fichier change de taille sous l'application).
7. Requêtes entre 150 et 300 ms : `/connections/stats` 286, `/connections?from=` 269, `/dns/messages?q=ab`
   268 (recherche de moins de trois caractères par `LIKE`), `/dns/stats` 265 (compteurs par parcours de
   `dns_messages`), `/open-ports/stats?category=public` 293, `/connections?protocol=dns` 194,
   `/http/headers?q=curl` 200, `/tls/stats` 174, `/http/stats` 172.
8. Non traités, sans mesure qui les justifie : double décodage (décodeur puis table de flux : 2,8 s de
   CPU pour tout l'import, 3 %), index d'offsets pour l'export d'un fichier unique, percentiles de
   latence DNS par `OFFSET` (partie des 265 ms de `/dns/stats`), `paths()` des identifiants (58 ms).
