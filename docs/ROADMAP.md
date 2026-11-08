# Feuille de route

Chaque tâche indique sa **branche** (= nom du worktree), ses dépendances et peut être confiée
à un agent `implementer`. Les tâches d'une même « vague » sont indépendantes et se lancent
en parallèle (skill `parallel`). Seul l'orchestrateur coche les cases, sur `main`, après fusion.

Légende : `[ ]` à faire, `[~]` en cours (branche ouverte), `[x]` fusionné dans `main`.

---

## Phase 0 — Amorçage (séquentiel, un seul agent)

Objectif : un squelette qui compile, se teste, se lance en local et se construit en CI.

- [x] **P0.1** `chore/toolchain` — Construire l'image (`./x.sh image`), vérifier `./x.sh cargo --version`,
      `./x.sh npm --version`, `./x.sh shell`. Corriger `docker/Dockerfile` / `x.sh` si besoin.
- [x] **P0.2** `chore/workspace` — Workspace Cargo (resolver 3, édition 2024, `[workspace.lints]` :
      `unsafe_code = "forbid"` hors desktop, `clippy::pedantic` en warn ciblé, `unwrap_used`/`expect_used`/
      `indexing_slicing`/`panic` = deny dans `netsift-dissect`), toutes les crates de `ARCHITECTURE.md`
      créées vides avec un test fumée, `exclude = [".worktrees", "fuzz"]`. `./x.sh check` vert.
- [x] **P0.3** `chore/ui-shell` — `ui/` : Vite + React + TS strict + Tailwind 4 + ESLint + Vitest + Playwright
      (version épinglée identique à `PLAYWRIGHT_VERSION` du Dockerfile). **Utiliser les versions de
      `docs/STACK_VERSIONS.md`** (combinaison testée : install + tsc + build OK). Tailwind 4 via
      `@tailwindcss/vite` + `@theme` (pas de `tailwind.config.js`). Code-splitting des vues et des graphes
      dès le départ (bundle echarts+sigma > 500 Kio sinon). AppShell + Sidebar avec toutes
      les entrées (onglets futurs inclus, désactivés), routes vides, thèmes clair/sombre, i18n en/fr,
      composants communs de base (`Card`, `Chart`, `DataTable`, `EmptyState`, `FilterBar`, `Toggle`, `Badge`).
- [x] **P0.4** `chore/dev-loop` — `netsift serve` minimal (axum, `/api/v1/health`), `./x.sh dev`
      (backend + Vite avec proxy et jeton), `./x.sh shots` avec les assertions de `UI_GUIDELINES.md`
      sur la page d'accueil. L'utilisateur peut ouvrir http://localhost:5173.
- [x] **P0.5** `chore/desktop` — `apps/desktop` Tauri 2 qui démarre l'API embarquée et affiche l'UI ;
      `./x.sh desktop` produit AppImage + .deb dans `dist/` ; icônes provisoires sobres.
- [x] **P0.6** `ci/github-actions` — Rendre `.github/workflows/ci.yml` et `release.yml` cohérents avec la
      structure réelle (chemins Tauri, cache). Vérification : pousser la branche, l'utilisateur confirme
      le statut vert dans GitHub (pas de `gh`).

Sortie de phase : `./x.sh check`, `./x.sh dev`, `./x.sh shots`, `./x.sh desktop` fonctionnent.

Suivis issus des revues de la phase 0 (à traiter dans la tâche indiquée) :

- P2.1 : progression SSE lue via `fetch` (jamais `EventSource`, qui ne peut pas envoyer `Authorization`) ;
  avant la première route mutante (`POST /sessions/import`), refuser les `Origin` hors liste et
  `Sec-Fetch-Site: cross-site` (le proxy Vite ajoute le jeton à toute requête `/api`) ; arrêt gracieux
  de `netsift serve` borné dans le temps (connexions SSE ouvertes).
- P2.5 : dialogue d'erreur si l'API embarquée ne démarre pas (pas de console en release Windows) ;
  attendre la fin réelle de l'API (writer SQLite) à la fermeture, avec délai maximal ; scope du plugin
  `opener` sur le dossier d'export ; vérifier `freezePrototype` avec ECharts et sigma ; créer la fenêtre
  dans `setup` après démarrage de l'API (`create: false`).
- P2.4 / P3.x : `DataTable` virtualisé : `scrollMargin` de l'en-tête collant, redimensionnement des
  colonnes au clavier.
- Outillage : le hook `.claude/hooks/guard-toolchain.sh` bloque à tort les commandes passées au conteneur
  entre guillemets (`./x.sh run '...; ...'`) et certaines lignes de heredoc ; la règle de permission
  `Read(./.artifacts/**)` empêche l'agent `ui-reviewer` de relire les captures produites par `./x.sh shots`.

---

## Phase 1 — Moteur d'ingestion

### Vague 1.A (parallèle)

- [x] **P1.1** `feat/capture-reader` — `netsift-capture` : pcap (µs/ns, 2 endianness), pcapng (SHB multiples,
      IDB multiples, EPB/SPB/PB, blocs inconnus), `.gz`, détection par magic, lecture en streaming,
      tolérance au dernier paquet tronqué. Dép. : P0.2.
- [x] **P1.2** `feat/chunk-sets` — Inventaire de dossier, regroupement, tri numérique, contrôles de continuité,
      fusion k-voies, rapport d'anomalies (`docs/CHUNKED_CAPTURES.md`). Dép. : P0.2 (interface du lecteur
      définie d'un commun accord : trait `PacketSource`, mock en attendant P1.1).
- [x] **P1.3** `feat/dissect-l2-l4` — `netsift-dissect` : Ethernet, VLAN/QinQ, Linux SLL/SLL2, raw IPv4/IPv6,
      loopback/null, **radiotap + 802.11** (trames data -> LLC/SNAP -> IP ; trames mgmt décodées en en-tête),
      IPv4/IPv6/ICMP/TCP/UDP via `etherparse`. Dép. : P0.2.
- [x] **P1.4** `feat/store-core` — `netsift-store` : catalogue, ouverture de session, migrations versionnées,
      writer par lots sur thread dédié, tables `meta`, `chunks`, `anomalies`, `timeseries`, `hosts`, `flows`.
      Dép. : P0.2.
- [x] **P1.5** `feat/fixtures` — `netsift-fixtures` : constructeur de scénarios (DNS, HTTP avec image, TLS
      ClientHello/ServerHello/certificat auto-signé, NBNS, SMB browser announce, SNMP community, FTP login),
      écrivain pcap/pcapng/gz, découpeur en chunks par taille et par durée avec les 4 conventions de nommage.
      Dép. : P0.2.

Suivis non bloquants de la vague 1.A (à intégrer à la tâche qui en a besoin) :

- Fixtures, pour P1.6 : faire varier l'IP ID (0 partout aujourd'hui) et ajouter un scénario de
  fragmentation IPv4/IPv6 ; tester les checksums IPv4/TCP/UDP générés.
- Fixtures : `checked_mul` dans la conversion `if_tsresol` (`writer.rs:79`, panique au-delà de 10^-21) ;
  `ServerKeyExchange` pour la suite ECDHE (onglet TLS, P3.3) ; nommages tcpdump `-W` et `-G` ;
  documenter que `SplitBy::Size` ne dépasse jamais la limite (comme tcpdump `-C`, contrairement à dumpcap).

### Vague 1.B (après 1.A)

- [x] **P1.6** `feat/flow-table` — `netsift-flow` : défragmentation IP bornée, table de flux, réassemblage TCP
      (hors ordre, retransmissions, chevauchements, bornes mémoire), expiration en temps paquet.
- [x] **P1.7** `feat/engine-pipeline` — `netsift-engine` : threads lecteur/décodeur/shards/writer, trait
      `Analyzer` **figé** (voir ARCHITECTURE), classification applicative pour `timeseries`, progression,
      annulation. CLI `netsift ingest <dossier|fichier> --out <dir>`. Test d'acceptation « fichier unique
      vs chunks = mêmes tables ».

Sortie de phase : ingestion d'un dossier de chunks synthétiques de 1 Go en CLI avec rapport.
Atteinte le 2026-11-08 : 11 chunks dumpcap de 100 Mo, 1 872 000 paquets, 192 004 flux, 0 anomalie, 6,65 s
(152 Mio/s, 20 shards sur 22 cœurs). Test d'acceptation vert : `timeseries`, `hosts` et `flows` identiques
entre fichier unique et découpages (dumpcap, tcpdump `-C`, nametimenum, formats mélangés + gz) et pour
1, 4 et 7 shards.

Suivis de la phase 1 :

- P2.1 / P2.5 : appeler `recover_interrupted()` au démarrage de l'API embarquée (desktop), comme le fait
  déjà `netsift serve` (sessions restées `importing` après un arrêt brutal -> `incomplete`).
- P4.2 : mesurer le pic de mémoire résidente (non mesuré en P1.7 : pas de GNU `time` dans l'image) ;
  supprimer le double décodage (décodeur puis `FlowTable`) si le profilage le justifie ; borne globale
  des tampons TCP tous flux confondus (les bornes actuelles sont par flux et par table).
- Phase 3 : le trait `Analyzer` est figé (`netsift-analyze`) ; chaque analyseur ajoute une ligne triée
  dans `Registry::BUILTIN`, ses variantes de `Record`, sa traduction dans `netsift-engine/src/translate.rs`,
  sa sous-structure dans `AnalyzerConfig` et sa migration dans sa plage réservée.

---

## Phase 2 — API, application et premières vues

### Vague 2.A (parallèle)

- [x] **P2.1** `feat/api-sessions` — Routes sessions (liste, import, SSE progression, suppression), `fs/browse`,
      génération des types ts-rs, client API typé côté UI.
- [x] **P2.2** `feat/geoip` — `netsift-geo` : lecture mmdb, cache LRU, classification d'adresses ;
      `./x.sh geoip` ; attribution DB-IP dans « À propos ».
- [x] **P2.3** `feat/ui-captures` — Vue Captures : liste des sessions, import (dialogue natif desktop /
      navigateur de dossiers en dev), progression, frise des chunks et anomalies. Spec : `specs/captures.md`.

Suivis de la vague 2.A :

- P2.5 : passer `geoip_path` vers la base du bundle (`apps/desktop/resources/geoip/`) ; exposer l'état
  de la base GeoIP (présente / absente) par l'API pour l'afficher dans « À propos ».
- Avant le premier onglet qui affiche des catégories d'adresses (Hosts, Network) : exporter
  `AddressCategory` via ts-rs et indexer `ADDRESS_CATEGORIES` de `ui/src/charts/palette.ts` par les
  libellés backend (`private`, `link_local`, `cgnat`, `unspecified`, `reserved`…), libellés affichés via
  l'i18n ; séparer le rôle « serveur » des catégories d'adresses.
- Fixtures : ajouter des hôtes à adresses publiques (aujourd'hui plages de documentation uniquement),
  pour que la démo montre pays et carte ; `crates/netsift-store/tests/writer.rs` utilise encore
  `"link-local"` comme exemple.
- [x] P2.1 : anomalies publiées pendant l'import et id de session fourni par `Progress`
  (`feat/engine-live-progress`, fusionnée le 2026-11-08 ; trous et chevauchements restent publiés en fin
  de lecture, `analyzer_panicked` seulement en base).
- [x] Outillage, hygiène du cache (`chore/cache-hygiene`, fusionnée le 2026-11-08) : `./x.sh clean`,
  nettoyage automatique dans `wt.sh`, sccache à 5 GiB, dépendances sans debuginfo en dev (-37 %).
  Reste : `x.ps1` sans `.origin` ni `clean` (les targets grossissent sous Windows).
- [x] Tests UI instables (`test/ui-flaky`, fusionnée le 2026-11-08) : préchargement des routes, user-event
  sans délai, délais 5 s / 20 s, 4 workers ; 6/6 sous charge ~100. Reste : au-delà d'une charge ~150-200 des
  dépassements restent possibles ; un Vitest s'est bloqué indéfiniment sous charge sur l'ancien main
  (soupçon : `src/test/freezePrototype.test.ts`) -> borner la durée du gate UI et vérifier ce test.
- P2.1 : `fs/browse` et inventaire : traiter explicitement les liens symboliques qui sortent de la racine
  autorisée ; mesurer le coût de `GET /sessions?limit=1000` sur un gros catalogue.
- P2.5 : `ApiConfig::max_imports` et `allow_any_path: true` à renseigner dans `apps/desktop`.
- P2.3, frise des chunks : lisible à 375 px (largeur minimale par chunk plus grande, défilement
  interne) ; rendre visible le trou d'un fichier manquant (aujourd'hui ~3 px sous la ligne pointillée).
- P2.3 : `useSessions` ignore le drapeau `truncated` (liste coupée à 5 000 sans avertissement) ; les shots
  Sources supposent une session démo `ready` avec chunks.
- P2.3 : à 375 px, les tableaux Anomalies et Chunks de Sources défilent horizontalement (State, Time,
  Detail hors champ) : passer en cartes sous `md`, comme la liste des sessions.
- P2.4 : sous-titre d'Overview avec le nom de la session, comme Sources.
- Settings : aligner les valeurs entre cartes, largeur maximale des formulaires à 1920 px.
- Sidebar : « Captures » est rangé sous l'intitulé « Session » alors que la vue est globale.
- Relecture visuelle : `.artifacts/screens/` est lisible depuis le 2026-11-08 ; la phase 0 (Overview,
  Settings) a été relue avec P2.3.

### Vague 2.B

- [x] **P2.4** `feat/ui-overview` — Vue Overview (`specs/overview.md`) : série temporelle par protocole,
      cartes de modules avec compteurs, résumé de session.
- [x] **P2.5** `feat/desktop-integration` — Dialogue de dossier natif, jeton API, CSP, répertoire de données,
      fermeture propre pendant un import.

Sortie de phase : importer un dossier depuis l'app desktop et voir l'Overview. **À vérifier par
l'utilisateur** sur un bundle installé (liste des 11 vérifications manuelles dans l'ADR-012).

Suivis de la vague 2.B :

- Desktop : une session reste `importing` si le writer dépasse `STOP_LIMIT` à la sortie (récupérée au
  lancement suivant) ; démarrage refusé si `catalog.db` est corrompu, sans réparation possible dans l'app ;
  un second lancement pendant l'arrêt de l'API (~15 s) quitte sans fenêtre.
- GeoIP : le cache de `/server-info` peut rester périmé si la base est remplacée dans la même seconde avec
  la même taille.
- [x] Desktop : crash à l'ouverture d'une session (ECharts 6 `Scheduler.mockMethods` affecte `constructor`
  sous `Object.prototype` gelé) corrigé par un plugin Vite (`fix/desktop-readonly`, 2026-11-08) ; écran
  d'erreur de route maison avec « Copier les détails » ; test de fumée desktop WebKit + Chromium dans
  `./x.sh shots`. La CI était rouge (shots Overview) de dd76c05 à cdfc665 : le gate local ne lance pas les
  shots -> envisager `shots` (ou le test de fumée desktop) dans `wt.sh merge` pour les branches UI.
- Vue Network (sigma) : l'ajouter au test de fumée desktop (`ui/tests/desktop/desktop.spec.ts`) sous gel.
- Outillage : `scripts/ct/shots.sh` et `scripts/ct/webkit.sh` absents de la liste shellcheck de la CI.
- Overview : performance au-delà de 24 h et zoom avec refetch, reportés dans P4.2.

---

## Phase 3 — Analyseurs et onglets (une branche = analyseur + API + vue + tests)

### Vague 3.A (parallèle, indépendantes)

- [ ] **P3.1** `feat/dns` — DNS + mDNS + NBNS (+ LLMNR) : transactions, codes réponse, types. `specs/dns.md`.
- [ ] **P3.2** `feat/http` — HTTP/1.x : transactions, en-têtes, corps bornés, décompression gzip/deflate/br,
      chunked ; vues HTTP et HTTP Headers. `specs/http.md`, `specs/http-headers.md`.
- [ ] **P3.3** `feat/tls` — TLS : ClientHello/ServerHello, versions, suites, SNI, ALPN, JA3/JA4 (client),
      certificats X.509 (export DER/PEM). `specs/tls.md`.
- [ ] **P3.4** `feat/connections-ports` — Agrégats de flux, ports ouverts (SYN-ACK / réponses UDP), table
      IANA des services embarquée. `specs/connections.md`, `specs/open-ports.md`.
- [ ] **P3.5** `feat/smb-netbios` — Annonces NetBIOS browser (OS, types), SMB1/2 négociation, NTLMSSP
      (v1/v2 -> lignes hashcat 5500/5600). `specs/smb.md`.

### Vague 3.B (dépend de 3.A)

- [ ] **P3.6** `feat/pictures` — Extraction d'objets HTTP (images), dédup SHA-256, miniatures Rust. Dép. P3.2.
      `specs/pictures.md`.
- [ ] **P3.7** `feat/credentials` — Agrégation + émetteurs : HTTP Basic/formulaires, FTP, POP3, IMAP,
      SMTP AUTH, SNMP v1/v2c, LDAP simple bind, NTLM (depuis P3.5). Export hashcat. `specs/credentials.md`.
- [ ] **P3.8** `feat/servers` — Rôles DNS / DHCP / LDAP (+ NTP, Kerberos, SMB) avec preuves. `specs/servers.md`.
- [ ] **P3.9** `feat/network-map` — Graphe des communications (sigma.js), filtres protocoles, agrégation
      par pays. `specs/network.md`.

---

## Phase 4 — Durcissement et version 0.1

- [ ] **P4.1** `test/fuzzing` — cibles cargo-fuzz : lecteurs pcap/pcapng, dissect L2-L4, DNS, HTTP, TLS,
      NTLMSSP, SNMP ; corpus depuis les fixtures ; 0 crash sur 30 min par cible.
- [ ] **P4.2** `perf/large-sessions` — Bench 5 Go (fixtures `--big`), profilage, index SQL, cibles d'ARCHITECTURE.
      Inclut (revue P2.4) : `resample` lit une ligne par seconde et par libellé (7 jours ≈ 6 M lignes,
      plusieurs secondes) et `traffic_totals` somme toute la table à chaque `summary` -> table cumulée par
      minute/heure écrite en fin d'import + `stats.bytes` dans `meta` (prévoir la mise à niveau des sessions
      existantes) ; mesurer l'affichage Overview (< 500 ms) côté UI ; zoom Overview avec refetch serveur
      (`from_us`/`to_us`) avec le filtre global de phase 5.
- [ ] **P4.3** `feat/export-pcap` — « Save PCAP » : export d'un flux, d'une plage temporelle ou de la session
      fusionnée (pcapng).
- [ ] **P4.4** `feat/i18n-fr` — Traduction française complète, formats de nombres/dates localisés.
- [ ] **P4.5** `chore/release-0.1` — Icônes définitives, à propos/licences tierces, tag `v0.1.0`.
- [x] **P4.6** `ci/release-pipeline` — Releases GitHub publiées par la CI sur tag `vX.Y.Z` : notes
      générées depuis l'historique des commits (Conventional Commits), bundles Linux (AppImage, .deb, .rpm),
      Windows (NSIS .exe, MSI) et macOS (.dmg), sommes SHA-256 ; version unique (workspace, Tauri, UI)
      vérifiée contre le tag ; script de préparation de version. Avancée hors vague, à la demande.

---

## Phase 5 — Onglets suivants (specs à rédiger à partir de captures de référence)

Documents, FTP, Telnet, SSDP, SIP, ARP, Ethernet, WiFi (beacons, probes, clients, EAPOL -> hc22000),
Hosts (fiche par hôte agrégeant tout). Puis : ajout de chunks à une session, surveillance de dossier
en direct, `.zst`/`.lz4`, filtre temporel global (brush de l'Overview appliqué à toutes les vues).
