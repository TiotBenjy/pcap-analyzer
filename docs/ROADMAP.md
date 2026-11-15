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

### Vague 3.A (parallèle, indépendantes) — terminée le 2026-11-08

- [x] **P3.1** `feat/dns` — DNS + mDNS + NBNS (+ LLMNR) : transactions, codes réponse, types. `specs/dns.md`.
- [x] **P3.2** `feat/http` — HTTP/1.x : transactions, en-têtes, corps bornés, décompression gzip/deflate/br,
      chunked ; vues HTTP et HTTP Headers. `specs/http.md`, `specs/http-headers.md`.
- [x] **P3.3** `feat/tls` — TLS : ClientHello/ServerHello, versions, suites, SNI, ALPN, JA3/JA4 (client),
      certificats X.509 (export DER/PEM). `specs/tls.md`.
- [x] **P3.4** `feat/connections-ports` — Agrégats de flux, ports ouverts (SYN-ACK / réponses UDP), table
      IANA des services embarquée. `specs/connections.md`, `specs/open-ports.md`.
- [x] **P3.5** `feat/smb-netbios` — Annonces NetBIOS browser (OS, types), SMB1/2 négociation, NTLMSSP
      (v1/v2 -> lignes hashcat 5500/5600). `specs/smb.md`.

Suivis de la vague 3.A :

- P3.4 (fusionnée le 2026-11-08) : cartes choroplèthes de Connections absentes (top 5 pays à la place ;
  réutiliser le composant carte du monde extrait par P3.1) ; routes `/open-ports*` au lieu de `/ports*`
  de la spec ; conversations orientées par l'initiateur ; pas de sélecteur de tri ni de filtre
  protocole/catégorie dans l'UI (l'API les propose) ; étiquettes du chord masquées en haut du cercle
  (collision sur boîtes alignées, adapter le contrôle de chevauchement des shots avant de passer aux
  boîtes tournées) ; tableau des conversations sans indice de défilement à 375/768 px ; badges de la
  sidebar non alimentés (`AppShell` ne transmet aucun compteur) ; P4.2 : `hosts_page` (deux
  `count(DISTINCT)` par hôte), `HOSTS_FROM` ré-agrégé à chaque page, `count_conversations` en scan.
- P3.3 (fusionnée le 2026-11-08) : téléchargement DER/PEM en desktop non vérifié (`<a download>` sur URL
  blob, aucun `on_download` dans `apps/desktop`) -> à tester sur un bundle, sinon écrire dans
  `<données>/exports` et ouvrir avec `opener` ; tableau des sessions sans cartes sous `md` (SNI invisible à
  375 px) ; `Endpoint` local à migrer vers le composant commun ; DTLS et STARTTLS non traités, une session
  TLS par flux ; P4.2 : filtres SQL `?n IS NULL OR col = ?n` qui neutralisent les index (aussi HTTP),
  recherche `LIKE` et `count(*)` filtré ; blobs sans fsync ni balayage des `.tmp` laissés par un crash.
- [x] `fix/session-migrate-on-open` (fusionnée le 2026-11-08, ADR-013) : migrations appliquées à l'ouverture
  des sessions `ready`/`incomplete`. Reste : vues Connections/Open Ports vides au lieu de « non analysé »
  sur une session migrée, messages d'erreur génériques hors Overview, `SessionGate` laisse passer une
  session trop récente, `Stats::read` avale les erreurs.
- P3.2 (fusionnée le 2026-11-08) : corps HTTP jamais écrits sur disque (`HttpConfig::store_bodies = false`,
  à activer par P3.6 avec ses règles de sélection) ; aperçu de corps 4 Kio au lieu de 64 ; un seul
  `Content-Encoding` décodé ; compteurs de méthodes globaux (ignorent la recherche) ; connexion prise en
  cours de route sans SYN-ACK mal orientée ; P4.2 : budget de corps par shard (32 Mio) à rendre global,
  `WHERE` dynamique (filtres sans index), coût des deux FTS5 trigram ; P4.1 : cible de fuzz HTTP.
  Piège i18n : passer `t` en paramètre d'un helper peut faire échouer `tsc` (type trop profond) quand le
  dictionnaire grossit : passer plutôt les libellés.
- P3.1 (fusionnée le 2026-11-08, ADR-014 : étapes de fin d'import `SESSION_FINALIZERS`, rattrapées à
  l'ouverture) : pas de phase « finalisation » dédiée dans `Progress` ; carte du monde non couverte par le
  test de fumée desktop (pas de serveur localisé dans la démo, pas de GeoIP) ; Sankey optionnel non fait ;
  P4.2 : coût de la finalisation sur une session très chargée en DNS (UPDATE de `pair_id`, reconstruction
  trigram), percentiles de latence par OFFSET, `LIKE` des recherches courtes ; P4.1 : cible de fuzz DNS.
  Connections affiche désormais les noms résolus (`hosts.names` alimenté par le finaliseur DNS).
- P3.5 (fusionnée le 2026-11-08) : `Record::Credential` est un contrat en mémoire, abandonné par le moteur
  (`to_store` -> `None`) jusqu'à P3.7, qui conçoit la table `credentials` (plage 0600) et son ADR ; SMB1 sans
  extended security (défi dans la réponse NEGOTIATE), dialecte et signature SMB1 non extraits ; pas de
  filtre ni de recherche dans l'en-tête de carte ; P4.1 : cibles de fuzz NetBIOS, SMB et NTLMSSP.
  `count_rows` accepte les vues SQL et le marqueur d'ADR-013 enregistre aussi les vues.
- Sécurité : alerte Dependabot #13 (GHSA-wrw7-89jp-8q8g, `glib` 0.18.5, unsound `VariantStrIter`) non
  corrigeable : `glib` vient des liaisons GTK3 0.18 tirées par Tauri/wry/webkit2gtk sous Linux, le correctif
  exige `glib` 0.20 (liaisons GTK4). À revoir quand Tauri change de pile GTK ; alerte à clore sur GitHub
  (« risque tolérable »). Les 12 alertes npm sont corrigées par `fix/npm-audit` (vite 7.3.7, echarts 6.1.0,
  override minimatch 11, à retirer quand eslint l'acceptera).
- G1 (fusionnée le 2026-11-08, ADR-015) : test manuel du téléchargement réel à faire sur un bundle (une
  redirection DB-IP vers un autre hôte ferait échouer proprement, règle « même origine ») ; navigateur de
  fichiers web dupliqué depuis `BrowserSelect` (à factoriser) ; cible de fuzz mmdb (profondeur du décodeur
  `maxminddb`) ; pas d'identifiant de fichier hors Unix pour détecter un remplacement externe ; tests de bout
  en bout manquants (import avec la base échangée, coupure en cours de corps). `Button` : les boutons pleins
  désactivés ont désormais un fond neutre dans toute l'app.
- P3.8 (fusionnée le 2026-11-09, ADR-017 : rôles calculés à la lecture par la vue `server_evidence`, bornés
  par rôle) : serveur DHCP pirate (incohérence option 54 / `src_ip`) non signalé ; DHCPv6, option overload
  et options longues non décodées, NTP broadcast ignoré ; P4.2 : mesurer `server_evidence` et `server_roles`
  sur 10 M paquets, coût des index de 0800 sur `dns_messages` et `http_transactions` ; P4.1 : cibles de fuzz
  DHCP, NTP, Kerberos. Network (P3.9) : renseigner le champ `role` des nœuds.
- P3.6 (fusionnée le 2026-11-09, ADR-016 : seules les réponses images complètes vont sur disque, rétention
  HTTP limitée à l'aperçu pour le reste) : visionneuse non capturée par les shots ; pas de phase
  « miniatures » dans `Progress` (jusqu'à 60 s dans `finishing`) ; téléchargement desktop (`<a download>`)
  non vérifié ; l'API lit l'original avant de prendre le jeton du sémaphore de décodage ; la copie d'URL
  copie la valeur nettoyée, pas la brute ; P4.2 : budget de rétention par shard (32 Mio) à rendre global,
  filtres SQL `?n IS NULL OR`, `LIKE`, `count(*)` ; P4.1 : cible de fuzz `thumbs::render`.
- P3.9 (fusionnée le 2026-11-14, ADR-018 : graphe replié en fin d'import, mémoire bornée quel que soit le
  nombre d'hôtes, plans épinglés par `INDEXED BY`) : étape lente au-delà de 2 M conversations (33 s, lectures par
  clé hors cache de pages ; pistes : id entier par hôte, `mmap_size`) ; formes de nœud par catégorie et forme
  « serveur » reportées (la spec les cite encore), export PNG/SVG reporté ; captures sans mode Countries, ni
  nœud cluster, ni couleur Public ; rôles affichés même quand Servers est « non analysé » sur une session
  ancienne ; P4.2 : mesurer `host_roles` / `server_roles` à chaque requête de graphe (si > 300 ms, rôles au
  détail seulement ou matérialisés), ajouter `dns_messages` et le rejeu à l'ouverture au test `timings`,
  orphelins lus par masque de groupe ; `shots network` effaçait les captures `network-detail` (corrigé en P4.3 : `shots.sh` ne supprime plus que `<vue>-<chiffre>*`).
- P3.7 (fusionnée le 2026-11-14, ADR-019 : table `credentials` repliée par empreinte SHA-256 interne, id public
  aléatoire, secrets lus seulement au détail, export CSV/hashcat explicite et refusé au-delà de 10 000 entrées) :
  non émis : formulaires JSON, HTTP Digest, Kerberos (7500/18200), SASL NTLM/GSS dans LDAP/SMTP, littéraux IMAP
  `{n}`, APOP sans ligne hashcat (mode 20), Telnet et EAPOL (phase 5) ; reconnaissance par port connu seulement ;
  entrée repliée = détails de la première observation (SNMP Set non distingué de Get) ; `SecretValue` affiche la
  longueur du secret (« Hidden (6 characters) ») alors que la spec parle de points, à trancher ; badge
  « Metadata only » jamais capturé (presque identique à « Recoverable ») ; pas de capture en français, ni d'état
  vide ou « non analysé » ; colonne Source très large à 1920 px ; la vue HTTP garde les URI avec leur chaîne de
  requête (`?password=`) dans `http_transactions` et son FTS (masquer ou assumer) ; test de logs limité à
  l'import (pas les routes API) ; P4.1 : cibles de fuzz `LineFlow` (FTP/SMTP/POP3/IMAP), `BerStream` +
  ldap-parser, `snmp::parse`, `http::auth` ; P4.2 : `paths()` (GROUP BY sur toute la table) sur 10 M paquets.
- P4.4 (fusionnée le 2026-11-15, conventions dans `docs/UI_GUIDELINES.md` « Langues et formats » : IEC Kio/Mio
  en fr, heures ISO 24 h dans les deux langues, `_many` français généré depuis `_other`) : les `reason`
  d'anomalies `read_error`/`skipped_record` viennent du moteur en anglais (`netsift-engine/src/translate.rs`)
  -> codes stables côté API traduits par l'UI ; `limit` des anomalies non groupé ; `Intl.DisplayNames` recréé à
  chaque appel (`lib/countries.ts`) ; dépendance circulaire `i18n/index.ts` <-> `lib/format.ts` (aucun `t()` à
  l'évaluation) ; `hardcoded.test.ts` : faux négatifs connus (un mot dans `{'…'}`, phrases en minuscules,
  `label:` hors JSX) ; espaces insécables littérales dans `OverviewView.tsx` et `ProgressStep.tsx` ; captures
  fr en thème clair seulement ; `shots` deux fois plus long (en + fr par défaut) ; fixture Overview avec une
  période fausse (ns passées pour des µs). Défauts communs aux deux langues : IP/port tronqués dans les chemins
  Credentials à 768, placeholder TLS coupé à 375, badge « Auto-signé » coupé à 1280.
- P4.1 (fusionnée le 2026-11-15, ADR-020, `docs/FUZZING.md`) : 17 cibles, 30 min chacune sans crash ; le gate
  vérifie `fuzz/` (fmt, check `--locked`, tests de la lib) ; job CI `fuzz` (60 s par cible, `main` et à la
  demande), vert au premier passage sur GitHub ; `scripts/release.sh` met à jour `fuzz/Cargo.lock` au changement de
  version, non testé par une vraie release (le `--dry-run` ne l'exerce pas : à surveiller en P4.5) ; campagnes
  `analyzers`/`pipeline` courtes (200 à 360 exécutions/s), à prolonger ; actions tierces de `ci.yml` épinglées
  par tag et non par SHA (contrairement à `release.yml`). Piège : `./x.sh -C <worktree> check` exécute le `x.sh`
  de la racine ; une branche qui modifie le gate doit le tester avec le `x.sh` du worktree.
- P4.7 (fusionnée le 2026-11-15, ADR-022) : l'id d'un flux est l'index global de la trame qui l'a créé (plus de
  hachage, plus de collision) ; il change si l'ordre délivré change (sous-ensemble de chunks, égalités d'horodatage
  entre chunks qui se chevauchent, dépassement de `max_open`) ; phase 5 (ajout de chunks à une session) : le
  compteur de trames doit reprendre au nombre de paquets déjà importés, sinon les upserts fusionnent en silence ;
  l'id révèle la position du flux dans la capture.
- P4.3 (fusionnée le 2026-11-15, ADR-021, `docs/specs/export-pcap.md`) : jobs d'export interrogés par polling (2 au
  plus), fichiers dans `exports/` jamais purgés ni supprimables depuis l'UI ; deux flux de même 5-tuple aux fenêtres
  qui se recouvrent sont exportés ensemble (sur une session lue hors ordre, aussi un flux antérieur) ; un fichier
  unique est relu depuis le début même pour un flux tardif (pas d'index d'offsets, P4.2) ; fragments IP : clés
  jamais expirées si le dernier fragment manque (4096 max), fragment arrivé avant le premier non inclus ; erreurs
  ICMP liées au flux non incluses ; snaplen 0 hors première interface d'un chunk pcapng ; `ExportJob.path` absolu
  exposé mais inutilisé par l'UI ; à vérifier sur un bundle : « Ouvrir le dossier » (plugin opener réel) et un
  export de plusieurs Go (progression, annulation) ; la fermeture du desktop annule un export sans confirmation.
- P4.2 (fusionnée le 2026-11-15, ADR-023, `docs/PERFORMANCE.md`, `./x.sh bench`) : import 5 Go 578 s -> 95 s sur
  4 cœurs (104 Mo/s pendant la lecture, 56 Mo/s sur la durée totale), pic RSS 375 Mio (cache d'import 256 Mio par
  import simultané), requêtes de vue > 300 ms 18 -> 4 sur 76 ; index secondaires, FTS HTTP, cumuls de séries et
  rôles de serveurs construits en fin d'import, avec replis justes (mais lents) tant que l'étape n'a pas tourné ;
  les suivis « P4.2 » des phases précédentes sont traités ou repris dans P4.8. Restent hors P4.8 : repli
  `server_evidence_source` très lent sans `flows_service` (lecture seule ou étape `indexes` en échec) ; repli
  `LIKE` sans pliage de casse Unicode ; détection des définitions d'index invalides par texte d'erreur ; test
  « import sans étapes » qui retouche une base finie au lieu d'arrêter le writer ; pic disque en fin d'import
  (WAL de la taille des index) ; rapports de bench en français. Le gate `./x.sh check` laissait passer un échec
  au milieu d'une chaîne `&&` (version, `fuzz/`, bindings) : corrigé sur `main` (une commande par ligne).
- P4.8 (fusionnée le 2026-11-15, `docs/PERFORMANCE.md` « Suite P4.8 ») : 0 requête de vue > 300 ms (`/servers`
  588 -> 7 ms, mesuré avant la lecture par l'index `server_ranks_rank`, non re-mesurée ; catégories Connections
  478 -> 4 ms et Open Ports 341 -> 44 ms ; HTTP `q=` 337 -> 132 ms) ; Overview 635 -> 298 ms (délai de suspension
  React supprimé, ECharts chargé hors `React.lazy`) ; phase `finalizing` publiée (étape n/N) et Annuler désactivé
  après la lecture. Restent : fin d'import 44,5 s (index 18,5 s, DNS 11,9 s, FTS HTTP 7,6 s, réseau 2,7 s) ;
  writer pendant la lecture 41 s (`tls_sessions`, `conversations`, `http_transactions`, `hosts`) ; neuf requêtes
  entre 150 et 300 ms ; premier `setOption` ECharts ≈ 90 ms ; mesures dans WebKitGTK non faites ; miniatures
  générées sous « Finalisation 9/9 » ; plan Probe/Lookup choisi sur la catégorie seule ; boîte de progression
  d'import sans capture `shots` (pas d'import possible sur le serveur des captures).
- P4.5, préparation (fusionnée le 2026-11-15, ADR-024, `docs/LICENSES.md`) : NetSift sous Apache-2.0 seule
  (`LICENSE` officiel, `NOTICE`), `THIRD_PARTY_LICENSES` généré hors ligne par cargo-about 0.9.3 et un script npm
  (`./x.sh licenses [--check]`, gate et job CI `licenses`), dont la section des sources des 5 crates MPL-2.0
  embarquées (cssparser, cssparser-macros, selectors, dtoa-short, option-ext) ; icône « flux qui convergent » ;
  « À propos » avec liste des licences ; `release.sh` publie la version courante (0.1.0 déjà en place) et refuse
  une relance après fusion ; notes de la première version résumées (fonctionnalités et performances). Suivis :
  `release.sh` propose de pousser un tag présent seulement en local sans inviter à vérifier son commit (tag
  supprimé exprès sur origin puis rapporté par un fetch) ; bundle `.deb` non reconstruit depuis le passage à
  Apache-2.0 (ressources vérifiées par `apps/desktop/tests/bundle.rs`) ; `taiki-e/install-action` avec
  `cargo-about@0.9.3` non vérifié avant le premier passage CI (repli : compilation épinglée) ; proc-macros et
  outils de build listés sans être embarqués ; preflight Tailwind et polyfill Vite non listés.
- Transverse : harmoniser les vues après la vague (composant `Endpoint` commun, `CopyButton` partagé
  16 px / cible 32 px, helper unique de barres horizontales avec valeurs, format d'heure, filtres dans
  l'en-tête de carte, tableaux en cartes sous `md`).

Hors vague (demande utilisateur du 2026-11-08) :

- [x] **G1** `feat/geoip-update` — Mise à jour de la base GeoIP depuis l'application (Paramètres > À
      propos) : téléchargement de la dernière DB-IP Country Lite côté Rust, sur clic uniquement, et import
      d'un fichier `.mmdb` ; validation avant remplacement atomique, rechargement à chaud. Seule exception
      à « aucun appel réseau sortant » (ADR-015).

### Vague 3.B (dépend de 3.A) — terminée le 2026-11-14

- [x] **P3.6** `feat/pictures` — Extraction d'objets HTTP (images), dédup SHA-256, miniatures Rust. Dép. P3.2.
      `specs/pictures.md`.
- [x] **P3.7** `feat/credentials` — Agrégation + émetteurs : HTTP Basic/formulaires, FTP, POP3, IMAP,
      SMTP AUTH, SNMP v1/v2c, LDAP simple bind, NTLM (depuis P3.5). Export hashcat. `specs/credentials.md`.
- [x] **P3.8** `feat/servers` — Rôles DNS / DHCP / LDAP (+ NTP, Kerberos, SMB) avec preuves. `specs/servers.md`.
- [x] **P3.9** `feat/network-map` — Graphe des communications (sigma.js), filtres protocoles, agrégation
      par pays. `specs/network.md`.

---

## Phase 4 — Durcissement et version 0.1

- [x] **P4.1** `test/fuzzing` — cibles cargo-fuzz : lecteurs pcap/pcapng, dissect L2-L4, DNS, HTTP, TLS,
      NTLMSSP, SNMP ; corpus depuis les fixtures ; 0 crash sur 30 min par cible.
- [x] **P4.2** `perf/large-sessions` — Bench 5 Go (fixtures `--big`), profilage, index SQL, cibles d'ARCHITECTURE.
      Inclut (revue P2.4) : `resample` lit une ligne par seconde et par libellé (7 jours ≈ 6 M lignes,
      plusieurs secondes) et `traffic_totals` somme toute la table à chaque `summary` -> table cumulée par
      minute/heure écrite en fin d'import + `stats.bytes` dans `meta` (prévoir la mise à niveau des sessions
      existantes) ; mesurer l'affichage Overview (< 500 ms) côté UI ; zoom Overview avec refetch serveur
      (`from_us`/`to_us`) avec le filtre global de phase 5.
- [x] **P4.3** `feat/export-pcap` — « Save PCAP » : export d'un flux, d'une plage temporelle ou de la session
      fusionnée (pcapng).
- [x] **P4.4** `feat/i18n-fr` — Traduction française complète, formats de nombres/dates localisés.
- [x] **P4.5** `chore/release-0.1` — Icônes définitives, à propos/licences tierces, tag `v0.1.0`. Préparation
      fusionnée le 2026-11-15. `v0.1.0` taguée le 2026-11-15 mais bundles Windows et macOS en échec (deux modules
      `ServerMap.tsx` / `serverMap.ts` confondus par les systèmes de fichiers insensibles à la casse ; corrigé, test
      `ui/scripts/case-collisions.test.ts`) : release `v0.1.0` publiée par l'utilisateur sans bundles (code source).
      **`v0.1.1` publiée le 2026-11-15** avec tous les bundles (AppImage, .deb, .rpm, NSIS, MSI, .dmg universel,
      `SHA256SUMS.txt`). À vérifier sur la prochaine release : la recherche de mise à jour de P4.10 depuis 0.1.1.
- [x] **P4.7** `fix/flow-id-collision` — `FlowId::derive(key, first_ts)` (`netsift-flow/src/api.rs`) donne le même
      id à deux flux successifs de même 5-tuple et même premier horodatage (flux fermé puis nouveau SYN, éviction
      LRU, capture à horodatages constants ou hostile) : `flows` fusionne les compteurs par max (octets perdus),
      `http_transactions` rejette le second flux (`UNIQUE (flow_id, seq)`), TLS l'ignore (`DO NOTHING`), SMB
      fusionne les sessions, sans erreur visible. Piste : faire entrer l'index de trame global du premier paquet,
      identique entre fichier unique et chunks (test d'équivalence) ; test synthétique : deux connexions HTTP
      même 5-tuple, ts constant. Trouvé par la revue de P4.1.
- [x] **P4.8** `perf/followups` — Reste de P4.2 (chiffres dans `docs/PERFORMANCE.md`) : affichage Overview 616 ms
      pour 500 visés (réponses ≈ 130 ms, ≈ 480 ms de rendu ECharts SVG de 13 séries ; mesurer aussi dans WebKitGTK) ;
      fin d'import de 44 s sans progression (index 19 s, DNS 11,5 s, FTS HTTP 7,7 s, réseau 2,6 s) -> phase dédiée
      dans `Progress` ; requêtes > 300 ms : `/servers` 571 ms (rang précalculé sans filtre), `/connections?category=`
      483 ms et `/open-ports?category=` 343 ms (comptes par catégorie ou total estimé), `/http/transactions?q=` 343 ms
      (régression de P4.2, 212 ms avant) ; requêtes entre 150 et 300 ms (`/connections/stats`, `/dns/stats`, `/dns/messages?q=`
      court) ; writer pendant la lecture (`tls_sessions`, `conversations`, `hosts`).
- [x] **P4.11** `feat/outbound-base` — Socle commun de P4.9 et P4.10, à fusionner avant elles (qui se font ensuite en
      parallèle) : client HTTP sortant partagé extrait de `netsift-api/src/geoip/download.rs` (HTTPS seul, redirections,
      délais et tailles bornés, `.part` puis renommage, User-Agent générique) ; réglages persistants « vérifications en
      ligne » (GeoIP, mises à jour), désactivés par défaut, lus au démarrage ; composant de bandeau de notification
      discret et masquable (UI_GUIDELINES) et son point d'insertion dans l'en-tête ; nouvel ADR (ADR-015 inchangé) qui
      crée les exceptions DB-IP (vérification sur option) et GitHub releases (vérification sur option, téléchargement
      sur clic), reprises dans `CLAUDE.md` / `ARCHITECTURE.md`. Pas de logique propre à GeoIP ni aux mises à jour.
      Fusionné le 2026-11-15 (ADR-025). Suivis : `.part` orphelins après un plantage jamais nettoyés (nouvel essai sur
      `AlreadyExists`, à traiter par P4.10, premier utilisateur de `download_to`) ; un champ mal typé de `settings.json`
      rejette tout le fichier (réglages remis à désactivé, sûr) ; `settings.json.tmp` à nom fixe ; retirer les
      `allow(dead_code)` d'`outbound.rs` / `online.rs` / `AppState::online` après P4.9 et P4.10.
- [x] **P4.9** `feat/geoip-prompt` — Proposer la base GeoIP au démarrage. Vérification locale, sans réseau :
      date de la base installée (métadonnées mmdb `build_epoch`) comparée au mois courant ; base absente ou antérieure
      au mois -> bandeau discret « Télécharger » / « Mettre à jour » (masquable jusqu'au mois suivant), qui lance le
      téléchargement existant (ADR-015). Réglage « Vérifier en ligne au démarrage », désactivé par défaut : activé, une
      requête HEAD vers l'URL DB-IP du mois confirme la disponibilité (échec réseau silencieux, aucun bandeau d'erreur) ;
      Exception DB-IP, client HTTP, réglages et bandeau fournis par P4.11 (dépendance). Demandé par l'utilisateur le
      2026-11-15, à livrer avant la publication de 0.1.0.
      Fusionné le 2026-11-15 (ADR-026 : mois DB-IP enregistré au téléchargement dans `dbip-country-lite.month`,
      masquage du mois par le serveur quand rien de plus récent). Suivis : la base du bundle n'a pas d'enregistrement de
      mois (bandeau « Mettre à jour » possible une fois si DB-IP l'a générée la veille ; `scripts/ci/geoip.sh` pourrait
      l'écrire) ; réponse réelle de DB-IP au `HEAD` non vérifiée à la main.
- [x] **P4.10** `feat/update-check` — Nouvelle version depuis les releases GitHub du dépôt. Bouton « Rechercher une
      mise à jour » dans « À propos » et réglage « Vérifier les mises à jour au démarrage », désactivé par défaut ;
      requête faite par l'API Rust (jamais la webview) vers la dernière release publiée (`releases/latest`, URL du dépôt
      fixée au build, HTTPS, tailles et redirections bornées, échec réseau silencieux au démarrage). Version plus récente
      -> bandeau discret avec le numéro et les notes (texte brut). Rien n'est téléchargé sans clic : « Télécharger »
      ouvre d'abord le dialogue natif d'enregistrement (plugin `dialog`), placé par défaut dans le dossier Téléchargements
      de l'utilisateur avec le nom de l'artefact adapté à la plateforme et au format installé (AppImage, .deb, .rpm,
      NSIS/MSI, .dmg) ; l'API Rust télécharge alors vers le chemin choisi (`.part` puis renommage), vérifie
      `SHA256SUMS.txt` (fichier supprimé si l'empreinte diffère) et affiche le chemin enregistré ; annulation du dialogue
      = aucun téléchargement. Installation manuelle par l'utilisateur (pas d'auto-installation ni de plugin updater,
      bundles non signés, ADR-011 ; confirmé par l'utilisateur). Mode web dev :
      lien en texte vers la page de la release. Exception GitHub, client HTTP, réglages et bandeau fournis par P4.11
      (dépendance) ; en parallèle de P4.9, avant la publication de 0.1.0. Demandé par l'utilisateur le 2026-11-15.
      Fusionné le 2026-11-15 (ADR-027). À vérifier sur la première release publiée après 0.1.0 : hôte réel de
      redirection des assets GitHub, détection du format installé (`bundle_type()`, AppImage/.deb/.rpm, NSIS/MSI),
      dialogue d'enregistrement et `downloadDir()` sur les trois systèmes. Suivis mineurs : lien de release coupé au
      trait d'union (`break-all` dans `ui/src/updates/parts.tsx`, mode web) ; `wait_imports` partage une seule borne
      `IMPORT_GRACE` entre imports et téléchargement.
- [~] **P4.12** `feat/release-title` — Titre de release : `scripts/release.sh X.Y.Z --title "..."` (message du tag
      annoté), repris par `release.yml` dans le nom de la release GitHub ; le bandeau de mise à jour affiche ce titre
      au lieu d'un extrait du changelog (notes complètes derrière « Notes de version »). Demandé par l'utilisateur
      le 2026-11-15 après la publication de 0.1.1.
- [x] **P4.6** `ci/release-pipeline` — Releases GitHub publiées par la CI sur tag `vX.Y.Z` : notes
      générées depuis l'historique des commits (Conventional Commits), bundles Linux (AppImage, .deb, .rpm),
      Windows (NSIS .exe, MSI) et macOS (.dmg), sommes SHA-256 ; version unique (workspace, Tauri, UI)
      vérifiée contre le tag ; script de préparation de version. Avancée hors vague, à la demande.

---

## Phase 5 — Onglets suivants

Découpage validé par l'utilisateur le 2026-11-15. Captures de référence fournies le même jour pour Documents,
FTP, Telnet, SSDP, SIP, ARP, Ethernet et WiFi (aucune pour Hosts). Chaque branche d'onglet commence par
écrire sa spec (`docs/specs/<onglet>.md`, gabarit de `docs/specs/README.md`) à partir de ces captures, en
reprenant les fonctionnalités et non le style (graphes illisibles, emoji, bulles ombrées, bouton « To Details »).
Au plus 4 agents en parallèle ; les ajouts voisins (navigation, routes, i18n, `shots.spec.ts`) se résolvent
en gardant les deux côtés.

### Vague 5.0 — Socle commun (séquentiel, avant les nouveaux onglets)

- [ ] **P5.1** `refactor/views-harmonize` — Tâche transverse notée après la vague 3.B : composant `Endpoint`
      commun, `CopyButton` partagé (16 px, cible 32 px), helper unique de barres horizontales avec valeurs,
      format d'heure, filtres dans l'en-tête de carte, tableaux en cartes sous `md`.
- [ ] **P5.2** `feat/time-filter` — Filtre temporel global : la plage choisie dans la Vue d'ensemble s'applique à
      toutes les vues (`from_us`/`to_us` dans l'API et l'URL, refetch serveur du zoom Overview, suivi de P4.2).
      Après P5.1.

### Vague 5.A — Couche 2 et protocoles simples (parallèle, après 5.0)

- [ ] **P5.3** `feat/arp` — Référence `arp.png`. Requêtes, réponses, ARP gratuits (compteurs et filtres),
      table IP <-> MAC dans le temps, conflits (une IP pour plusieurs MAC) et signes d'usurpation expliqués ;
      graphe lisible (réutiliser sigma de Network) ou tableau.
- [ ] **P5.4** `feat/ethernet` — Référence `ethernet.png`. Adresses MAC, constructeur d'après l'OUI (registre
      IEEE, licence et mode de mise à jour à vérifier, pas de fichier GPL), broadcast/multicast, VLAN, EtherTypes,
      volumes ; paires source -> cibles. Barres des constructeurs à la place des bulles.
- [ ] **P5.5** `feat/ssdp` — Référence `ssdp.png`. Messages NOTIFY / M-SEARCH / réponses, appareils UPnP (USN,
      types NT/ST, `SERVER`, `LOCATION`), émetteurs ; message brut dépliable. Le graphe de la référence est
      illisible : tableau groupé par appareil, graphe facultatif borné.
- [ ] **P5.6** `feat/sip` — Référence `sip.png`. Méthodes (graphe), dialogues et appels (INVITE -> BYE, durée,
      statut), REGISTER, user-agents (scanners comme `friendly-scanner`), messages bruts dépliables, flux RTP
      associés sans lecture audio, identifiants SIP Digest vers Credentials.
- [ ] **P5.7** `feat/compressed-captures` — Lecture `.zst` et `.lz4` (`netsift-capture`), comme `.gz` ; en
      parallèle de n'importe quelle vague.

### Vague 5.B — Protocoles à flux et fichiers (parallèle, après 5.A)

- [ ] **P5.8** `feat/ftp` — Référence `ftp.png`. Sessions de contrôle en transcription (commandes, réponses,
      arguments mis en évidence, `PASS` masqué par défaut comme dans Credentials), canal de données associé
      (PORT/PASV/EPRT/EPSV), fichiers transférés extraits dans `objects` (taille, sens, nom).
- [ ] **P5.9** `feat/telnet` — Référence `telnet.png`. Sessions en transcription (négociation d'options retirée,
      échos fusionnés, bornée), identifiants login/password vers Credentials (masqués).
- [ ] **P5.10** `feat/wifi` — Références `wifi-1.png` à `wifi-5.png`. Onglets : handshakes WPA (export hc22000,
      format actuel d'hashcat, au lieu de `.hccapx`), points d'accès (BSSID, SSID, canal, chiffrement,
      constructeur), broadcast, client à client, probe requests ; s'appuie sur le décodage 802.11/radiotap
      existant et sur l'OUI de P5.4.

### Vague 5.C — Vues d'agrégation (après 5.A et 5.B)

- [ ] **P5.11** `feat/documents` — Référence `documents.png`. Objets hors images (PDF, Office, archives,
      exécutables) venus d'HTTP, SMB et FTP : liste avec type, taille, origine, empreinte ; téléchargement
      seulement, jamais rendus dans la webview (ADR-016).
- [ ] **P5.12** `feat/hosts` — Sans référence. Fiche par hôte agrégeant tout (noms, MAC et constructeur, pays,
      flux, DNS, services, identifiants, fichiers) ; le composant `Endpoint` ouvre la fiche partout.

### Vague 5.D — Moteur (indépendante des onglets)

- [ ] **P5.13** `feat/append-chunks` — Ajout de chunks à une session existante : l'index de trame et donc les
      FlowId reprennent où ils s'étaient arrêtés (ADR-022), étapes de fin d'import rejouées (ADR-014, ADR-023).
- [ ] **P5.14** `feat/watch-folder` — Surveillance d'un dossier en direct, après P5.13.

Ordre suggéré : 5.0, puis 5.A (+ P5.7), puis 5.B, puis 5.C, puis P5.13 et P5.14.
