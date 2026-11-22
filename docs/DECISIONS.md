# Décisions d'architecture (ADR)

Format : contexte, décision, conséquences. Ajouter en fin de fichier, ne jamais réécrire une ADR
acceptée : la remplacer par une nouvelle qui la référence.

## ADR-001 — Application de bureau Tauri 2 + API HTTP locale

- Contexte : vraie application Linux/Windows, mais l'utilisateur veut aussi voir l'interface
  pendant le développement sans toolchain sur sa machine.
- Décision : frontend web unique (React) ; backend Rust exposé en HTTP (axum) ; en desktop,
  Tauri démarre l'API sur `127.0.0.1:<port aléatoire>` avec un jeton et affiche l'UI ;
  en dev, le même backend et Vite tournent dans le conteneur et l'UI s'ouvre dans le navigateur.
- Conséquences : un seul chemin de code pour les deux modes, API testable avec curl, SSE pour
  la progression. Le port local est protégé par jeton et non exposé hors loopback.
  Alternative écartée : IPC Tauri (pas de streaming simple, pas de mode navigateur).

## ADR-002 — Parsing 100 % Rust, sans libpcap / Npcap / tshark

- Contexte : build Windows en CI et local sans dépendance système ; entrées hostiles.
- Décision : `pcap-file` pour les formats, `etherparse` pour L2-L4, crates rusticata et parseurs maison
  au-dessus. Aucune capture live dans l'application.
- Conséquences : binaire autonome ; chaque protocole est à implémenter (pas de dissecteurs Wireshark) ;
  fuzzing indispensable. Aucun code GPL porté.

## ADR-003 — SQLite par session + blobs sur disque

- Contexte : sessions de plusieurs gigaoctets, usage solo, requêtes paginées et agrégées.
- Décision : un fichier SQLite (WAL) par session, writer unique par lots ; objets extraits stockés
  hors base, adressés par SHA-256.
- Conséquences : mémoire bornée, sessions portables (un dossier), requêtes rapides avec index.
  DuckDB écarté (taille du binaire, cross-compilation Windows plus complexe).

## ADR-004 — Toolchain exclusivement conteneurisée

- Contexte : pas de Rust ni de Node sur la machine de l'utilisateur.
- Décision : image `docker/Dockerfile` (Ubuntu 22.04, Rust épinglé, Node LTS, dépendances Tauri,
  Chromium Playwright) pilotée par `./x.sh`, compatible Docker et Podman. Un hook Claude Code bloque
  l'usage direct des toolchains sur l'hôte. Binaires Windows produits par la CI (`windows-latest`) ;
  cross-compilation locale expérimentale via `cargo-xwin` (`./x.sh desktop-win`).
- Conséquences : premier build de l'image long (~10 min), ensuite caches partagés (volume `netsift-cache`).

## ADR-005 — Interface en anglais par défaut, i18n fr dès le départ

- Contexte : vocabulaire réseau majoritairement anglais, utilisateur francophone.
- Décision : toutes les chaînes passent par un dictionnaire `en` / `fr` ; la langue suit l'OS,
  modifiable dans les réglages.

## ADR-006 — Intégration desktop : API embarquée, CSP et lints

- Contexte : P0.5. L'UI desktop doit joindre l'API locale sans exposer le jeton, sous une CSP stricte,
  et le crate Tauri doit compiler dans le gate du workspace sans build préalable de l'UI.
- Décision :
  - L'API est liée de façon synchrone sur `127.0.0.1:0` avant l'ouverture de la fenêtre ; jeton de
    256 bits (`getrandom`) ; l'UI obtient `{ base_url, token }` par la commande `get_api_endpoint`
    (import dynamique de `@tauri-apps/api`, absent du bundle web). CORS limité aux origines de la
    webview (`tauri://localhost`, `http://tauri.localhost`). Arrêt propre de l'API à `RunEvent::Exit`.
  - CSP : celle d'ARCHITECTURE, complétée de `style-src 'self' 'unsafe-inline'` (le rendu SVG
    d'ECharts pose des attributs `style`), `script-src 'self'`, `object-src 'none'`, `base-uri 'none'`,
    `form-action 'none'`, `frame-ancestors 'none'` et `ipc:` pour le pont Tauri ; aucune ressource
    distante. `dangerousDisableAssetCspModification: ["style-src"]` évite que les nonces injectés par
    Tauri n'annulent `'unsafe-inline'`. Le thème initial est appliqué par un script externe
    (`public/theme-init.js`), jamais inline ; Vite n'intègre aucun asset en `data:` (`assetsInlineLimit: 0`).
  - Le crate desktop n'hérite pas des lints du workspace : `unsafe_code = "deny"` au lieu de `forbid`
    (code généré par Tauri), pedantic conservé.
  - `build.rs` crée une page de remplacement `ui/dist/index.html` si l'UI n'est pas construite, pour que
    `cargo clippy/nextest --workspace` compile ; les bundles passent toujours par `cargo tauri build`,
    dont `beforeBuildCommand` construit la vraie UI.
- Conséquences : un seul chemin de code API pour dev, shots et desktop ; le jeton ne quitte jamais le
  processus (pas d'URL, pas de log) ; à revoir si une vue doit afficher des contenus distants (refusé).

## ADR-007 — Table de flux : chevauchements, expiration et fin de capture déterministes

- Contexte : P1.6. Les captures sont hostiles (chevauchements forgés, fragments incohérents) et
  P1.7 exige les mêmes tables quels que soient le découpage en chunks et le nombre de shards.
- Décision :
  - Chevauchements IP et TCP : **le premier arrivé gagne**. Un fragment ou un segment ultérieur
    ne fait que combler les trous ; les octets déjà reçus ou livrés ne sont jamais réécrits.
    Les fragments incohérents (longueurs de fin contradictoires, données au-delà de la fin,
    fragment non final de taille non multiple de 8, datagramme > 65 535 octets) font rejeter
    tout le datagramme. Un datagramme incomplet n'est jamais signalé.
  - Expiration **décidée à la recherche du flux**, à partir du seul flux : un paquet arrivant
    plus d'un timeout après le dernier paquet de son flux clôt celui-ci (`Timeout`, `last_ts` =
    dernier paquet) et ouvre un nouveau flux. Le balayage périodique ne fait que libérer la
    mémoire, avec une marge de 5 s, et produit le même `FlowCtx`. Même règle pour les fragments.
  - `FlowTable::finish_at(end_ts)` : à la fin, l'engine passe le dernier horodatage **global** ;
    les flux inactifs depuis plus que leur timeout finissent en `Timeout`, les autres en
    `EndOfCapture`.
  - Bornes mémoire comptées avec un surcoût fixe par morceau tamponné (64 octets) ; un segment
    tronqué par le snaplen saute immédiatement sa fin perdue (gap).
- Conséquences : l'ensemble des flux et des flux réassemblés ne dépend ni des chunks ni du
  nombre de shards, sauf l'éviction LRU (`max_flows`, par table) et des reculs d'horloge
  supérieurs à 5 s. `max_flows` et `max_defrag_bytes` sont des bornes par table : l'engine
  divise ses bornes globales par le nombre de shards.

## ADR-008 — Conventions JSON de l'API et contrat des sessions

- Contexte : vague 2.A, backend (P2.1) et vue Captures (P2.3) développés en parallèle ; les horodatages
  en nanosecondes (~1,7e18) et les identifiants de flux sur 63 bits dépassent la précision exacte des
  nombres JavaScript (2^53).
- Décision :
  - le contrat des routes sessions/import/SSE/fs est figé dans `netsift-api/src/contract.rs` (types
    ts-rs exportés vers `ui/src/api/types/`), modifiable seulement d'un commun accord ;
  - horodatages JSON en **microsecondes** (`*_us`, exacts jusqu'en 2255) ; la base garde les nanosecondes ;
  - identifiants pouvant dépasser 2^53 (flux, lignes) transmis en **chaînes** ; sessions en ULID ;
  - compteurs (octets, paquets) en nombres ; `TS_RS_LARGE_INT = "number"` pour que ts-rs n'émette pas
    de `bigint` (que `JSON.parse` ne produit jamais) ;
  - champs en `snake_case`, énumérations en chaînes minuscules, événements SSE étiquetés par `type` ;
  - progression lue par `fetch` en flux (pas `EventSource`, qui ne peut pas envoyer `Authorization`).
- Conséquences : aucune perte de précision côté UI ; conversions ns <-> µs aux frontières de l'API ;
  un champ ajouté au contrat se fait en ajout rétrocompatible (optionnel côté client).

## ADR-009 — Catégories d'adresses et GeoIP pendant l'import

- Contexte : P2.2 ; `hosts.category` et `hosts.country` alimentent filtres, légendes et cartes de
  plusieurs onglets (Overview, Hosts, réseau, carte du monde), développés plus tard en parallèle.
- Décision :
  - classification pure dans `netsift-geo` (`AddressCategory`), sans base, d'après les registres IANA
    des adresses à usage spécial ; libellés stables en minuscules stockés tels quels en base :
    `private`, `public`, `broadcast`, `multicast`, `link_local`, `loopback`, `cgnat`, `unspecified`,
    `reserved`. L'UI les associe à sa légende (`private` = « LAN », `link_local` = « Link-local ») ;
  - seul `255.255.255.255` est `broadcast` : le broadcast dirigé d'un sous-réseau est indécidable sans
    masque et garde la catégorie de sa plage ; les IPv4 mappées en IPv6 sont classées comme leur IPv4 ;
  - pays (ISO alpha-2) calculé **pendant l'import** par l'analyseur `core`, uniquement pour les adresses
    `public`, à partir d'un `Arc<GeoDb>` partagé par les shards (cache LRU borné) ; une session garde
    donc les pays de la base présente lors de son import ;
  - base absente ou invalide : pays inconnu, un avertissement par processus, l'import n'échoue jamais ;
    emplacement par défaut `<data_dir>/geoip/dbip-country-lite.mmdb`, surchargeable par
    `IngestOptions::geoip_path` ;
  - les tests construisent leurs bases mmdb avec un petit writer écrit d'après la spécification
    publique du format (feature `test-util` de `netsift-geo`), sans données sous licence.
- Conséquences : requêtes de filtrage par catégorie/pays en SQL pur (colonnes indexées) ; changer de base
  GeoIP n'affecte que les imports suivants ; ajouter une catégorie est un changement de contrat (UI, API).

## ADR-010 — Routes liées à une session

- Contexte : toutes les vues d'analyse (Overview, Sources, puis DNS, HTTP, ...) affichent une session ;
  l'URL doit être partageable et le retour arrière fiable, sans état global implicite.
- Décision :
  - les vues d'analyse vivent sous `/sessions/$sessionId/<vue>`, enfants code-splittés d'une route
    parente (`SessionLayout`) ; `/captures` et `/settings` restent hors session ;
  - la dernière session ouverte est mémorisée (identifiant ULID seul, clé `netsift.session.last`) ;
    la sidebar résout les entrées `scope: 'session'` vers la session de l'URL, sinon la dernière,
    et les désactive s'il n'y en a aucune ;
  - les chemins hérités (`/overview`, `/dns`, ...) redirigent vers la dernière session, sinon vers
    `/captures` ; une session inconnue (404) affiche un état « introuvable » et est oubliée.
- Conséquences (une dizaine de vues ajoutées en parallèle en phase 3) : chaque vue ajoute **une ligne**
  triée par chemin dans `NAV_ITEMS` (`scope: 'session'`, `src/app/nav.ts`) et **une ligne** triée dans le
  registre `SESSION_VIEWS` (`chemin -> import()` paresseux, `src/app/router.ts`) ; une entrée de
  navigation sans vue enregistrée reçoit le module d'attente partagé. La vue lit l'identifiant via
  `getRouteApi('/sessions/$sessionId')` ; ses filtres sont des paramètres de recherche sous ce chemin.

## ADR-011 — Publication des versions : version unique, notes git-cliff, release en trois temps

- Contexte : P4.6 ; publier des releases GitHub complètes (Linux, Windows, macOS) dont la version est
  exactement celle de l'application, avec des notes tirées de l'historique, sans `gh` et sans secret,
  depuis une procédure qu'un agent peut exécuter seul sans enfreindre « `main` n'est poussé que par
  `wt.sh merge --push` ».
- Décision :
  - **version unique** : `[workspace.package] version` de `Cargo.toml` ; les crates en héritent
    (`version.workspace = true`), Tauri la lit (aucune `version` dans `tauri.conf.json`), l'API la
    renvoie ; `ui/package.json` et `ui/package-lock.json` sont des copies synchronisées.
    `scripts/check-version.sh [vX.Y.Z]` vérifie tout (y compris `Cargo.lock` et le tag) dans le gate,
    `ci.yml` et en premier dans `release.yml` ; un suffixe SemVer donne une prerelease ;
  - **notes et CHANGELOG** générés par git-cliff (`cliff.toml`, groupes en français, fusions,
    `docs(roadmap)` et `chore(release)` exclus) : même version (2.14.2) en local (`./x.sh cliff`,
    installé dans le volume de cache, pas dans l'image) et en CI (`orhun/git-cliff-action`) ;
  - **procédure** `scripts/release.sh X.Y.Z` : branche `chore/release-X.Y.Z` (versions, lockfiles,
    CHANGELOG, commit), fusion par `wt.sh merge --push` (gate complet, seul chemin qui pousse `main`),
    puis tag annoté sur le commit de fusion et push du tag, seul déclencheur de `release.yml`.
    Non interactive, sans mode « sans push » (tests : clone jetable avec un remote bare local),
    nettoyage automatique en cas d'échec avant la fusion ; suivi sans jeton par
    `scripts/release-status.sh` (API publique GitHub) ;
  - **publication en trois temps** : `create` (brouillon + notes), `bundle` (artefacts du workflow),
    `publish` (tous les fichiers + `SHA256SUMS.txt` joints au brouillon, puis publication). Les
    bundles passent par les artefacts plutôt que d'être téléversés un par un : la release ne reçoit
    ses fichiers qu'une fois tous les bundles réussis. Build direct par `cargo tauri build` (pas
    `tauri-action`, qui ajoute des archives `.app.tar.gz` aux noms sans architecture) ;
    actions tierces épinglées par SHA (`softprops/action-gh-release`, `git-cliff-action`,
    `dtolnay/rust-toolchain`, `taiki-e/install-action`), `persist-credentials: false` ;
    `permissions: contents: write` sur `create` et `publish` seulement ; **aucun cache** (Rust ni
    npm) dans les builds de release : un binaire publié ne dépend jamais d'un cache ;
  - **bundle en échec** : un échec passager se relance (« Re-run failed jobs ») ; un échec qui
    demande une correction de code se règle en publiant `X.Y.Z+1` (le brouillon `vX.Y.Z` est
    supprimé, le tag reste) plutôt qu'en supprimant et réécrivant le tag publié ;
  - **bundles** : Linux `.AppImage`, `.deb`, `.rpm` (Ubuntu 22.04, glibc 2.35), Windows NSIS et MSI
    (pas de MSI pour une prerelease : WiX exige une version numérique ; deb et rpm ordonnent mal
    `X.Y.Z-pre`, donc prereleases déconseillées pour l'instant), macOS **universel** `.dmg`
    (un seul job sur `macos-15` : les runners Intel `macos-13` sont retirés), macOS 11 minimum ;
  - **pas de signature** (aucun certificat ni secret) : signature ad hoc macOS (`signingIdentity: "-"`)
    pour que l'app se lance sur Apple Silicon, sans notarisation ; avertissements SmartScreen et
    Gatekeeper documentés dans les notes de release.
- Conséquences : un numéro de version ne se modifie qu'à un endroit et ne peut pas diverger du tag ;
  la qualité des notes dépend des messages de commit ; une release en échec reste un brouillon sans
  fichiers ; signer plus tard (Windows Authenticode, Apple Developer ID + notarisation) demandera des
  secrets de dépôt et une nouvelle ADR ; la base GeoIP sera ajoutée aux bundles par P2.5.

## ADR-012 — Cycle de vie de l'application desktop

- Contexte : P2.5. L'application desktop doit démarrer sans console (release Windows), ne jamais perdre
  silencieusement un import à la fermeture, embarquer la base GeoIP et n'accorder à la webview que le
  strict nécessaire. Complète l'ADR-006 sans la remplacer.
- Décision :
  - instance unique (`tauri-plugin-single-instance`, premier plugin) : un second lancement met la fenêtre
    existante au premier plan et quitte pendant `build`, avant `setup`. Il n'appelle donc jamais
    `recover_interrupted` sur les imports de la première instance. Le verrou est tenu jusqu'à la fin du
    handler `RunEvent::Exit`, donc pendant l'arrêt de l'API ;
  - démarrage dans `setup`, dans cet ordre : répertoire de données (`dirs::data_local_dir()/NetSift`,
    avec `exports/`), `recover_interrupted`, résolution de la base GeoIP, démarrage de l'API, puis création
    de la fenêtre (`create: false`). Toute erreur s'affiche dans un dialogue natif (texte en/fr selon la
    locale de l'environnement), puis l'application quitte avec le code 1 ;
  - fermeture : si `ServerMonitor::running_imports() > 0`, la sortie est suspendue et un dialogue natif
    demande confirmation. Deux chemins partagent le même `CloseGate` et le même dialogue : la fermeture de
    la fenêtre (`CloseRequested`) et `RunEvent::ExitRequested` (Cmd+Q sous macOS, qui ne passe pas par la
    fenêtre). « Quitter » appelle `exit(0)`, dont la demande de sortie trouve le gate confirmé. La langue des dialogues est celle de l'UI, transmise par la
    commande `set_ui_language`. Le dialogue est natif et non dans l'UI, pour qu'une webview figée
    n'empêche jamais de quitter ;
  - arrêt à `RunEvent::Exit` : signal d'arrêt de l'API, puis attente bornée par `STOP_LIMIT`
    (`SHUTDOWN_GRACE` + `IMPORT_GRACE` + 2 s). Les imports annulés passent `incomplete`. Au-delà du délai,
    le processus quitte et la session restée `importing` est récupérée au démarrage suivant ;
  - GeoIP : la copie de `<données>/geoip/` est prioritaire (mise à jour sans réinstaller), sinon la base du
    bundle (`bundle.resources` -> `geoip/`). `release.yml` la télécharge (`scripts/ci/geoip.sh`, mois
    courant ou précédent) et échoue sans base valide : une release ne part jamais sans base. L'état est exposé par `GET /server-info` (`geoip.status`
    `available|missing|invalid`, `built_at_us`), qui est authentifié et décrit déjà la configuration du
    serveur. `/health` reste une sonde de vivacité sans E/S et sans authentification. Le fichier n'est
    rouvert que si sa taille ou sa date change ;
  - capabilities : `dialog:allow-open` et `opener:allow-open-path`, ce dernier limité à
    `$LOCALDATA/NetSift/exports`. `core:default` est retiré : l'UI n'appelle que ses propres commandes ;
  - `allow_any_path: true`, car les chemins viennent du dialogue natif. `max_imports` vaut 1 jusqu'à
    4 cœurs, sinon `DEFAULT_MAX_IMPORTS` ;
  - `freezePrototype` est conservé (tauri 2 ne gèle que `Object.prototype`, avant tout script). ECharts
    6.0/6.1 ne le supporte pas tel quel : à l'évaluation de son module, `mockMethods` de
    `lib/core/Scheduler.js` affecte `target.constructor` sur un `{}` (piège de l'« override mistake »),
    ce qui empêchait tout graphique de se charger dans l'AppImage (« Attempted to assign to readonly
    property. » sous WebKitGTK, correctif du 2026-11-08). Le plugin Vite `ui/vite-plugins/frozenPrototype.ts`
    remplace cette affectation par `Object.defineProperty` au build, et fait échouer le build si le code
    d'ECharts change. L'ancien test Vitest `freezePrototype.test.ts` est supprimé : il importait ECharts
    avant de geler (son runner ne supporte pas un prototype gelé), n'a donc pas vu ce défaut, et gelait
    le prototype d'un worker partagé. La référence est le test de fumée desktop (`ui/tests/desktop`),
    lancé par `./x.sh shots` sur la build de production sous WebKit (le moteur de WebKitGTK) et
    Chromium, avec le prototype gelé avant tout script et un faux pont Tauri ; il échoue sur toute
    erreur de page ou de console. Désactiver `freezePrototype` reste le dernier recours
    si une dépendance ne peut pas être corrigée : c'est une défense en profondeur, pas une exigence
    fonctionnelle.
- Conséquences : une fonctionnalité qui a besoin d'une nouvelle API Tauri côté JS ajoute la permission
  ciblée dans `capabilities/default.json`. Un export doit écrire sous `<données>/exports` pour pouvoir être
  ouvert. sigma et graphology ne sont pas encore vérifiés avec le prototype gelé : la vue du graphe
  réseau doit être ajoutée au test de fumée desktop.
- Vérifications manuelles (sur un bundle installé, à chaque release ou changement de `apps/desktop`) :
  1. Premier lancement : la fenêtre s'ouvre et `<données>/exports` est créé.
  2. Import d'un dossier puis d'un fichier unique par le dialogue système : progression, puis Overview.
  3. Fermeture pendant un import : « Continuer l'import » garde la fenêtre, « Quitter » ferme. Au
     lancement suivant, la session est `incomplete`.
  4. Même essai avec l'UI en français : dialogue en français.
  5. « Paramètres > À propos » : état GeoIP correct, avec et sans base.
  6. Aucune erreur CSP ou de permission dans la console de la webview ; `get_api_endpoint` et
     `set_ui_language` répondent sans `core:default`.
  7. Répertoire de données non inscriptible : dialogue d'erreur explicite, puis sortie.
  8. Double clic sur le bouton de fermeture pendant un import : un seul dialogue.
  9. macOS : Cmd+Q pendant un import affiche le même dialogue.
  10. Second lancement : la fenêtre existante revient au premier plan, aucune seconde fenêtre.
  11. Windows : aucune console ne s'ouvre.

## ADR-013 — Mise à niveau des sessions anciennes à l'ouverture

- Contexte : chaque analyseur de la phase 3 ajoute une migration de session (0100 DNS, 0200 HTTP, ...).
  L'ouverture en lecture seule exigeait un schéma à jour : une session importée avant une nouvelle
  migration renvoyait `SchemaOutdated`, traduit en erreur 500 opaque sur toutes les vues (Overview et
  `GET /sessions/{id}` compris), et la liste affichait 0 paquet.
- Décision :
  - l'API ouvre les sessions `ready` et `incomplete` par `Session::open_finished` : vérification en
    lecture seule (`write_needed`, aujourd'hui « schéma en retard »), puis, si une écriture est
    nécessaire, connexion en écriture (sans création de fichier) qui applique les migrations, puis
    réouverture en lecture seule. Les étapes de fin d'import en attente (ADR-014) font aussi partie de
    `write_needed` et s'exécutent dans `upgrade()`, après les migrations, sur la même connexion ; seule
    une migration en attente rend la session illisible. Chaque migration reste une transaction
    `BEGIN IMMEDIATE` qui vérifie d'abord qu'elle n'est pas déjà appliquée : deux ouvertures simultanées
    sont sérialisées et la migration n'est jamais appliquée deux fois ;
  - une session `importing` ou `failed` n'est jamais écrite par une lecture (ouverture en lecture seule
    stricte ; un schéma en retard y donne un 409 `conflict`) ;
  - les tables créées par une migration appliquée à une base qui avait déjà un schéma sont notées dans la
    méta `schema.tables_added_after_import`, dans la transaction de la migration
    (`migrate::migrate_with`). Les tables fantômes des tables virtuelles (FTS5 `*_data`, `*_idx`,
    `*_content`, `*_docsize`, `*_config`) ne sont pas notées. `traffic::count_rows` renvoie `None` pour ces tables comme pour une table
    absente : l'Overview omet le module, que l'UI affiche « non analysé » (`notRun`) et non « vide ».
    La règle porte sur les tables et non sur la méta `import.analyzers`, car un module ne correspond pas
    toujours à un seul analyseur (`openPorts` -> `ports`, `httpHeaders` -> `http`). Un import (mode
    `Import`, session vide) efface cette méta. Une future migration qui remplit elle-même une table
    (`INSERT ... SELECT` depuis des tables existantes) doit la retirer de cette méta dans son SQL, sinon
    le module apparaîtrait à tort « non analysé » ;
  - une session plus récente que l'application (`SchemaTooNew`) est refusée par un 409
    `urn:netsift:problem:session-too-new` ; l'échec de la mise à niveau (disque en lecture seule, fichier
    corrompu, migration en erreur) donne une 500 `urn:netsift:problem:session-upgrade-failed`, sans
    détail (chemins et SQL vont au journal). Le verrou d'écriture est attendu 30 s
    (`UPGRADE_BUSY_TIMEOUT`) ; au-delà, 503 `urn:netsift:problem:session-busy` avec `Retry-After` ;
  - un serveur en lecture seule (`--read-only`, « Disable every mutating route ») ne met **pas** à niveau :
    sans retour en arrière possible, une simple lecture rendrait la session illisible par la version
    précédente. Il renvoie un 409 `urn:netsift:problem:session-upgrade-needed`. Seules les captures
    (`./x.sh shots`, session de démo créée par la version courante) utilisent ce mode ; le desktop et
    `./x.sh dev` ne l'utilisent pas ;
  - l'UI traduit ces types (`errors.sessionTooNew`, `errors.sessionUpgradeFailed`,
    `errors.sessionUpgradeNeeded`, `errors.sessionBusy`).
- Conséquences : une session ancienne s'ouvre avec les nouveaux onglets présentés comme non exécutés ;
  il faut la réimporter pour les remplir. Une migration qui ajoute une colonne à une table existante
  laisse cette colonne vide (valeur par défaut) pour les lignes déjà importées : les vues doivent le
  tolérer. Une migration appliquée ne peut pas être annulée : une session mise à niveau ne s'ouvre plus
  avec la version précédente de l'application (`session-too-new`).

## ADR-014 — Étapes de fin d'import des analyseurs (`SESSION_FINALIZERS`)

- Contexte : P3.1 (DNS). Les shards sont routés par paire d'IP ; la réponse à une requête envoyée à une
  adresse de groupe (NBNS en broadcast, LLMNR, mDNS) vient d'un autre hôte, donc souvent d'un autre shard,
  parfois de plusieurs hôtes. Aucun shard ne peut apparier seul sans que le résultat dépende du nombre de
  shards. D'autres analyseurs auront le même besoin (tables dérivées, index de recherche).
- Décision :
  - registre `netsift_store::finalize::SESSION_FINALIZERS` de
    `Finalizer { id, version, after, fills, reads, run }`,
    **dans l'ordre d'exécution** : une étape figure après celles qu'elle cite dans `after` (vérifié par
    un test) ; entre étapes indépendantes, on ajoute à la fin. L'ordre n'est jamais alphabétique ;
  - le writer exécute les étapes une fois le dernier enregistrement écrit, sur sa connexion, chacune dans
    sa transaction avec la mise à jour de son marqueur `meta.finalizers` (`id:version` séparés par des
    virgules) ; une étape est idempotente et ne dépend pas de l'ordre d'arrivée des lignes ;
  - `run_finalizers(conn)` (publique, idempotente) n'exécute que les étapes absentes du marqueur ; elle
    sert à l'ouverture d'une session dont le marqueur est incomplet : import interrompu (arrêt brutal,
    `STOP_LIMIT` dépassé, session passée `incomplete` par `recover_interrupted`), étape en échec, ou
    nouvelle `version` d'une étape livrée par une mise à jour ;
  - ouverture (ADR-013) : `write_needed` signale aussi un marqueur incomplet, si bien que le chemin rapide
    en lecture seule passe par `upgrade()`, qui appelle `run_finalizers` après les migrations, sur la même
    connexion en écriture ; une étape en échec n'y est pas une erreur de mise à niveau (la session reste
    lisible, l'étape est retentée à l'ouverture suivante). Un serveur `read_only` n'écrit jamais : les
    étapes restent en attente et la session s'ouvre sans erreur, alors qu'une migration en attente y
    donne `upgrade-needed` ;
  - une étape remplit des tables (`fills`) à partir d'autres (`reads`) : sur une session mise à niveau
    après son import, les tables remplies sortent de `meta.schema.tables_added_after_import`, sauf si
    une table lue y figure encore (son analyseur n'a pas tourné : il n'y a rien à dériver) ;
  - une étape en échec **ne fait pas échouer l'import** : elle est annulée (rollback), signalée dans
    `WriterStats::finalize` et dans les journaux, son marqueur reste absent et l'ouverture suivante la
    retente ; les étapes qui la citent dans `after` sont reportées. Les données brutes de l'analyseur
    restent intactes : marquer toute la session `failed` (et la rendre illisible) pour une table dérivée
    serait disproportionné ;
  - DNS : l'analyseur n'apparie jamais dans un shard une requête envoyée à un groupe ; il l'émet
    `pending` (rcode `timeout` si une réponse est attendue, `NULL` sinon) et émet ses réponses seules.
    L'étape `dns` les apparie (réponse la plus ancienne dans la fenêtre `meta.dns.pair_window_ns`, lots de
    10 000 requêtes), construit `dns_pairs`, reconstruit `dns_fts` et complète `hosts.names` pour les hôtes
    déjà vus (sans évincer les noms d'autres sources).
- Conséquences :
  - coût : SQL ensembliste sur les tables de l'analyseur (DNS : linéaire en transactions, plus une
    recherche indexée par requête de groupe) ; pendant ces étapes, le writer publie l'étape en cours et le
    nombre d'étapes faites (`FinalizeWatch`), et l'import est dans une phase dédiée, `Phase::Finalizing`
    (P4.8) : l'événement SSE `progress` porte `phase = finalizing`, `step`, `steps_done` et `steps_total`,
    publié à chaque intervalle de progression et toujours une fois à la fin des étapes (même brèves) ;
    l'assistant d'import et l'indicateur de l'en-tête les affichent. Les étapes rejouées à l'ouverture
    d'une session (ADR-013) ne publient rien (aucun import en cours) ;
  - tant que le marqueur est incomplet, les vues de l'analyseur peuvent montrer des requêtes de groupe
    non appariées ; les tests d'acceptation comparent 1, 3 et 7 shards, fichier unique et chunks.

## ADR-015 — Mise à jour de la base GeoIP depuis l'application : seule sortie réseau

- Contexte : G1. La base DB-IP Country Lite est publiée chaque mois ; celle du bundle vieillit avec la
  version installée. L'utilisateur veut la remplacer depuis « Paramètres > À propos », par téléchargement
  ou par un fichier, alors que l'application s'interdit tout appel réseau sortant.
- Décision :
  - **seule exception** à « aucun appel réseau sortant » : `POST /api/v1/geoip/download`, déclenché
    uniquement par un clic de l'utilisateur, jamais au démarrage, jamais en tâche de fond, sans
    réessai automatique. Aucun autre code de l'application ne contacte un hôte extérieur ;
  - la requête part de l'API Rust (`reqwest` 0.13, déjà présent dans l'arbre via Tauri, TLS rustls
    + `ring`, certificats vérifiés par `rustls-platform-verifier` avec le magasin du système, sans
    OpenSSL). La webview n'accède jamais au réseau : CSP et capabilities Tauri inchangées ;
  - cible fixe `https://download.db-ip.com/free/dbip-country-lite-AAAA-MM.mmdb.gz` (mois courant UTC,
    puis le précédent sur 404, comme `scripts/ci/geoip.sh`) ; HTTPS seulement, au plus 3 redirections
    et seulement vers la même origine, délais de connexion (15 s), de lecture (30 s) et total (300 s) ;
    `User-Agent: NetSift/<version>`, ni cookie, ni identifiant, ni autre donnée ; proxy des variables
    d'environnement respecté ;
  - tailles bornées pendant la lecture : 32 Mio compressés (`MAX_COMPRESSED_BYTES`), 64 Mio décompressés
    (`MAX_DB_BYTES`, la base fait environ 10 Mio) ;
  - import d'un fichier `.mmdb` ou `.mmdb.gz` (`POST /api/v1/geoip/import { path }`) : dialogue natif en
    desktop (chemin quelconque), racines autorisées en mode dev web, comme l'import de captures ;
  - validation avant remplacement (`netsift_geo::install`) : la base s'ouvre, son `database_type`
    désigne une base pays, des recherches de contrôle (8.8.8.8, 1.1.1.1, 9.9.9.9, 2001:4860:4860::8888)
    répondent sans erreur et au moins une donne un pays ; puis écriture dans un fichier temporaire de
    `<données>/geoip/`, `fsync`, renommage atomique vers `dbip-country-lite.mmdb`. Un échec laisse
    l'ancienne base intacte ;
  - la copie utilisateur `<données>/geoip/dbip-country-lite.mmdb` est lue en premier, la base du bundle
    (`ApiConfig::geoip_fallback_path` en desktop) sert de repli et n'est jamais écrite ;
  - rechargement à chaud : l'API garde la base chargée (`Arc<GeoDb>`) et la remplace après une
    installation ; chaque import reçoit au démarrage la base du moment (`AnalyzerConfig::geo`) et la
    garde jusqu'à sa fin. Un fichier remplacé hors de l'application est détecté par taille, date de
    modification et inode (Unix) ;
  - une seule mise à jour à la fois (409 `geoip-update-running`), routes refusées en `--read-only`,
    erreurs `problem+json` sans chemin ni détail interne (`geoip-download-failed`, `geoip-invalid`,
    `geoip-too-large`), progression par `GET /api/v1/geoip/update`.
- Conséquences :
  - les pays des sessions déjà importées ne changent pas (ADR-009) : l'UI invite à réimporter ;
  - l'hôte contacté (download.db-ip.com) est affiché à côté du bouton ; le test du téléchargement réel
    reste manuel, les tests automatiques utilisent un serveur HTTP local ;
  - `deny.toml` admet `CDLA-Permissive-2.0` pour la seule crate `webpki-root-certs` (données, tirée
    par `rustls-platform-verifier` pour wasm32 uniquement, absente de nos binaires).

## ADR-016 — Objets extraits : sélection, budget, miniatures et affichage

- Contexte : P3.6 (Pictures). Les corps HTTP sont des entrées hostiles et peuvent contenir des secrets
  (formulaires, jetons) ; P3.2 ne les écrivait jamais sur disque (`store_bodies = false`). La vue doit
  montrer des images sans que la webview ne charge jamais un contenu extrait.
- Décision :
  - sélection (`netsift_analyze::http::objects::selected`, documentée dans `HttpConfig::store_bodies`,
    activé par défaut) : seuls les corps de **réponse** lus et décodés en entier (pas de `206`), dont le
    **contenu** est une image par signature (PNG, JPEG, GIF, WebP, BMP, ICO, SVG ; le `Content-Type` annoncé
    est ignoré), entre `object_min_bytes` (32 o) et `object_max_bytes` (16 Mio), sont confiés à `put_blob`.
    Pages, scripts, formulaires, téléversements et corps de requête n'arrivent jamais sur disque ;
  - rétention en mémoire (`HttpConfig::max_retained_bytes`, par shard) : seule une réponse qui peut
    devenir un objet est gardée au-delà de son aperçu (`Retain::Image`, au plus `object_max_bytes`).
    Requêtes, réponses `206` et corps annoncés plus grands que `object_max_bytes` ne gardent que
    l'aperçu (`preview_bytes`, au moins 512 o). Dès que 512 octets sont décodés, un corps sans signature
    d'image retombe à l'aperçu et rend le reste au budget ; un corps qui ne peut plus être gardé en entier
    (budget, taille, trou, décodage arrêté) rend aussitôt ce qui dépasse l'aperçu. Un gros téléchargement
    ne prive donc plus les images servies en parallèle sur le même shard (test e2e sur 1 et 4 shards) ;
  - budget de session : `IngestOptions::max_blob_bytes` (1 Gio) partagé par tous les shards
    (`AtomicU64`), qui ne débite que les fichiers nouveaux (contenu déjà présent gratuit) et seulement
    les objets (`RecordSink::put_object`, méthode par défaut ajoutée au trait, qui délègue à
    `put_blob`) ; les certificats TLS, déjà bornés par leur analyseur, passent par `put_blob` et ne sont
    pas débités. Au-delà, `put_object` renvoie `None` : la transaction garde ses métadonnées. Seule
    exception à l'indépendance vis-à-vis du nombre de shards : quand le budget est atteint, les objets
    retenus dépendent de l'ordre d'arrivée ;
  - table `objects` (migration 0700) : une ligne par SHA-256, dérivée de `http_transactions` par l'étape
    de fin d'import `objects` (ADR-014) ; première apparition = plus petit `(heure de réponse, flow_id,
    seq)`, nombre d'occurrences et dernière heure agrégés ; `id` suit l'ordre d'apparition (clé de
    pagination). Upsert qui conserve les colonnes de miniature. Vue SQL `pictures` (images) comptée par
    l'Overview ; une session importée avant P3.6 la montre « non analysée » ;
  - miniatures (`netsift_engine::thumbs`) : crate `image` avec les seuls codecs purs Rust nécessaires,
    format pris de la signature, `Limits` (16 384 px par côté, 64 Mio d'allocation) vérifiées sur
    l'en-tête avant toute allocation (bombe de dimensions ou de décompression), entrée ≤ 16 Mio, panique
    d'un codec rattrapée (`catch_unwind`). Générées **après** le writer et ses étapes de fin d'import, hors
    des shards (le décodage coûte bien plus que l'analyse), par lots de 256 (keyset sur `id`), sur
    2 threads (certains décodeurs, comme le JPEG progressif, gardent des tampons non comptés), arrêtées
    par l'annulation et après 60 s ; PNG ≤ 320 px dans `thumbs/<aa>/<sha256>.png`, état `ready`/`failed`
    et dimensions dans `objects`. Ce qui reste `pending` (import annulé, délai) est rendu à la demande
    par l'API (au plus 2 décodages simultanés), puis enregistré (fichier, état, dimensions) sauf sur un
    serveur en lecture seule. Le SVG n'est jamais rastérisé (`none`) ;
  - API : `GET /sessions/{id}/objects` (+ `/stats` ; extrémités client et serveur en DTO `Endpoint`), `.../objects/{sha256}/thumb` et `/preview`
    (PNG ré-encodés par nous, 320 et 1 600 px, `image/png` + `nosniff`), `.../objects/{sha256}` en pièce
    jointe toujours typée `application/octet-stream`, `CSP: sandbox`, `nosniff`, `no-store`, nom de
    fichier assaini et extension du type détecté, taille du blob vérifiée (409 sinon) ;
  - UI : les PNG sont lus par `fetch` (jeton en en-tête) puis affichés en URL `data:image/png`, autorisée
    par `img-src` (ADR-006). Une balise `<img src="http://127.0.0.1:…">` exigerait le jeton dans l'URL,
    ce qu'ADR-006 exclut ; `blob:` n'est pas dans la CSP. L'original n'est jamais affiché, seulement
    téléchargé.
- Conséquences : les images apparaissent à la fin de l'import (étape de fin d'import puis miniatures,
  pendant la phase `finishing`) ; une session très riche en images allonge cette phase d'au plus 60 s.
  La mémoire des corps reste bornée par `max_retained_bytes` par shard (un budget global est un suivi de
  P4.2) ; hors images, un corps n'y occupe que son aperçu.

## ADR-017 — Rôles de serveurs dérivés à la lecture (vue SQL `server_evidence`)

- Contexte : P3.8 (Servers). Un rôle d'infrastructure (DNS, DHCP, LDAP, NTP, Kerberos, SMB, HTTP) se
  prouve surtout par des données que d'autres analyseurs stockent déjà (`dns_messages`, `open_ports`,
  `flows`, `smb_sessions`, `smb_announces`, `http_transactions`, `hosts.names`). Seuls DHCP, NTP et
  Kerberos n'avaient aucune table. Matérialiser une table de rôles par une étape de fin d'import
  (ADR-014) aurait dupliqué ces données et obligé à rejouer l'étape à chaque nouvelle source de preuve.
- Décision :
  - l'analyseur `servers` n'enregistre que ce qui manque : `dhcp_messages` (un message par ligne),
    `ntp_responses` et `kerberos_replies` (repliées par serveur, client et type, upserts commutatifs) ;
  - les rôles ne sont **jamais stockés** : la vue `server_evidence (role, ip, kind, count, clients,
    first_ts, last_ts, example)` les dérive à la lecture, une ligne par serveur, rôle et type de preuve
    (`dns_response`, `open_port`, `dns_srv`, `dhcp_offer|ack|nak`, `ntp_response`,
    `kdc_as_rep|tgs_rep|error`, `smb_session`, `browser_server`, `browser_dc`, `http_response`). La vue
    `server_roles` (une ligne par rôle et serveur) alimente le compteur de l'Overview, lu à chaque
    résumé : elle reprend les mêmes sources et conditions en simples `SELECT DISTINCT` (`UNION`), sans
    agrégat ni exemple, et un test vérifie qu'elle donne les mêmes paires que `server_evidence` ;
  - l'API borne les serveurs **par rôle** en SQL (`row_number() OVER (PARTITION BY role ...)`), après
    le filtre de catégorie : un balayage HTTP de milliers de répondeurs ne masque jamais DHCP ou
    Kerberos. Un serveur absent de `hosts` (sans catégorie stockée) passe le filtre SQL et l'API le
    filtre d'après son adresse ;
  - DHCP relayé : quand les deux étapes d'une réponse sont capturées (serveur vers relais, puis relais
    vers client, émise depuis `giaddr`), l'étape du relais n'est pas comptée ;
  - LDAP n'a pas de parseur ici : port 389/636/3268/3269 vu ouvert, ou cible d'un SRV `_ldap._tcp` /
    `_gc._tcp` dont le nom a été appris par un hôte (`hosts.names`, rempli par l'étape `dns`) ;
  - seule étape de fin d'import : `servers` (après `dns`, pour que le remplissage de `hosts.names`
    reste déterministe quand un hôte atteint la limite de noms), qui apparie le nom d'hôte DHCP (option 12, souvent dans un
    DISCOVER/REQUEST diffusé) à l'adresse de l'ACK de la même transaction (xid, MAC) et complète
    `hosts.names` des hôtes déjà vus, comme l'étape `dns` ;
  - la migration 0800 ajoute deux index couvrants sur des tables d'autres analyseurs
    (`dns_messages_responder`, `http_transactions_server` partiel) pour que la vue reste indexée ;
  - session mise à niveau (ADR-013) : `server_evidence` figure dans `meta.schema.tables_added_after_import`,
    l'API répond `analyzed: false` sans rien lister (pas de demi-résultat DNS/SMB) et l'Overview affiche
    le module « non analysé ».
- Conséquences :
  - une nouvelle preuve est une branche `UNION ALL` de plus dans une nouvelle migration (la vue est
    recréée), sans réimport si ses données existent déjà ;
  - coût : chaque lecture de la vue Servers évalue `server_evidence` une fois (agrégats indexés, une
    sous-requête corrélée par serveur pour les exemples), le résumé d'Overview n'évalue que
    `server_roles`. **Mesure sur une session de 10 M paquets à faire en P4.2** ;
  - les index `dns_messages_responder` et `http_transactions_server` appartiennent à 0800 : une future
    migration DNS ou HTTP qui recrée sa table (`CREATE TABLE ... AS`, copie puis renommage) doit les
    recréer. Sur une session ancienne mise à niveau à l'ouverture (ADR-013), la migration 0800
    construit l'index de `dns_messages` (lecture complète de la table, quelques secondes sur des
    millions de transactions) pendant la première ouverture ;
  - les tables lues par la vue ne peuvent plus être renommées sans recréer la vue (SQLite réécrit les vues
    lors d'un `ALTER TABLE ... RENAME`) ; une migration qui supprime une de ces tables doit aussi supprimer
    ou recréer la vue.

- Mise à jour P4.2 (ADR-023) : la vue dérivait les rôles à chaque lecture (1,1 s pour la vue Servers,
  250 ms pour les rôles du graphe et 320 ms de chaque résumé de session sur 8,9 M paquets). Depuis la
  migration 0801, les deux vues gardent leur SQL sous les noms `server_evidence_source` et
  `server_roles_source`, et l'étape de fin d'import `servers` (version 2) les copie dans des tables qui
  portent les anciens noms : les lectures sont inchangées, une source de preuve ajoutée plus tard
  demande une nouvelle version de l'étape.

## ADR-018 — Graphe Network : graphe borné, replié en fin d'import, disposition en Web Worker

- Contexte : P3.9. Une session peut compter des milliers d'hôtes ; sigma.js (WebGL) reste fluide jusqu'à
  quelques milliers de nœuds, mais le graphe devient illisible bien avant (défaut principal de la
  référence) ; la disposition ForceAtlas2 bloque le fil principal si elle y tourne ; la CSP desktop
  (`script-src 'self'`, ADR-006) et le prototype gelé de Tauri contraignent les dépendances. Une
  première version repliait le graphe à la lecture depuis `conversations` (trois à quatre parcours par
  requête) : environ 1 s par requête à 50 000 conversations et 17 s à 500 000, mesurés en revue
  (SQLite 3.50, cache chaud), loin de la cible de 300 ms. Même le seul cumul des octets par adresse
  coûte environ 1 s à 500 000 conversations.
- Décision :
  - **matérialisation en fin d'import** : l'étape `network` (`SESSION_FINALIZERS`, ADR-014) replie
    `conversations`, `hosts` et `host_traffic` dans les tables de `0900_network.sql`. Les arêtes y sont repliées par (nœud client, nœud serveur, groupes de protocoles en masque de bits,
    catégories des deux extrémités, IPv6) : une requête lit quelques milliers de lignes (table
    `network_edges`, index pour le reste) et finit le repli en mémoire. Résultat déterministe (égalités
    départagées par l'adresse), idempotent, indépendant de l'ordre d'arrivée ; une session mise à niveau
    rejoue l'étape à l'ouverture (ADR-013) ;
  - **mémoire de l'étape bornée quel que soit le nombre d'hôtes** : un scan ou un flood à sources
    usurpées peut amener des millions d'adresses, et un import tourne avec `temp_store = MEMORY` (un tri
    ou un `GROUP BY` SQLite garderait alors toutes les lignes en mémoire). L'état par hôte vit donc dans
    `network_hosts`, sur disque, et aucune instruction ne trie ni ne groupe une table d'hôtes ou de
    conversations : (1) lecture de `conversations` dans l'ordre de stockage, octets et groupes cumulés
    par adresse dans la table de travail `network_ends` (un upsert par extrémité), puis fusion avec
    `hosts`, les deux lus dans l'ordre des adresses par index, un hôte à la fois en mémoire, inséré dans
    l'ordre de la clé primaire ; (2) une passe dans l'ordre des rangs (index `network_hosts_bytes`) à état constant
    (compteur par groupe et par pays), qui ne met à jour que les hôtes relus par le graphe (hôtes à clé,
    30 premiers de chaque pays) ; (3) une passe sur `conversations`, extrémités trouvées par clé
    primaire, repli dans des tables de hachage indexées par clés de nœud (hôtes à clé, pays, « autres »,
    hôtes dépliables) ; (4) comptage des hôtes par clé de nœud sur un simple parcours. Tests : identité
    avec une implémentation de référence en mémoire sur une session aléatoire pleine d'égalités,
    idempotence, indépendance à l'ordre d'arrivée, plans de requête sans tri, tailles des tables en
    mémoire identiques à 1 000 et 10 000 adresses usurpées. Coût : un passage par SQLite par extrémité
    et par hôte, plus lent que l'agrégation en mémoire de la première version (3,8 s à 500 000
    conversations, mesurés sur une base en mémoire), mais le pic de mémoire de l'étape reste de
    quelques Mio à 650 000 hôtes ;
  - **hôtes à clé** : un hôte garde son adresse comme clé s'il est parmi les 150 plus volumineux, ou
    parmi les 150 plus volumineux ayant l'un des groupes de protocoles. Les N premiers hôtes ayant du
    trafic qui passe un filtre protocole sont donc toujours à clé (un hôte dans les N premiers d'un
    filtre l'est aussi dans chacun de ses groupes). Les autres hôtes publics géolocalisés sont repliés
    par pays, le reste dans « autres » ;
  - **bornes** : en mode hôtes, les `limit` premiers hôtes (40 par défaut, 10 à 150) qui passent les
    filtres, classés par octets toutes conversations confondues, ont leur nœud, les autres hôtes publics
    forment un nœud par pays (15 au plus, les plus gros), le reste un nœud « autres ». Un pays déplié
    (`expand`) ajoute ses 30 plus gros hôtes (table `network_expand`, leur trafic retiré du nœud pays).
    En mode pays : un nœud par pays, plus « LAN et local » et « pays inconnu ». Au plus 400 arêtes non
    orientées, les plus volumineuses ; les orphelins (hôtes sans trafic retenu par le filtre protocole)
    sont comptés, et 30 au plus sont listés sur demande ;
  - **filtre protocole** : une conversation est retenue si elle porte une étiquette d'un des groupes
    choisis (DNS, HTTP, HTTPS = `tls`, SSH, FTP, Telnet, RDP, SMB = `smb` + `netbios`, TCP, UDP,
    Autres) ; ses octets comptent en entier, `conversations` ne les ventilant pas par protocole (l'UI
    le signale). Le filtre de catégorie garde les arêtes dont les deux extrémités passent ;
  - **disposition** : ForceAtlas2 de `graphology-layout-forceatlas2`, itérations fixes (150 à 600 selon
    la taille), départ déterministe (cercle par rang), puis figée. Elle tourne dans un worker module
    servi par l'origine de l'application (`new Worker(new URL('./layout.worker.ts', import.meta.url))`),
    pas dans le worker `blob:` fourni par la bibliothèque, que `script-src 'self'` refuse ; repli sur le
    fil principal si le worker manque, échoue ou ne répond pas en 5 s (graphe borné, quelques dizaines
    de ms) ;
  - **repli sans WebGL** : la vue teste un contexte WebGL ; sans lui (webview sans accélération), et
    sous 768 px, elle liste les liens classés par octets au lieu d'un canevas vide ;
  - sigma reste en 3.0.2 (`docs/STACK_VERSIONS.md`) ; la 4.0, publiée fin octobre 2026, change d'API et
    fera l'objet d'une montée de version dédiée. Les nœuds sont des disques colorés par catégorie
    d'adresse : la forme par catégorie (`NodeShape` de la palette) demande des programmes WebGL
    sigma dédiés, reportés. L'export PNG/SVG de la spec est reporté.
- Mesures (test `network::tests::timings`, build release, base sur disque avec les réglages d'un import
  (WAL, cache de 64 Mio, `temp_store = MEMORY`), session synthétique : 500 hôtes LAN, 20 pays,
  7 combinaisons de protocoles, 40 % d'adresses publiques distinctes) :

  | Conversations | Hôtes | Étape de fin d'import | Pic mémoire de l'étape | Graphe par défaut | HTTPS | Dépliage + orphelins | Pays | Détail d'hôte |
  |---|---|---|---|---|---|---|---|---|
  | 50 000 | 17 000 | 0,4 s | + 4 Mio | 21 ms | 6 ms | 21 ms | 2 ms | 1 ms |
  | 500 000 | 162 000 | 5,7 s | + 4 Mio | 35 ms | 9 ms | 30 ms | 2 ms | 7 ms |
  | 2 000 000 | 648 000 | 33 s | + 3 Mio | 32 ms | 11 ms | 35 ms | 3 ms | 37 ms |

  À 2 000 000 conversations, l'étape se partage entre les hôtes (17 s), le repli (14 s) et les rangs
  (2 s) : les lectures par clé débordent du cache de pages.

  Avant : environ 1 s (50 000) et 17 s (500 000) par requête par défaut.
- Conséquences : les requêtes du graphe ne dépendent plus du nombre de conversations mais du nombre de
  clés repliées (`network_edges` : environ 21 000 lignes à 500 000 conversations) ; l'import paie
  l'étape une fois, dans sa phase `finishing` (environ 11 µs par conversation à 500 000, 16 µs à
  2 000 000). Les nombres d'hôtes par
  nœud ne tiennent pas compte du filtre de catégorie au-delà des deux extrémités d'une arête (un hôte
  dont toutes les conversations sont écartées par ce filtre n'est ni dessiné ni orphelin) ; les
  étiquettes de protocole d'un nœud pays dont on a déplié des hôtes peuvent garder celles de ces hôtes.
  Une requête abandonnée par l'UI n'interrompt pas son calcul côté serveur (borné à quelques dizaines
  de ms). Les rôles serveur d'un hôte (`roles`, ADR-017) sont lus à la requête dans la vue
  `server_roles`, pour les seuls hôtes dessinés (au plus 210) ou détaillés ; leur coût sur une grosse
  session est à mesurer avec celui de la vue (P4.2). Ils s'affichent en badges dans le panneau de
  détail ; la forme « serveur » du nœud reste reportée avec les formes par catégorie.

## ADR-019 — Identifiants : table `credentials` repliée par empreinte, secrets servis à la demande

- Contexte : P3.7 (Credentials). Depuis P3.5, `Record::Credential` est un contrat commun à tous les
  émetteurs, abandonné par le moteur faute de table. Les secrets en clair (FTP, SMTP, HTTP Basic, SNMP...)
  et le matériel récupérable hors ligne (NetNTLM, CRAM-MD5) sont les données les plus sensibles de
  l'application ; certains se répètent à chaque paquet (community SNMP d'un poller, en-tête Basic de
  chaque requête).
- Décision :
  - **émetteurs** : `smb` (NTLMSSP, P3.5), `http` (`Authorization` / `Proxy-Authorization` Basic,
    NTLM / Negotiate apparié au CHALLENGE du `WWW-Authenticate` précédent de la connexion, formulaires
    `application/x-www-form-urlencoded` et chaînes de requête ayant un champ de mot de passe) et le nouvel
    analyseur `credentials` (FTP `USER`/`PASS`, SMTP `AUTH`, POP3 `USER`/`PASS`/`APOP`/`AUTH`, IMAP
    `LOGIN`/`AUTHENTICATE` avec SASL PLAIN, LOGIN et CRAM-MD5, LDAP simple bind via `ldap-parser`, SNMP
    v1/v2c via `snmp-parser`). Reconnaissance par port connu (les deux extrémités sont essayées pour une
    connexion prise en cours de route). Une identification attend la réponse du serveur à la commande
    qui l'a complétée pour noter `result = accepted | rejected` (sinon émise sans résultat en fin de
    flux). Au plus 128 identifiants par flux, communities SNMP comprises (compteur par flux UDP) ;
    lignes (4 Kio), messages BER (4 Kio, au-delà ils sont sautés sans être mis en mémoire) et liaisons
    LDAP en attente (8) bornés. Un défi CRAM-MD5 qui n'est pas du base64 valide ne donne pas de ligne
    hashcat ; une réponse CRAM-MD5 sans séparateur ne donne pas de compte ;
  - **stockage** : migration 0600, table `credentials` `WITHOUT ROWID`, clé `fingerprint` = SHA-256
    (calculé par le moteur, champs préfixés par leur longueur) du protocole, du type, des IP client et
    serveur, du port serveur, de l'identité (compte, domaine), du secret et de la ligne hashcat. Les
    observations identiques sont **repliées** : `seen_count` additif, `first_ts`/`last_ts` min/max, et le
    flux, le port client, la station et les détails de l'observation la plus ancienne (départage par
    identifiant de flux puis détails), upsert commutatif donc indépendant des shards et du découpage. Les
    détails non secrets sont un tableau JSON de paires `[clé, valeur]`. Aucune étape de fin d'import ;
  - **identifiant public** : l'empreinte dérive du secret sans clé (un dictionnaire retrouverait une
    community ou un mot de passe faible à partir d'elle) : elle ne sort jamais de la base (ni API, ni
    curseur de pagination, ni `Debug`). Une entrée est désignée par `id`, 16 octets aléatoires en hexa
    (`randomblob`) fixés par la première insertion et jamais modifiés : liste, URL de détail, `ids=` de
    l'export et curseur keyset (`first_ts, id`). Alternative écartée : un HMAC de l'empreinte avec une clé
    aléatoire par session dans `meta`, déterministe mais qui oblige à distribuer la clé aux shards, pour
    un gain nul (l'identifiant n'a pas à être stable d'un import à l'autre) ;
  - **API** : la liste (keyset `first_ts, id`, filtres `protocol`, `state`, `mode` en clauses
    statiques indexées), les statistiques et les chemins agrégés client -> protocole -> serveur (top N
    + « autres ») ne lisent **jamais** les colonnes `secret` et `hashcat_line`. Le secret d'une entrée
    est servi par `GET /credentials/{id}` (dépliage d'une carte) ; l'export par
    `GET /credentials/export?format=csv|hashcat` (sélection `ids=`, 500 au plus, ou filtres), jamais
    tronqué : au-delà de 10 000 entrées correspondantes il est refusé (400) et l'UI le dit dans la
    confirmation au lieu de proposer l'export,
    en pièce jointe `no-store` + `CSP: sandbox`. Un fichier hashcat ne contient qu'un mode (`mode=`
    obligatoire), une ligne par entrée. En CSV, une cellule commençant par `=`, `+`, `-`, `@`, tabulation
    ou retour chariot reçoit une apostrophe initiale (pas d'évaluation de formule dans un tableur) : la
    valeur exacte reste disponible dans le détail et l'export hashcat. Routes en `GET` : elles marchent
    sur un serveur `--read-only` ;
  - **journaux** : `Credential`, `CredentialRow` et `CredentialSecret` ont un `Debug` manuel qui masque
    secret, ligne hashcat et empreinte ; l'état interne des analyseurs (tampons de lignes et BER, flux en
    cours, community SNMP) n'affiche que des longueurs et compteurs. Aucune route ni aucun analyseur ne
    journalise un identifiant. Un test d'intégration
    (`netsift-engine/tests/credentials_logs.rs`) capture tout `tracing` (niveau TRACE) pendant un import
    de tous les émetteurs et y cherche chaque secret stocké ;
  - **UI** : `SecretValue` masqué par défaut ; l'export demande une confirmation et laisse un bandeau
    « contient des données sensibles » tant que la vue est ouverte.
- Conséquences :
  - une entrée regroupe des observations de plusieurs flux : son `flow_id` et ses détails (verdict du
    serveur, version SNMP, type de PDU) sont ceux de la première. Un second essai avec le même secret
    refusé puis accepté reste une seule entrée avec le verdict du premier ;
  - un SNMP `SetRequest` n'est pas distingué d'un `GetRequest` à communauté égale (même entrée, PDU de la
    première observation) ;
  - les formulaires JSON, HTTP Digest, Kerberos (AS-REQ pré-authentifié, mode 7500/18200), SASL NTLM / GSS
    dans LDAP et SMTP, Telnet et les poignées de main Wi-Fi ne sont pas encore émis ; `handshakes` vaut 0 ;
  - sessions mises à niveau (ADR-013) : la table créée à l'ouverture est vide, l'Overview affiche le module
    « non analysé » et `GET /credentials/stats` répond `analyzed: false`.

## ADR-020 — Fuzzing : crate `fuzz/` hors workspace, feature `fuzzing`, outils épinglés dans le cache

- Contexte : P4.1. Les captures sont des entrées hostiles ; chaque parseur et chaque analyseur doit être
  fuzzé (cargo-fuzz, libFuzzer), ce qui exige une nightly et des drapeaux d'instrumentation, alors que le
  workspace est épinglé sur la stable 1.99.1. Beaucoup de parseurs sont privés à leur module (NTLMSSP,
  PDU SMB, datagrammes NetBIOS, communautés SNMP, identifiants HTTP). L'image de dev n'a pas de nightly,
  son `RUSTUP_HOME` n'est pas inscriptible par l'utilisateur du conteneur et le conteneur est éphémère.
- Décision :
  - **crate `fuzz/` hors workspace** (`exclude` du `Cargo.toml` racine, son propre `[workspace]` et son
    `Cargo.lock`) : 17 cibles au niveau de l'API la plus basse et pure possible, plus des cibles qui
    pilotent les analyseurs par leur interface publique `Analyzer`, comme le moteur (`on_stream` direct
    ou table de flux alimentée par des trames forgées), et une cible de bout en bout sans SQLite. Il
    dépend de `analyze`, `capture`, `engine`, `geo` ; `fixtures` en dépendance de développement pour le
    générateur de graines (`examples/gen_corpus.rs`), qui reproduit les formats d'entrée des cibles :
    aucun corpus binaire n'est commité. `./x.sh check` n'est pas concerné ;
  - **feature `fuzzing` comme seule porte** vers les parseurs privés : `netsift_analyze::fuzz`, module
    `#[doc(hidden)]` compilé seulement avec la feature (et en test), qui enveloppe chaque parseur
    (`ntlmssp`, `smb`, `snmp`, `http_auth`) sans rien renvoyer d'interne ; les modules concernés passent
    `pub(crate)`. Jamais activée par l'application ; compilée par le clippy du gate (`--all-features`),
    donc maintenue. Une nouvelle cible sur un parseur privé ajoute une fonction à ce module plutôt que
    d'élargir l'API publique ;
  - **outils épinglés dans le cache** : `scripts/ct/fuzz.sh` fixe `NIGHTLY` et `CARGO_FUZZ_VERSION`
    (source unique, lue aussi par la CI), installés une fois dans `/cache/tools` (un `RUSTUP_HOME` à part,
    la stable de l'image n'est pas touchée), builds instrumentés dans `<target du worktree>/fuzz`, sans
    sccache ; `--target x86_64-unknown-linux-gnu` forcé (le cargo-fuzz précompilé est musl). Campagnes par
    `./x.sh fuzz all <durée>` : un processus par cible, cœurs - 2 à la fois, bilan dans `.artifacts/fuzz/` ;
  - **CI facultative** : job `fuzz` de `ci.yml`, sur `main` et à la demande seulement (60 s par cible,
    même script hors conteneur via `scripts/ci/fuzz.sh`) ; il ne ralentit pas la validation des branches.
- Conséquences :
  - un crash se corrige dans le parseur (commit `fix(<scope>)` séparé) avec un test unitaire de
    régression sur l'entrée minimisée (`./x.sh fuzz tmin`) ; le corpus vivant reste local ;
  - changer de nightly ou de cargo-fuzz se fait dans `scripts/ct/fuzz.sh` seulement ; une nightly trop
    ancienne pour l'édition ou les fonctions utilisées par le workspace casse les cibles, pas le gate ;
  - le gate (`./x.sh check`, job Rust de la CI) vérifie `fuzz/` sur la stable : format, `cargo check
    --locked --all-targets` et tests de sa bibliothèque (pas de clippy) ; `fuzz/Cargo.lock`, commité,
    suit la version des crates `netsift-*` (mis à jour par `scripts/release.sh`). À formater avec
    `./x.sh cargo fmt --manifest-path fuzz/Cargo.toml`. Procédure et résultats : `docs/FUZZING.md` ;
  - le job `fuzz` de la CI rend `main` rouge si une cible plante en 60 s : assumé, comme un test cassé.

## ADR-021 — Save PCAP : export pcapng par job en arrière-plan, sources vérifiées

- Contexte : P4.3. L'utilisateur veut récupérer les paquets d'une session, d'une plage horaire ou d'un
  flux dans un pcapng. Les captures ne sont jamais copiées (seuls leurs chemins et empreintes sont en
  base) ; une session peut peser plusieurs Gio et un export durer des minutes ; le desktop ne peut
  ouvrir que `<données>/exports` (ADR-012) ; la webview desktop ne peut pas télécharger une URL qui
  exige le jeton en en-tête.
- Décision :
  - **writer maison** `netsift_capture::writer::PcapNgWriter`, écrit d'après la spécification pcapng
    (pas de code porté) : SHB petit-boutiste, un IDB par couple (linktype, snaplen) émis juste avant
    son premier paquet, `if_tsresol = 9`, EPB avec longueur d'origine. `pcap-file` n'est pas une
    dépendance du dépôt (les lecteurs sont déjà écrits à la main, ADR de P1.1) et n'apporte rien pour
    trois types de blocs ; l'aller-retour est vérifié avec nos lecteurs ;
  - **relecture par le lecteur de l'import** : le moteur reconstruit le `ChunkGroup` à partir de la
    table `chunks`, dans l'ordre des identifiants, sans `ChunkGroup::new` (qui retrierait) ; les chunks
    hors de la demande (`[first_ts, last_ts]` disjoint) et les doublons y figurent comme membres
    `Skipped`, donc jamais ouverts, et l'ordre de sortie est celui de `ChunkSetSource` (fusion k-voies,
    égalités par chunk puis position). `ChunkSetSource` rend chaque fichier dans l'ordre du fichier :
    la lecture ne s'arrête au premier paquet postérieur à la fin, et un flux n'est borné en bas par
    son `first_ts` (heure de son premier paquet *lu*, pas la plus petite), que si l'import a lu la
    session dans l'ordre des horodatages (`read_in_time_order` : aucune anomalie `out_of_order`,
    `timestamp_backwards` ou `merge_fanout_limit`, liste d'anomalies non tronquée par
    `limit_reached`, statistiques de fin d'import présentes). Sinon, aucun arrêt anticipé, et un flux
    est choisi par sa fenêtre de chunks (sans borne basse) et son 5-tuple. `max_backstep_ns` n'est
    pas utilisé comme marge : il ne mesure que le recul observé à la sortie de la fusion ;
  - **erreurs de lecture** : les anomalies `read_error` et `skipped_record` rencontrées pendant la
    relecture (fichier inchangé mais corrompu, que l'import a lu de la même façon) sont comptées dans
    `ExportReport::read_errors` et `ExportJob.read_errors`, affichées dans l'UI et par la CLI : un
    export incomplet ne passe pas pour complet ;
  - **flux d'une conversation** : `GET /sessions/{id}/connections/{conversation}/flows`, servi par
    l'index `flows_conversation (src_ip, dst_ip, first_ts)` de la migration 0401 (appliquée à
    l'ouverture des sessions existantes, ADR-013) : pagination keyset sans tri temporaire ;
  - **sources vérifiées deux fois** par `chunkset::probe_file` (même sonde que l'inventaire) : avant la
    lecture (taille, date de modification, empreinte des 64 premiers Kio, en-tête lisible), d'où une
    erreur problem+json synchrone (409 `export-source-missing` ou `export-source-modified`, détail
    limité au nom du fichier), puis après la lecture, avant de publier le fichier : une source remplacée
    pendant l'export fait échouer le job. Seuls les chunks relus sont vérifiés ;
  - **job en arrière-plan interrogé par polling** : `POST /sessions/{id}/exports/pcap` planifie et
    vérifie dans `spawn_blocking`, répond 202 avec le job, puis un thread dédié écrit le fichier (le
    runtime async n'est jamais bloqué). L'UI interroge `GET /sessions/{id}/exports` toutes les 500 ms
    tant qu'un job tourne ; `POST /exports/{job}/cancel` arrête la lecture (jeton vérifié à chaque
    paquet). Le SSE de l'import a été écarté : il sert un flux d'anomalies et d'événements, alors qu'un
    export n'a qu'un état court à relire, que le polling donne avec un cache TanStack Query ordinaire et
    qui survit à la fermeture du dialogue. Au plus 2 exports simultanés (409 `too-many-exports`) ; les
    jobs vivent en mémoire (32 terminés gardés), les fichiers restent ;
  - **fichier** : `<données>/exports/netsift-<session>-<portée>-<job>.pcapng`, nom généré par le serveur
    à partir de l'ULID de session, de la portée et des 8 derniers caractères de l'ULID du job (aucun
    champ du client, champs inconnus ignorés), écrit en `<nom>.part` (`create_new`), `fsync`, renommé,
    jamais écrasé. Le `.part` est supprimé à l'erreur et à l'annulation (garde `Drop`) ; les orphelins
    (arrêt brutal) au démarrage d'un serveur non `--read-only`. L'arrêt de l'API annule les exports et
    les attend avec les imports (`STOP_LIMIT`) ; la fermeture du desktop ne demande pas de confirmation
    pour un export (rien n'est perdu que l'on ne puisse relancer) ;
  - **livraison** : desktop, « Ouvrir le dossier » par la commande `plugin:opener|open_path` sur le
    dossier des exports (permission existante `opener:allow-open-path`, aucune capability ajoutée) ;
    web, lien same-origin `GET /exports/{job}/file` que le navigateur télécharge lui-même (le proxy Vite
    ajoute le jeton), servi en flux par blocs de 256 Kio, `application/octet-stream`, `attachment`,
    `CSP: sandbox`, `nosniff`, `no-store` ;
  - **flux** : retrouvé par sa ligne `flows` (5-tuple, premier et dernier horodatage), jamais en
    recalculant un identifiant ; les deux sens, même décodage que la table de flux. Fragments IP : le
    premier fragment est reconnu par ses ports, les suivants par (source, destination, identification),
    avec 30 s de marge avant le début du flux (la table date un datagramme par son dernier fragment) ;
  - serveur `--read-only` : la route `POST` est refusée comme toute mutation ; la CLI
    `netsift export pcap` appelle le même code moteur et refuse, comme l'API, une session `importing`
    ou `failed`. Le nom du fichier et le `flow_id` du job viennent de l'identifiant analysé (`+5` ou
    des zéros en tête ne passent jamais dans le nom).
- Conséquences :
  - limites : deux flux successifs de même 5-tuple dont les fenêtres se recouvrent (port réutilisé
    aussitôt, horodatages identiques) ne se distinguent pas, l'export de l'un contient l'autre ; un
    fragment arrivé avant son premier fragment n'est pas inclus ; sur une session lue hors de l'ordre
    des horodatages, l'export d'un flux peut contenir un flux antérieur de même 5-tuple présent dans
    les chunks relus, et l'export relit tous les chunks jusqu'à la fin demandée ; le snaplen d'une
    interface autre que la première d'un chunk pcapng n'est pas connu (écrit 0) ;
  - une session mono-fichier relit le fichier depuis le début même pour un flux tardif (pas d'index
    d'offsets) ; seul le découpage en chunks évite de relire ce qui précède ;
  - les fichiers d'export s'accumulent dans `exports/` (aucune purge automatique, en mode web
    compris) ; `ExportJob.folder` et `path` exposent des chemins absolus de la machine, sans risque
    hors de l'API locale authentifiée.

## ADR-022 — Identifiant de flux = index de trame global de son premier paquet

- Contexte : P4.7, trouvé par la revue de P4.1. `FlowId::derive(clé, premier_ts)` (FNV-1a 63 bits de
  la clé orientée et de l'horodatage du premier paquet) donnait le même identifiant à deux instances
  successives d'un même 5-tuple ayant le même premier horodatage : connexion fermée puis nouveau SYN,
  éviction LRU puis reprise, capture à horodatages constants ou forgée. Sans erreur visible, `flows`
  fusionnait les compteurs par maximum, `http_transactions` rejetait le second flux
  (`UNIQUE (flow_id, seq)`), `tls_sessions` l'ignorait (`DO NOTHING`) et `smb_sessions` fusionnait les
  sessions. Ajouter l'index de trame au hachage aurait laissé des collisions 63 bits, rares mais
  provocables par une entrée hostile (FNV n'est pas résistant aux collisions), donc un traitement de
  repli à concevoir.
- Décision :
  - **l'identifiant d'un flux est l'index de trame global de la trame qui l'a créé**
    (`FlowId::from_first_frame`, `PacketCtx::frame` de son premier paquet ; pour un flux ouvert par un
    datagramme IP réassemblé, la trame du fragment qui l'a complété), sans hachage. Le lecteur du
    moteur numérote les trames une seule fois, dans l'ordre de lecture et avant la répartition en
    shards ; une trame crée au plus un flux (`FlowTable::handle` n'appelle `create` qu'une fois). Deux
    instances distinctes ont donc toujours des identifiants distincts et **aucune collision n'est
    possible** : il n'y a ni détection au writer ni identifiant de repli à prévoir. Contrat de
    `FlowTable::process` : un index de trame distinct par appel (le moteur, les tests et `fuzz/` le
    respectent) ;
  - **déterminisme** : l'index est celui du flux de paquets délivré par `ChunkSetSource`, après
    l'exclusion des chunks en double (jamais lus) et la fusion k-voies des chunks qui se chevauchent
    (ordre `(ts, chunk, offset)`). Il ne dépend pas du nombre de shards. Il est identique entre un
    fichier unique et le même trafic découpé en chunks dès que les deux délivrent les paquets dans le
    même ordre, ce qui est déjà la condition pour que l'analyse soit la même (réassemblage TCP,
    appariements) : découpage séquentiel, chunks qui se chevauchent sans égalité d'horodatage entre
    fichiers, chunks d'horodatage constant (départage par numéro de chunk) ;
  - **pas de migration** : les sessions déjà importées gardent leurs identifiants hachés ; aucun code
    ne recalcule un `FlowId` depuis la base (les tables le stockent, l'API le lit). Les deux schémas
    d'identifiants coexistent sans conflit puisqu'un identifiant n'est comparé qu'à l'intérieur d'une
    session.
- Conséquences :
  - les identifiants deviennent petits et suivent l'ordre de création des flux (insertions plus
    locales dans l'index de `flows`) ; le tri par `flow_id` utilisé pour départager (objets, identifiants)
    reste déterministe ;
  - l'identifiant change si l'ordre délivré change : import d'un sous-ensemble des chunks, horodatages
    égaux entre chunks qui se chevauchent rangés autrement que dans le fichier unique, dépassement de
    `ReadOptions::max_open` (paquets délivrés hors ordre). L'ancien schéma résistait à ces
    réordonnancements entre flux mais pas aux collisions ; l'identifiant n'a pas à être stable d'un
    import à l'autre ;
  - un identifiant ne doit jamais être réutilisé dans une session : les clauses `ON CONFLICT` de
    `flows` (maximum des compteurs) et de `tls_sessions` (`DO NOTHING`) ne servent qu'aux rejeux et à
    la commutativité entre shards, et fusionneraient ou ignoreraient sans erreur un second flux. En
    particulier, l'ajout de chunks à une session existante (phase 5, `docs/CHUNKED_CAPTURES.md`) devra
    reprendre le compteur de trames au nombre de paquets déjà importés au lieu de repartir de 0 ;
  - tests : dérivation (`netsift-flow/src/api.rs`), table de flux (réouverture et éviction à horodatage
    constant, 1 à 7 tables, propriété « jamais deux fois le même identifiant » sur du trafic hostile,
    `netsift-flow/tests/identity.rs`) et bout en bout HTTP, TLS, SMB et éviction, fichier unique,
    chunks qui se chevauchent avec un doublon, 1 à 7 shards (`netsift-engine/tests/flow_identity.rs`).

## ADR-023 — Index et agrégats construits en fin d'import

- Contexte : P4.2. Le banc de 5 Go de trafic mixte synthétique (`./x.sh bench`, `docs/PERFORMANCE.md`)
  importait à 9,2 Mo/s sur 4 cœurs (578 s), le writer SQLite occupé à 94 % et les shards à 5 %, et
  18 requêtes de vue sur 76 dépassaient 300 ms sur la session obtenue (8,9 M paquets). Le writer
  passait l'essentiel de son temps à entretenir, ligne à ligne et dans le désordre, les index
  secondaires (dix sur `flows`) et les deux index trigram HTTP, puis à réécrire leurs pages à chaque
  commit ; les vues lisaient des agrégats recalculés à chaque requête (série temporelle d'une semaine,
  rôles de serveurs, totaux).
- Décision :
  - **index secondaires différés** (`netsift_store::deferred`) : une session ouverte en mode `Import`
    supprime tous ses index non uniques après avoir noté leur définition dans `meta`
    (`import.deferred_indexes`) ; la première étape de fin d'import, `indexes`, les recrée (un tri
    chacun) avant les étapes qui les lisent (`dns`, `servers`, `objects`, `network` la citent dans
    `after`). Les index uniques et ceux des clés primaires et contraintes `UNIQUE` restent : les
    upserts en ont besoin. Seules des instructions `CREATE INDEX` sont exécutées depuis `meta` ;
  - **index de recherche HTTP en fin d'import** (0201) : plus de déclencheurs ; l'étape `http`
    reconstruit `http_transactions_fts` et `http_headers_fts`. Le `SAVEPOINT` du writer autour de
    chaque transaction HTTP forçait FTS5 à écrire puis fusionner un segment par transaction ;
  - **agrégats matérialisés** : `timeseries_minute` et `timeseries_hour` plus les totaux dans `meta`
    (0002, étape `timeseries` ; `resample` lit la table la plus grossière dont la largeur divise celle
    du pas, repli sur la table à la seconde tant que l'étape n'a pas tourné) ; rôles de serveurs
    (0801, ADR-017 mis à jour). P4.8 ajoute, sur le même modèle : rang de chaque serveur dans son rôle
    (`server_ranks`, 0802, étape `servers` version 3 ; vue Servers sans filtre de catégorie), conversations
    par paire de catégories de leurs extrémités (`conversation_categories`, 0402, étape `connections`) et
    ports ouverts par hôte avec sa catégorie (`open_port_hosts`, 0402, étape `ports`). Les comptes par
    catégorie servent aussi à choisir le plan du filtre de catégorie de Connections : sondage de `hosts`
    par clé primaire dans l'ordre de tri quand les catégories couvrent beaucoup de conversations, recherche
    par index des conversations de leurs hôtes sinon (la page la plus coûteuse de chaque plan reste sous
    1 ms sur le banc, contre 0,7 à 2,7 s avec le mauvais) ;
  - **filtres actifs seulement** (`query::Conditions`) : une condition `?n IS NULL OR col = ?n` est
    évaluée ligne à ligne et SQLite ne peut pas utiliser l'index d'un filtre peut-être inactif ; les
    listes HTTP, DNS, Connections et Open Ports ne composent plus que les fragments constants des
    filtres actifs (jamais de saisie dans le texte SQL), chacun vérifié contre l'ancien SQL ;
  - **réglages d'import** : cache de pages de 256 Mio, point de contrôle du WAL tous les 128 Mio,
    transactions de 200 000 lignes ou 1 s ; les étapes de fin d'import trient avec des fichiers
    temporaires (`temp_store = FILE`) et 4 threads ;
  - **bornes mémoire globales** : rétention de corps HTTP (128 Mio), décodeurs (256, dont 8 brotli) et
    tampons TCP hors ordre de toutes les connexions (256 Mio, `FlowConfig::max_buffered_bytes`, au
    moins `max_stream_buffer` par shard pour qu'un flux puisse toujours utiliser sa propre borne) sont
    partagés entre les shards par le moteur, comme `max_flows` : le total ne croît plus avec le nombre
    de cœurs, le résultat ne dépend du nombre de shards que lorsqu'une borne est atteinte ;
  - les analyseurs `core`, `connections` et `ports` vident leurs agrégats toutes les heures de temps
    paquet (au lieu de chaque minute) ; la mémoire reste bornée par `max_pending`.
- Conséquences :
  - import de 5 Go sur 4 cœurs en 95 s au lieu de 578 (56 Mo/s au total, 104 Mo/s pendant la lecture),
    mémoire résidente de 375 Mio (440 Mio sur 20 shards, cache de pages compris) ; la phase
    `finishing` dure environ 44 s, dont 19 s d'index (depuis P4.8, une phase `finalizing` publie l'étape en
    cours, ADR-014) ; 4 requêtes de vue sur 76 dépassent encore 300 ms (18 avant), suivis dans
    `docs/PERFORMANCE.md` ;
  - une session dont l'import s'arrête avant ses étapes (ou dont une étape échoue) reste sans index
    secondaires jusqu'à sa prochaine ouverture en écriture ; un serveur `--read-only` ne la répare
    pas. Ses vues restent justes, plus lentes : aucune requête ne nomme un index différé
    (`INDEXED BY` seulement sur les index uniques et ceux des tables remplies par une étape, qui ne
    sont jamais différés) ; tant que l'étape correspondante n'est pas marquée
    (`finalize::step_done`), la série temporelle et ses totaux lisent la table à la seconde, les rôles
    de serveurs les vues `*_source` (vue Servers, compteur du résumé, rôles du graphe ; les tables de
    rôles d'une étape `servers` de version antérieure restent lues, `finalize::step_done_since`), le rang des
    serveurs, les comptes par catégorie et les ports par hôte sont recalculés à la lecture, et les
    recherches HTTP et DNS passent par `LIKE` au lieu des index trigram. Un test d'API compare une
    session finalisée et la même sans ses étapes, servie en lecture seule. Restent comme avant P4.2,
    propres aux étapes d'ADR-014 et d'ADR-018 : appariement DNS (`dns_pairs`), graphe Network et
    objets, vides ou incomplets tant que leur étape n'a pas tourné ;
  - une définition d'index notée par une ancienne version est recréée telle quelle ; si une migration
    ultérieure a supprimé sa table ou sa colonne, elle est ignorée avec un avertissement (une migration
    supprime un index par `DROP INDEX IF EXISTS`, `schema.rs`) ;
  - après l'échec d'une étape à l'ouverture, les ouvertures suivantes de la session dans le même
    processus ne la retentent pas avant 10 minutes (`STEP_RETRY_DELAY`) : l'étape `indexes` d'une
    grosse session coûte une vingtaine de secondes ;
  - la mémoire ne dépend pas du nombre de cœurs, mais deux imports simultanés (`max_imports` vaut 2)
    ont chacun leur cache de 256 Mio ; en fin d'import, la construction des index écrit dans le WAL
    environ la taille des index (plusieurs centaines de Mo sur 5 Go) et ses tris passent par des
    fichiers temporaires ;
  - les tables matérialisées doublent une partie des données (minutes, heures, rôles) et chaque nouvelle
    source de preuve ou nouvel agrégat demande une nouvelle version de son étape, rejouée à
    l'ouverture des sessions existantes ;
  - garde-fous dans la CI : plans de requête sans `SCAN` ni `TEMP B-TREE` pour les lectures corrigées,
    équivalence ancien et nouveau calcul (séries, filtres, rôles), instruction de l'upsert d'hôtes
    jamais préparée de nouveau ; les mesures restent hors du gate (`./x.sh bench`).

## ADR-024 — Licences tierces : liste générée et commitée, vérifiée par le gate

- Contexte : P4.5. Les bundles redistribuent environ 440 crates Rust et 40 paquets npm sous MIT,
  Apache-2.0, BSD, ISC, MPL-2.0, Unicode, OFL... ; la plupart exigent que leur texte de licence (et
  pour Apache-2.0 les fichiers `NOTICE`) accompagne la distribution. L'application est hors ligne et
  ne peut rien télécharger pour les afficher.
- Décision :
  - **liste générée, commitée** : `ui/src/views/settings/licenses/third-party-licenses.json` (UI) et
    `THIRD_PARTY_LICENSES` (racine, cité par `NOTICE`, livré dans les bundles), produits par
    `./x.sh licenses` ; le gate et le job `licenses` de `ci.yml` régénèrent avec `--check` et échouent
    sur toute différence. Commiter plutôt que générer au build : le build de l'UI (dev, shots, Tauri)
    ne dépend ni de cargo-about ni du registre cargo, et chaque changement de licence apparaît dans un
    diff relu ;
  - **Rust** : `cargo-about` 0.9.3 (MIT OR Apache-2.0), épinglé dans `scripts/ct/licenses.sh`, compilé
    dans le cache comme git-cliff ; périmètre = binaire desktop, quatre cibles des bundles, sans
    dépendances de dev ni de build ; `--frozen` (registre local uniquement) ;
  - **npm** : script maison (`ui/scripts/third-party-licenses.ts`, Node avec suppression des types,
    sans dépendance) sur les entrées de production de `package-lock.json` et les fichiers de
    `node_modules` ; la liste d'acceptation est celle d'`about.toml` plus `0BSD`, `Unlicense`, `OFL-1.1` ;
  - **UI** : dialogue chargé à la demande (chunk séparé de ~420 Ko, ~50 Ko compressé), regroupement par
    licence reproduite, recherche, textes affichés en nœuds texte (aucun HTML injecté) ;
  - **licence du projet** : Apache-2.0 seule (décision de l'utilisateur), `LICENSE` officiel et
    `NOTICE` à la racine ;
  - **MPL-2.0** : pour chaque paquet embarqué sous MPL-2.0, `THIRD_PARTY_LICENSES` donne l'adresse
    de son code source à la version embarquée (MPL-2.0, section 3.2) ;
  - **bundles** : `LICENSE`, `NOTICE` et `THIRD_PARTY_LICENSES` en ressources Tauri
    (`licenses/`), vérifiés par un test du crate desktop ; pas de page de licence à accepter dans les
    installateurs (`licenseFile` non défini : les licences permissives ne demandent pas d'acceptation).
- Conséquences : toute mise à jour de dépendance demande `./x.sh licenses` et un commit des deux
  fichiers (le gate le signale) ; le gate fait un `cargo fetch` (réseau) et environ 25 s de
  cargo-about ; une nouvelle version de `ring` exige de relire et réépingler sa clarification dans
  `about.toml` ; la liste npm est un sur-ensemble de ce que Vite garde après tree-shaking.

## ADR-025 — Sorties réseau sur option : vérifications DB-IP et releases GitHub

- Contexte : P4.11, socle de P4.9 (proposer la base GeoIP au démarrage) et P4.10 (nouvelle version
  depuis les releases GitHub), demandées par l'utilisateur le 2026-11-15. L'application s'interdit
  tout appel réseau sortant ; ADR-015 n'admet que le téléchargement de la base GeoIP sur clic. Les
  deux fonctionnalités ont besoin de requêtes de plus, dont certaines au démarrage. ADR-015 reste
  valable tel quel pour le téléchargement de la base ; cette ADR ajoute deux exceptions, et seulement
  celles-ci.
- Décision :
  - **exception DB-IP** : au démarrage, une requête (`HEAD`) vers `download.db-ip.com` vérifie si une
    base plus récente est publiée, **uniquement si l'utilisateur a activé** « Rechercher une nouvelle
    base GeoIP au démarrage » (désactivé par défaut). Le téléchargement reste celui d'ADR-015, sur clic ;
  - **exception releases GitHub du dépôt** : la dernière release publiée est lue sur `api.github.com`
    (JSON borné) au démarrage si l'utilisateur a activé « Rechercher les mises à jour au démarrage »
    (désactivé par défaut), ou sur clic du bouton « Rechercher une mise à jour ». Le téléchargement
    d'un artefact (et de `SHA256SUMS.txt`) se fait **seulement sur clic**, vers le chemin choisi par
    l'utilisateur dans le dialogue natif d'enregistrement, depuis `github.com` et l'hôte de stockage
    des assets vers lequel il redirige (`release-assets.githubusercontent.com`,
    `objects.githubusercontent.com`) ; jamais d'installation automatique (ADR-011) ;
  - **points communs** :
    - requêtes faites par l'API Rust, jamais par la webview : CSP (ADR-006) et capabilities inchangées ;
    - un seul client, `netsift-api/src/outbound.rs` (utilisé aussi par ADR-015) : HTTPS seulement sur
      le port par défaut, noms d'hôte seulement (jamais d'IP littérale), sans identifiants dans l'URL,
      hôtes en **liste blanche passée par l'appelant** (comparaison exacte, un point final est refusé)
      et revérifiée à chaque redirection (au plus 3), délais de connexion, de lecture et total réglables
      par l'appelant (`Policy::with_*`), taille maximale par requête vérifiée pendant la lecture ;
      téléchargement vers un fichier temporaire propre à chaque téléchargement
      (`<nom>.<pid>-<n>.part`, créé en exclusif, jamais à travers un lien, jamais un fichier existant),
      SHA-256 calculé à la volée et vérifié avant le renommage atomique vers la cible, fichier temporaire
      supprimé sur erreur ou annulation : deux téléchargements simultanés vers la même cible donnent
      l'un des deux fichiers, entier et vérifié ; mode HTTP local réservé aux tests (absent des builds) ;
    - **aucune donnée utilisateur envoyée** : `User-Agent: NetSift/<version>`, ni cookie, ni
      identifiant, ni information sur les captures ; jamais de corps de réponse dans les logs ni dans
      les erreurs ;
    - **échecs silencieux au démarrage** : un échec réseau ne produit aucun bandeau d'erreur, au plus
      une ligne de log ; une action sur clic rapporte son échec ;
  - **réglages côté serveur** : `<données>/settings.json` (`online.geoip_check`, `online.update_check`,
    `dismissed_notices`, liste du moins récemment masqué au plus récent, 32 entrées au plus, la plus
    ancienne oubliée au-delà), lu au démarrage de l'API, valeurs par défaut sûres (tout désactivé), fichier
    absent ou invalide = valeurs par défaut avec un avertissement, écriture atomique ; routes
    `GET /settings`, `PUT /settings` (champs absents inchangés), `PUT /settings/notices/{id}`, refusées
    en `--read-only`. Le serveur décide seul des vérifications au démarrage (`online::STARTUP_CHECKS`,
    jamais sur un serveur en lecture seule) : desktop et mode web dev se comportent pareil. Chaque
    fonctionnalité garde son état dans `AppState::online` (un emplacement par type, `online.get::<T>()`)
    et expose ses erreurs par `ApiError::Feature { status, kind, title }` (`OutboundError::into_problem`),
    sans toucher au code commun. Thème et
    langue restent dans le stockage de la webview ;
  - **bandeaux** : les résultats s'affichent dans des bandeaux discrets sous l'en-tête (au plus deux
    à la fois), masquables jusqu'à ce que leur clé change (mois de la base, version proposée) ;
    le masquage est enregistré dans `settings.json`.
- Conséquences :
  - l'application reste entièrement hors ligne tant que l'utilisateur n'active rien et ne clique sur
    rien ; les hôtes contactés sont affichés à côté de chaque réglage ;
  - ajouter un hôte ou une requête exige une nouvelle ADR ; une fonctionnalité en ligne s'enregistre par
    une ligne dans `online::STARTUP_CHECKS` (Rust), `NOTICE_PROVIDERS` (bandeau) et `ONLINE_EXTENSIONS`
    (Paramètres > En ligne), et son propre dictionnaire i18n ;
  - les tests utilisent un serveur HTTP local ; les requêtes réelles vers DB-IP et GitHub restent
    vérifiées à la main.

## ADR-026 — Vérification DB-IP au démarrage : précisions

- Contexte : P4.9 (proposer la base GeoIP au démarrage) met en œuvre l'exception DB-IP d'ADR-025, qui
  reste valable ; cette ADR précise quand la requête part et comment la fraîcheur de la base est jugée.
  ADR-015 (téléchargement sur clic) est inchangée.
- Décision :
  - **fraîcheur, sans réseau** (`GET /geoip/status`, `netsift-api/src/geoip/freshness.rs`) : le mois de la
    base utilisée (copie utilisateur, sinon bundle) est comparé au mois courant UTC. Ce mois est celui du
    fichier DB-IP téléchargé par l'application, enregistré à côté de la copie utilisateur
    (`<données>/geoip/dbip-country-lite.month` : mois et `build_epoch` du fichier, écriture atomique) et
    pris en compte tant que le `build_epoch` de la base installée est le même ; sinon (bundle, fichier
    importé ou remplacé à la main) le mois UTC du `build_epoch` des métadonnées mmdb. Raison : un fichier
    publié pour un mois peut avoir été généré le dernier jour du mois précédent ; sans cet enregistrement,
    le bandeau reviendrait chaque mois après une mise à jour. Base absente ou illisible : « Télécharger » ;
    mois antérieur : « Mettre à jour » ;
  - **quand la requête part** : au démarrage seulement, si « Rechercher une nouvelle base GeoIP au
    démarrage » est activé (désactivé par défaut), jamais sur un serveur `--read-only`, et seulement si la
    base n'est pas du mois courant. Au plus **deux** `HEAD` : le fichier du mois courant, puis, sur 404,
    celui du mois précédent (les mois que tente le téléchargement d'ADR-015). Si rien de plus récent que la
    base n'est publié, aucun bandeau ;
  - **échecs silencieux** : réseau, statut inattendu ou redirection refusée donnent une ligne de log
    (`info`, sans URL ni corps de réponse) et le bandeau suit la vérification locale ; jamais de bandeau
    d'erreur. Pendant la vérification, l'UI attend son résultat (interrogation bornée à environ une minute) ;
  - **rien en lecture seule** : aucun bandeau ni requête sur un serveur `--read-only` ;
  - **téléchargement sans base plus récente** (début de mois, fichier du mois pas encore publié) : si, après
    un téléchargement, la base reste antérieure au mois courant, le serveur masque le bandeau jusqu'au mois
    suivant (`dismissed_notices`, clé `YYYY-MM`) et l'UI l'indique (« Aucune base plus récente n'est encore
    publiée »).
- Conséquences :
  - le bandeau ne revient ni chaque mois après une mise à jour ni après un téléchargement sans nouveauté ;
  - une base du bundle générée la veille du mois de sa publication est vue comme du mois précédent tant
    qu'elle n'a pas été téléchargée par l'application (un téléchargement l'enregistre) ;
  - les tests utilisent un serveur HTTP local ; la réponse réelle de DB-IP au `HEAD` reste vérifiée à la main
    (un refus du `HEAD` compterait comme un échec, donc silencieux).

## ADR-027 — Vérification et téléchargement des mises à jour (releases GitHub)

- Contexte : P4.10, demandée par l'utilisateur le 2026-11-15 ; met en œuvre l'exception « releases GitHub
  du dépôt » d'ADR-025 (inchangée), avec le client sortant partagé et ses règles (HTTPS, liste blanche
  revérifiée à chaque redirection, délais et tailles bornés, `User-Agent` générique, aucune donnée
  utilisateur). Bundles non signés (ADR-011) : pas de plugin updater ni d'installation automatique.
- Décision :
  - **vérification** (`netsift-api/src/updates.rs`) : `GET https://api.github.com/repos/<dépôt>/releases/latest`,
    dépôt fixé au build (`[workspace.package] repository`), `Accept: application/vnd.github+json`, JSON
    borné à 1 Mio ; au démarrage si `online.update_check` est activé (échec silencieux, une ligne de log),
    ou sur clic de « Rechercher une mise à jour » (`POST /updates/check`, échec rapporté). Brouillons,
    prereleases (drapeau ou suffixe SemVer) et versions égales ou plus anciennes (précédence SemVer,
    métadonnées de build ignorées) = « à jour » ; 404 (aucune release) = « à jour ». Notes en texte brut
    (caractères de contrôle et bidirectionnels retirés, 8 000 caractères au plus), jamais rendues en HTML
    ou Markdown. Résultat gardé en mémoire (`GET /updates`) pour le bandeau, masquable par version ;
  - **URL lues dans le JSON** : analysées (`Url`), schéma, hôte et port de la release attendue, chemin
    comparé segment par segment après normalisation (propriétaire et dépôt sans tenir compte de la casse),
    refusées avec `..`, `.` ou leurs formes encodées, une requête ou un fragment ; les assets sous
    `https://github.com/<dépôt>/releases/download/`, la page sous `.../releases/` ;
  - **installateurs proposés** : ceux du système et de l'architecture en cours, le format installé en
    premier. Ce format vient du type de bundle que Tauri inscrit dans le binaire
    (`tauri::utils::platform::bundle_type()`, variable `APPIMAGE` en repli), passé à l'API par
    `Server::with_install_format` ; inconnu (build de dev) : AppImage, NSIS ou dmg d'abord, et l'UI
    laisse choisir le format ;
  - **téléchargement, desktop seulement** (`allow_any_path`) : le dialogue natif d'enregistrement s'ouvre
    d'abord dans le dossier Téléchargements avec le nom exact de l'asset (capabilities `dialog:allow-save`
    et `core:path:allow-resolve-directory`, toujours sans `core:default`) ; annulation = aucune requête.
    `POST /updates/download { asset, path }` n'accepte qu'un nom d'installateur de la dernière release
    vérifiée (jamais une URL) et un chemin absolu, sans `..`, dont le dossier existe et qui n'est pas un
    dossier. L'API lit `SHA256SUMS.txt` de la même release (64 Kio au plus, formats `hash  nom` et
    `hash *nom`), puis télécharge vers le chemin choisi (`.part` puis renommage, empreinte vérifiée avant ;
    absente ou différente = erreur et aucun fichier), taille bornée par celle annoncée dans le JSON plus
    1 Mio (2 Gio au plus), délai total d'une heure. Un téléchargement à la fois, progression par
    `GET /updates/download`, tâche attendue (bornée) à l'arrêt du serveur pour que le `.part` soit supprimé ;
    l'utilisateur installe lui-même le fichier. Mode web dev : lien vers la page de la release ;
  - **hôtes** : `api.github.com` (vérification) ; `github.com` et l'hôte de stockage des assets vers lequel
    il redirige, `release-assets.githubusercontent.com` et `objects.githubusercontent.com`
    (`DOWNLOAD_HOSTS`). Les URL signées de ce stockage n'apparaissent jamais dans les logs
    (erreurs reqwest sans URL) ;
  - **noms de fichiers temporaires** : un `.part` laissé par un plantage avec le même PID est sauté
    (16 noms au plus), jamais ouvert ni supprimé.
- Conséquences :
  - la liste des hôtes de stockage suit GitHub : s'il en change, elle (et cette ADR) doit être mise à
    jour ; seul un téléchargement réel depuis une release publiée la vérifie, comme la détection du format
    installé dans un vrai bundle et les noms d'assets de Tauri (`_amd64`, `.x86_64`, `_x64-setup.exe`,
    `_x64_en-US.msi`, `_universal.dmg`) ;
  - les tests utilisent un serveur HTTP local.

## ADR-028 — Titre de release : message du tag, nom de la release, bandeau de mise à jour

- Contexte : retour de l'utilisateur sur le bandeau de mise à jour d'ADR-027 (0.1.0 voyant 0.1.1) :
  l'extrait de deux lignes des notes git-cliff (entrées de commit, lien de comparaison, mentions
  d'installation) n'apprend rien. Il veut un titre de release, affiché à la place de cet extrait.
  ADR-027 reste valable pour tout le reste (vérification, notes en texte brut dans le dialogue,
  téléchargement).
- Décision :
  - **source** : `scripts/release.sh X.Y.Z --title "…"` ; le titre est le corps du message du tag
    annoté (`NetSift vX.Y.Z`, ligne vide, titre ; `--cleanup=whitespace` pour garder un `#` initial).
    Une ligne d'UTF-8, 80 caractères au plus, sans caractère de contrôle (C0, DEL, C1, séparateurs
    U+2028-U+2029), invisible (U+180E, U+200B, U+2060-U+2064, U+FEFF) ni de mise en forme
    bidirectionnelle (dont U+061C) ; refusé avant toute action. Le tag est déjà le document signé de la
    version : pas de fichier en plus dans le dépôt, et le titre ne peut pas diverger du tag poussé ;
  - **nom de la release** : `release.yml` (job `create`) récupère l'objet tag (`git fetch --force`,
    actions/checkout ne laisse qu'une référence légère pour un événement de tag) et nomme la release
    `NetSift vX.Y.Z — titre`, `NetSift vX.Y.Z` sans titre (`scripts/ci/release-name.sh`, testé par
    `scripts/tests/release.sh`). Titre invalide ou tag léger : nom par défaut et avertissement,
    jamais d'échec de la publication (objet tag non récupéré ou script en échec compris) ;
  - **application** : `UpdateRelease` expose `name` (texte brut, une ligne, 120 caractères au plus ;
    ces caractères y sont retirés, comme dans les notes) et `title` : ce qui suit la version
    dans `NetSift vX.Y.Z <séparateur> titre`, le nom entier s'il a été écrit à la main sans ce
    préfixe, rien pour le nom par défaut ou le seul tag. L'application lit le nom de la release, pas
    le tag : un titre corrigé dans l'interface GitHub (« Edit release ») s'affiche à la vérification
    suivante, y compris pour les releases publiées avant cette ADR. Le bandeau montre la version puis
    le titre, sans extrait des notes ; « Paramètres > À propos » montre aussi le titre ; les notes
    complètes restent dans le dialogue « Notes de version ». Texte brut partout, jamais de HTML.
- Conséquences : une release sans titre affiche seulement la version ; le titre fait partie de la
  publication (à choisir avec l'accord de l'utilisateur, comme le numéro de version). Le message du
  tag n'est jamais modifié après coup (tag publié) : seul le nom de la release peut l'être.

## ADR-029 — Captures compressées zstd et LZ4 : décodeurs purs Rust, bornés

- Contexte : P5.7. Les captures archivées sont souvent compressées en zstd (`zstd`, tcpdump `-z zstd`)
  ou LZ4 (`lz4`), en plus de gzip (lu par `flate2` depuis P1.1). Le projet parse 100 % en Rust, sans
  bibliothèque C, et les fichiers sont des entrées hostiles.
- Décision :
  - **détection** par magic number (gzip `1f 8b`, zstd `28 b5 2f fd`, LZ4 frame `04 22 4d 18`), après
    d'éventuelles trames ignorables en tête (`pzstd`, 1 Mio au plus), jamais par l'extension ; même
    chemin que gzip (`reader::from_reader`) pour l'import, les jeux de chunks et l'export « Save PCAP ».
    Compression imbriquée refusée ;
  - **zstd** : `ruzstd` (MIT, pur Rust), un `FrameDecoder` neuf par trame (fenêtre allouée au fil des
    données, pas réservée d'après l'en-tête), fenêtre bornée à 32 Mio (`MAX_ZSTD_WINDOW`, tous les
    niveaux de l'outil jusqu'à `--ultra -20`), trames concaténées et ignorables, somme de contrôle de
    contenu vérifiée, dictionnaires refusés. La liaison C (`zstd`) n'est pas retenue : décoder une
    entrée hostile avec du code C contredit le parti pris du projet, et le débit mesuré suffit
    largement (lecture complète d'un pcapng synthétique de 66 Mo en mémoire, build release : environ
    730 Mo/s en zstd et en LZ4 contre 160 Mo/s en gzip et 680 Mo/s sans compression, pour une cible
    d'ingestion de 80 Mo/s) ;
  - **LZ4** : couche frame écrite ici (spécification publique du format frame : en-tête, sommes de
    contrôle xxHash32 d'en-tête, de bloc et de contenu, taille de contenu) et décompression des blocs
    par `lz4_flex` (MIT, pur Rust, mode `safe-decode`) ; `lz4_flex::frame::FrameDecoder` n'est pas
    utilisé car il prend une fin de fichier entre deux blocs pour une fin propre, ce qui masquerait un
    fichier coupé. Blocs au plus de la taille déclarée (4 Mio), historique de 64 Kio en mode chaîné ;
    ancien format (`lz4 -l`) et dictionnaires non pris en charge ;
  - **erreurs** : flux coupé -> `UnexpectedEof` -> `TruncatedTail`, comme gzip ; flux corrompu ->
    `Malformed` (« corrupt zstd stream: … ») ; hors bornes -> `Malformed` (« unsupported … ») avec la
    raison, y compris à l'ouverture (chunk « illisible » plutôt que « non reconnu »).
- Conséquences : `CaptureInfo::compressed` reste un booléen (pas de migration ; l'onglet Sources
  déduit le suffixe affiché du nom de fichier). `ruzstd` ne rend la dernière fenêtre d'une trame qu'à
  sa fin et LZ4 un bloc entier : un fichier coupé perd au plus une fenêtre (zstd) ou un bloc (LZ4)
  avant la coupure. Mémoire au pire par lecteur ouvert : 32 Mio (zstd) ou 8 Mio (LZ4), multipliée par
  le nombre de chunks ouverts en fusion k-voies (64 au plus) dans un cas pathologique.

## ADR-030 — Filtre temporel global : paramètres, sémantique et coût

- Contexte : P5.2. La plage choisie dans l'Overview doit restreindre toutes les vues ; environ 45
  routes de données par session, des tables d'enregistrements horodatés et des tables repliées ou
  précalculées en fin d'import (ADR-014, ADR-023). Mesures du banc de 8,9 M paquets : `docs/specs/time-filter.md`.
- Décision :
  - **paramètres** `from_us` / `to_us` (microsecondes, bornes incluses, chacun facultatif), lus et
    validés par un extracteur unique de l'API, convertis en `[F, T)` en nanosecondes (`TimeRange` du
    store) ; 400 problem+json pour une plage inversée ou hors bornes ; une plage disjointe donne des
    résultats vides ; une plage qui couvre la session est abandonnée (tables précalculées) ;
  - **sémantique** : enregistrement ponctuel dans `[F, T)` par sa colonne horodatée ; élément replié
    (flux, conversation, identifiant, annonce, port ouvert) retenu s'il chevauche la plage, compté en
    entier ; les statistiques, totaux et compteurs d'une vue suivent la plage de sa liste ; détails par
    identifiant, fichiers, chunks et anomalies non filtrés ;
  - **convention transverse** : toute nouvelle route de données d'une session accepte la plage ou dit
    dans sa spec pourquoi elle ne l'accepte pas ; toute vue s'inscrit dans `ui/src/app/timeFilterViews.ts`
    ou ignore la plage, ce que la pastille d'en-tête signale ;
  - **coût** : un agrégat filtrable est servi par un index couvrant terminé par la colonne horodatée, la
    plage écrite `+ts` dans les agrégats (choix de l'index couvrant sans `INDEXED BY`), plan des pages
    choisi à la sélectivité ; flux actifs en deux branches (index `(first_ts, last_ts)` et index partiel
    des flux de plus d'une heure) ; les vues agrégées (Connections, Open Ports, Servers, Network)
    matérialisent leurs tables par plage dans une base annexe (LRU) : la première requête d'une plage
      large attend la construction et peut dépasser 300 ms (pas de réponse 202 ; état de chargement de
    l'UI), les suivantes non ;
  - **UI** : la plage vit dans l'URL de la session (`from_us`, `to_us`), conservée entre les onglets de
    cette session (`retainSearchParams`), jamais reportée sur une autre session (garde du layout de
    session), et entre dans la clé de requête de chaque route filtrée.
- Conséquences : environ 5 s d'index et +6 % de taille de session sur le banc (aussi à la première
  ouverture d'une session existante) ; les compteurs repliés (`seen_count`, octets d'un flux long)
  restent ceux de la session, avec la mention « session entière » dans l'en-tête de leur colonne sous
  plage ; la règle des 300 ms d'`ARCHITECTURE.md` reçoit une exception pour la première requête d'une vue
  agrégée sous plage.
- Notes d'implémentation (P5.2b, `docs/specs/time-filter.md`) : la « base annexe » est un **fichier SQLite par
  plage** (`sessions/<id>/ranges/<début>_<fin>_<empreinte>.db`, 4 par session, les moins récemment utilisés
  supprimés) plutôt qu'un `ranges.db` commun : publication par renommage, éviction par suppression, aucune
  écriture dans un fichier lu. Il porte les tables dérivées sous les noms et le schéma de la session et
  s'ouvre en `main`, la session attachée en lecture seule : les requêtes des vues sont inchangées. Une seule
  construction par plage (requêtes concurrentes en attente), 2 au plus en même temps, interrompue quand plus
  aucune requête ne l'attend ; empreinte (migrations, étapes, statistiques, version) dans le nom pour qu'une
  session migrée n'en relise jamais une ancienne ; serveur `--read-only` : dossier temporaire du processus.
  Conversations, trafic par hôte et clients des ports agrégés en Rust en une lecture des flux actifs (le
  `GROUP BY` SQL coûtait 8 s à 6 jours ; mémoire bornée par passes, catégories et ports lus par clé
  primaire). Les compteurs de modules des vues agrégées sont servis par une route à part,
  `GET /sessions/{id}/modules`, qui attend la base ; `/summary` ne l'attend jamais (compteurs `pending`) et
  garde ses temps de P5.2a à chaque zoom. Un test compare, sur des sessions importées, la base d'une plage
  couvrante et la session table par table. Suivi : construire les tables du graphe seulement à la première
  requête Network (non retenu en l'état : le fichier publié est immuable). Mesures : `docs/PERFORMANCE.md`,
  « Filtre temporel (P5.2b) ».

## ADR-031 — Constructeurs des adresses MAC : listes publiques de l'IEEE, table générée et commitée

- Contexte : P5.4 (onglet Ethernet). Le constructeur d'une carte réseau se lit dans le préfixe de son
  adresse MAC, attribué par l'IEEE Registration Authority. La base la plus diffusée (`manuf` de Wireshark)
  est sous GPL, et l'application ne fait aucun appel réseau hors des exceptions de `CLAUDE.md`.
- Décision :
  - **source** : les listes publiques de l'IEEE, seules : MA-L (24 bits), MA-M (28 bits), MA-S (36 bits) et
    l'ancien registre IAB (36 bits), en CSV sur `standards-oui.ieee.org`. Le paquet Debian `ieee-data`
    (`debian/copyright`) consigne que l'IEEE ne revendique aucun droit d'auteur sur ces listes, n'en
    restreint pas la diffusion et recommande seulement de les obtenir chez lui et de les mettre à jour
    régulièrement ; la page de conditions du site de l'IEEE, inaccessible à un client automatisé lors de
    l'analyse, est **à vérifier par un humain avant la prochaine release**. Ce sont des faits (préfixe,
    organisation), sans création protégeable ; la source est citée dans `THIRD_PARTY_LICENSES`, avec la
    référence à Debian plutôt qu'une déclaration prêtée à l'IEEE ;
  - **contenu** : préfixe et nom de l'organisation seulement, jamais l'adresse postale (environ 59 000
    entrées, 1,8 Mo), dans `crates/netsift-analyze/data/ieee-oui.tsv`, généré par `scripts/gen-ieee-oui.py`
    (Python, bibliothèque standard, comme la table IANA des services) et **commité** : build hors ligne et
    reproductible, diff lisible à chaque mise à jour, aucun téléchargement en CI (le serveur de l'IEEE
    refuse certains clients automatisés). Mise à jour manuelle, par exemple avant une release
    (`crates/netsift-analyze/data/README.md`) ;
  - **embarquement** : `include_str!` dans le module `netsift_analyze::oui`, analysé au premier usage en
    trois vecteurs triés, recherche du préfixe le plus long (MA-S, puis MA-M, puis MA-L : un bloc MA-L
    « IEEE Registration Authority » subdivisé nomme le titulaire MA-M ou MA-S) ;
  - **classes** d'après les bits de l'adresse seuls (IEEE 802) : groupe (bit I/G) et diffusion, adresse
    administrée localement (bit U/L, jamais attribuée : machines virtuelles, adresses aléatoires des
    téléphones et portables), sans constructeur ; une adresse de groupe universelle est attribuée au
    titulaire du préfixe sans le bit I/G (`01:80:c2` -> IEEE 802.1) ; groupes connus nommés à part
    (multicast IPv4 `01:00:5e`, IPv6 `33:33`, adresses réservées 802.1 `01:80:c2:00:00:0x`) ;
  - **moment** : le constructeur est résolu par l'analyseur à l'import et stocké avec l'adresse
    (`eth_macs.vendor`), comme les pays (ADR-009) : tri, filtre et regroupement en SQL. Une session garde
    les constructeurs de la table de son import.
- Conséquences : +1,8 Mo dans le binaire et environ 0,1 s d'analyse de la table au premier import (build
  release) ; une table périmée laisse des préfixes récents sans constructeur (affichés « inconnu ») jusqu'à
  sa régénération ; les autres vues (ARP, Hosts) peuvent réutiliser `netsift_analyze::oui`.

## ADR-032 — FTP : canal de données associé au contrôle dans le shard de la paire d'adresses

- Contexte : P5.8 (onglet FTP, `docs/specs/ftp.md`). Les fichiers d'une session FTP passent par une autre
  connexion TCP que le contrôle (port 21), annoncée par `PORT` / `EPRT` (actif) ou par les réponses `227` /
  `229` (passif, RFC 959, RFC 2428). Les analyseurs sont instanciés par shard sans état partagé, et le
  résultat doit être le même quel que soit le nombre de shards et le découpage en chunks. Deux pistes
  étaient proposées : (a) le thread décodeur repère les annonces sur le port 21 et route le flux de données
  attendu vers le shard du contrôle, comme tout l'ARP vers le shard 0 (P5.3) ; (b) les flux candidats sont
  stockés comme objets orphelins puis appariés en fin d'import par (adresse, port, temps).
- Décision :
  - **ni (a) ni (b)** : le routage existant suffit pour le cas courant. `shard_hash`
    (`netsift-flow/src/api.rs`, interface figée) hache le protocole et la **paire d'adresses non ordonnée,
    ports ignorés** (pour les fragments IP) : le contrôle et un flux de données qui relient les deux mêmes
    adresses sont toujours sur le même shard, vus dans l'ordre de capture. L'analyseur `ftp` associe donc
    le canal au contrôle dans son propre état, sans changer le moteur. Un test de l'analyseur vérifie que
    `shard_hash` ignore les ports (garde-fou si le routage change un jour) ;
  - **association** : un flux TCP est le canal attendu si son extrémité répondante est l'adresse annoncée,
    ou à défaut si son port est le port annoncé et qu'il relie les deux mêmes adresses que le contrôle ; il
    doit avoir été créé après la commande qui a demandé le canal (`PASV`, `EPSV`, `PORT`, `EPRT`), ce que
    donne son identifiant (index de trame de son premier paquet, ADR-022), sans horloge ; la première
    correspondance consomme l'attente ; ordre de recherche déterministe (ordre des annonces) ;
  - (a) écarté : l'analyse des réponses par paquet dans le décodeur ne voit pas un `227` coupé entre deux
    segments ni retransmis (pas de réassemblage dans le décodeur), alourdit le thread unique du pipeline et
    modifie une interface figée, pour un gain limité aux cas ci-dessous. (b) écarté : sans connaître les
    annonces, chaque flux TCP est un candidat, et garder le contenu de tous les flux jusqu'à la fin de
    l'import n'est pas borné ;
  - **contenu** : tenu en mémoire pendant le transfert dans un budget de 128 Mio partagé par les shards
    (compteur atomique de la configuration de l'analyseur, recréé par le moteur à chaque import, comme le
    budget des blobs), puis stocké par `put_object` (64 Mio au plus par fichier) si le transfert est
    complet. Un budget partagé plutôt que divisé par shard (`max_retained_bytes` d'HTTP) : un fichier de
    64 Mio reste extractible quel que soit le nombre de cœurs.
- Conséquences et limites :
  - **FXP** (transfert entre deux serveurs) et **serveur multi-adresses** dont la réponse `227` désigne une
    autre adresse que celle du contrôle : le flux de données relie une autre paire, tombe sur un autre shard
    et n'est pas associé ; le transfert garde sa commande, son chemin et son statut, sans taille ni contenu
    (« canal de données non vu ») ;
  - **NAT** : vu d'un côté du NAT, le contrôle et les données relient les mêmes adresses ; un `227` qui
    annonce l'adresse interne du serveur est associé par le port (repli) ;
  - **segmentation du `227`** : sans effet, l'analyseur lit le flux réassemblé. Un `227` retenu par le
    réassemblage (segment perdu puis retransmis) arrive après l'ouverture du canal : les octets du canal
    reçus avant sa lecture sont perdus pour ce transfert, marqué tronqué ;
  - **port non standard** : seul le port 21 est reconnu comme contrôle ;
  - **ports réutilisés** : un flux plus ancien que la commande ne peut pas être associé ; deux attentes du
    même port sur la même paire : la plus ancienne d'abord ;
  - **déterminisme** : les flux d'une paire arrivent au même shard dans le même ordre pour 1 à N shards et
    tout découpage en chunks (test d'équivalence fichier unique et chunks, 1, 4 et 7 shards). Le résultat
    ne dépend du nombre de shards ou de l'ordonnancement que lorsqu'une borne est atteinte : sessions et flux
    de données suivis par shard (4 096 et 1 024), budget mémoire partagé épuisé (comme le budget des blobs) ;
  - FTPS implicite (990) et contrôle après `AUTH TLS` : chiffrés, non analysés (la note « suite chiffrée »
    l'indique) ; leurs flux de données ne sont pas associés.
