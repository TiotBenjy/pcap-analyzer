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
    recherche indexée par requête de groupe) ; aucune progression n'est publiée pendant ces étapes,
    l'import reste dans sa phase `finishing` jusqu'à leur fin (une phase dédiée dans `Progress` changerait
    le contrat des événements d'import : non fait) ;
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
  - le crate `fuzz/` n'est pas couvert par `cargo fmt --all` ni par le clippy du gate : à formater avec
    `./x.sh cargo fmt --manifest-path fuzz/Cargo.toml`. Procédure et résultats : `docs/FUZZING.md`.
