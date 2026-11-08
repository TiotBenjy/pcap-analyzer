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
  - `freezePrototype` est conservé. ECharts et graphology fonctionnent avec un `Object.prototype` gelé
    (test Vitest dédié). `./x.sh shots` gèle aussi le prototype et échoue sur toute erreur de page.
- Conséquences : une fonctionnalité qui a besoin d'une nouvelle API Tauri côté JS ajoute la permission
  ciblée dans `capabilities/default.json`. Un export doit écrire sous `<données>/exports` pour pouvoir être
  ouvert. sigma n'est pas encore vérifié avec le prototype gelé : à faire avec la vue du graphe réseau.
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
