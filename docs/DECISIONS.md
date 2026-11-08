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
