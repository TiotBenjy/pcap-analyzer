# NetSift — mémoire projet pour Claude Code

Application de bureau (Linux, Windows ; bundles publiés aussi pour macOS) d'analyse forensique de captures réseau
(pcap / pcapng), y compris des **captures découpées en chunks** (dumpcap/Wireshark
`-b filesize:` / `-b duration:`, tcpdump `-C` / `-G`) importées en dossier et
recollées en une seule session. Usage solo, local, hors ligne.

Interface de référence : `docs/reference/` (captures d'une plateforme existante).
On reprend les **fonctionnalités**, pas le style : voir `docs/UI_GUIDELINES.md`.

## Documents à lire selon la tâche

- Architecture, crates, flux de données, stockage : @docs/ARCHITECTURE.md
- Captures en chunks (détection, ordre, recollage, cas limites) : `docs/CHUNKED_CAPTURES.md`
- Règles UI (sobriété, responsive, anti-chevauchement) : `docs/UI_GUIDELINES.md`
- Spécification d'un onglet : `docs/specs/<onglet>.md`
- Plan de travail et état d'avancement : `docs/ROADMAP.md`
- Workflow git, worktrees, agents parallèles : `docs/GIT_WORKFLOW.md`
- Décisions d'architecture (ADR) : `docs/DECISIONS.md`

## Règle n°1 : aucune toolchain sur l'hôte

L'utilisateur n'a **ni Rust ni Node** sur sa machine. Tout passe par le conteneur
(Docker ou Podman, détecté automatiquement) via `./x.sh` :

```
./x.sh check                 # gate complet : fmt + clippy + tests Rust + lint/tests UI
./x.sh test [args nextest]   # tests Rust
./x.sh cargo <args>          # cargo arbitraire dans le conteneur
./x.sh npm <args>            # npm dans ui/
./x.sh dev                   # backend + Vite -> http://localhost:5173 (long, en arrière-plan)
./x.sh shots [vue]           # captures Playwright 375/768/1280/1920 -> .artifacts/screens/
./x.sh desktop               # build Tauri Linux (AppImage + .deb) -> dist/
./x.sh -C .worktrees/<branche> <cmd>   # exécuter dans un worktree
./x.sh cliff [args]          # git-cliff épinglé (CHANGELOG, notes de release)
./x.sh clean [--dry-run]     # supprime les targets orphelins du cache (disque plein : skill dev-env)
scripts/release.sh X.Y.Z [--dry-run]       # publier une version (accord utilisateur requis)
scripts/release-status.sh vX.Y.Z [--wait]  # suivre release.yml et les fichiers publiés
```

N'appelle **jamais** `cargo`, `rustc`, `rustup`, `npm`, `npx`, `node` directement :
un hook bloque ces commandes. Détails et dépannage : skill `dev-env`.
Le premier `./x.sh` construit l'image (~10 min) : lance-le en arrière-plan.

## Règle n°2 : git local, worktrees, pas de `gh`

- `gh` n'est pas installé. Tout se fait avec `git` et `scripts/wt.sh`.
- Le checkout racine reste **sur `main`, propre**. On n'y code pas directement
  (sauf `docs/ROADMAP.md` et petits correctifs de config faits par l'orchestrateur).
- Chaque tâche = une branche `type/nom-court` + un worktree au **même nom** :
  `scripts/wt.sh new feat/dns-analyzer` crée `.worktrees/feat/dns-analyzer`.
- Fusion locale uniquement via `scripts/wt.sh merge <branche>` (rebase + gate + `--no-ff`).
  Pousser des branches est autorisé ; `main` n'est poussé que par `wt.sh merge --push`.
- Jamais de `push --force` sur `main`. `--force-with-lease` toléré sur sa propre branche.
- Une version se publie uniquement via `scripts/release.sh X.Y.Z`, après accord explicite de
  l'utilisateur pour ce numéro de version. Jamais de tag poussé à la main.
  Suivi : `scripts/release-status.sh vX.Y.Z --wait`. Procédure : `docs/GIT_WORKFLOW.md`.
- Travail parallèle : skill `parallel` (orchestrateur + agents `implementer` en arrière-plan,
  un worktree chacun, puis `reviewer` / `ui-reviewer`, puis fusions séquentielles).

## Stack

- Rust 1.99.1 (épinglé dans `rust-toolchain.toml` et `docker/Dockerfile`), édition 2024.
- Tauri 2 (fenêtre native) + API HTTP axum embarquée sur `127.0.0.1` (port aléatoire + jeton).
- Parsing 100 % Rust, **sans libpcap/Npcap/tshark** : `pcap-file`, `etherparse`,
  `tls-parser`, `x509-parser`, `simple-dns`, `httparse`, `snmp-parser`, `ldap-parser`, `nom`.
- Stockage : un fichier SQLite (WAL) par session via `rusqlite` (feature `bundled`)
  + blobs extraits adressés par SHA-256 sur disque.
- UI : React 19 + TypeScript + Vite + Tailwind 4, TanStack Query/Table/Virtual/Router,
  ECharts (renderer **SVG**), sigma.js + graphology (graphe réseau), d3-chord,
  icônes `lucide-react`, drapeaux `flag-icons` (SVG). Tests : Vitest + Playwright.
- Types partagés Rust -> TS générés par `ts-rs` dans `ui/src/api/types/` (ne pas éditer à la main).

Versions épinglées testées ensemble : `docs/STACK_VERSIONS.md` (à utiliser en phase 0).
Avant d'ajouter une dépendance : `./x.sh cargo add <crate>` ou `./x.sh npm i <pkg>`
(dernière version compatible), licence permissive uniquement (`deny.toml`). Pas de code GPL
porté (Wireshark, NetworkMiner, etc.) : on s'appuie sur les RFC et specs publiques.

## Conventions de code

- Code, identifiants, commentaires, messages de commit : **anglais**. Docs projet : français.
- Commits : Conventional Commits (`feat(dns): parse NBNS name queries`), impératif, sans emoji.
- Crates de parsing (`netsift-dissect`) : `#![forbid(unsafe_code)]`, aucune panique sur
  entrée hostile (`clippy::unwrap_used`, `expect_used`, `indexing_slicing`, `panic` = deny),
  tailles bornées, pas d'allocation proportionnelle à un champ de longueur non vérifié.
- Erreurs : `thiserror` dans les bibliothèques, `anyhow` uniquement dans binaires/tests.
- Horodatages : `i64` nanosecondes UTC partout. IP : `std::net::IpAddr` côté Rust, texte canonique en base.
- Tests : chaque analyseur a des tests sur pcaps **synthétiques** générés par `netsift-fixtures`
  (jamais de captures réelles commitées). Snapshots `insta` pour les sorties structurées.
- UI : aucun emoji, aucun caractère décoratif, textes courts et factuels, i18n `en` + `fr`
  (toutes les chaînes via le dictionnaire). Voir `docs/UI_GUIDELINES.md`.
- Un onglet n'est « fini » que si `./x.sh shots <vue>` passe (pas de débordement horizontal,
  pas de libellés qui se chevauchent) et que les captures ont été relues.

## Définition de « terminé » pour une branche

1. `./x.sh -C <worktree> check` vert.
2. Nouveaux comportements couverts par des tests (unitaires + pcap synthétique).
3. Si UI touchée : `./x.sh -C <worktree> shots <vue>` vert et captures relues (agent `ui-reviewer`).
4. Revue par l'agent `reviewer` sans point bloquant.
5. Commits propres et rebasés sur `main` ; fusion via `scripts/wt.sh merge`.
6. L'orchestrateur coche la tâche dans `docs/ROADMAP.md` sur `main`.

## Sécurité et données

- Les captures sont des **entrées hostiles** : parsing défensif, fuzzing (`./x.sh fuzz`).
- Les identifiants extraits sont sensibles : masqués par défaut dans l'UI, jamais logués,
  aucune télémétrie, aucun appel réseau sortant de l'application.
- Contenus extraits (HTML, SVG, scripts) jamais rendus tels quels dans la webview :
  miniatures générées côté Rust, SVG servis en téléchargement uniquement.
- `captures/`, `.data/`, `.artifacts/`, `dist/`, `*.pcap*` sont ignorés par git.

## Mode de travail attendu

- Commence par lire la spec concernée et la section de `ROADMAP.md`.
- Plan court, puis implémentation incrémentale avec tests ; lance `./x.sh check` souvent.
- Pour montrer l'avancement à l'utilisateur : skill `preview` (`./x.sh dev` ou `./x.sh desktop`).
- Si une décision structurante est nécessaire, ajoute un ADR dans `docs/DECISIONS.md`.
- Réponds à l'utilisateur en français.
