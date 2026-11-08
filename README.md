# NetSift

Analyse forensique de captures réseau (pcap / pcapng), application de bureau pour **Linux, Windows et macOS**.
Importe un fichier unique ou **un dossier de captures découpées en chunks** (dumpcap/Wireshark
`-b filesize`/`-b duration`, tcpdump `-C`/`-G`) et les recolle en une seule session continue.

Usage solo, local, hors ligne. Parsing 100 % Rust (ni libpcap, ni Npcap, ni tshark). Interface sobre
et professionnelle. Stockage SQLite par session (sessions de plusieurs gigaoctets).

> État : amorçage. Le code est produit tâche par tâche selon `docs/ROADMAP.md`.

## Téléchargement

Les installateurs sont attachés à chaque version sur la page
[Releases](https://github.com/TiotBenjy/pcap-analyzer/releases) : `.deb`, `.rpm` et `.AppImage`
(Linux x86_64), `-setup.exe` et `.msi` (Windows x86_64), `.dmg` universel (macOS 11+, Apple Silicon
et Intel), avec `SHA256SUMS.txt`. Ils ne sont pas signés : Windows SmartScreen et macOS Gatekeeper
affichent un avertissement au premier lancement (marche à suivre dans les notes de chaque version).
Historique : `CHANGELOG.md`.

## Développement : prérequis

**Docker** ou **Podman** uniquement. Aucune installation de Rust ou de Node sur votre machine :
toute la toolchain vit dans un conteneur, piloté par `./x.sh` (Linux/macOS) ou `./x.ps1` (Windows).

## Démarrage

```bash
./x.sh image     # construit l'image (première fois ~10 min)
./x.sh check     # fmt + clippy + tests Rust + lint/tests UI
./x.sh dev       # lance l'app en local -> http://localhost:<port affiché>
./x.sh desktop   # construit l'application desktop Linux (AppImage + .deb) dans dist/
```

Windows : remplacez `./x.sh` par `./x.ps1` (sous-commandes principales ; `cliff` y fonctionne
depuis le checkout racine seulement). Les installateurs Windows et
macOS sont produits par la CI (voir ci-dessous).

## Voir l'interface pendant le développement

- `./x.sh shots` : captures d'écran de chaque vue en plusieurs largeurs (clair/sombre) dans
  `.artifacts/screens/`, avec vérifications anti-débordement et anti-chevauchement.
- `./x.sh dev` : application en direct dans le navigateur.
- `./x.sh desktop` : vraie application desktop à tester.

Déposez des captures dans `captures/` pour les essayer en mode dev.

## Développement avec Claude Code

Ce dépôt est préparé pour Claude Code :

- `CLAUDE.md` : règles du projet (toolchain conteneurisée, git local, conventions).
- `.claude/skills/` : `dev-env` (build/test/dev), `parallel` (agents en parallèle), `preview` (montrer l'UI).
- `.claude/agents/` : `implementer`, `reviewer`, `ui-reviewer`.
- `.claude/hooks/` : garde-fou qui empêche d'appeler cargo/npm/node/gh directement sur l'hôte.
- `docs/` : architecture, specs par onglet, gestion des chunks, règles UI, workflow git, roadmap.

Le travail se fait par branches dans des **worktrees** (`scripts/wt.sh`), fusionnés **en local**
(pas de `gh`, pas de pull requests). Voir `docs/GIT_WORKFLOW.md`.

## Compilation continue (CI/CD GitHub)

- Push d'une branche -> `.github/workflows/ci.yml` (fmt, clippy, tests Rust, lint/tests/visuels UI, licences).
- `scripts/release.sh X.Y.Z` -> fusion de la version sur `main` et tag `vX.Y.Z` ->
  `.github/workflows/release.yml` : bundles **Linux** (AppImage, .deb, .rpm), **Windows** (NSIS, MSI)
  et **macOS** (.dmg universel) construits sur les runners GitHub, publiés dans une release dont les
  notes sont générées depuis les commits (git-cliff). C'est ainsi qu'on produit les binaires Windows
  et macOS sans toolchain sur votre machine. Procédure : `docs/GIT_WORKFLOW.md`, « Publier une version ».

## Structure

```
crates/      bibliothèques et CLI Rust (voir docs/ARCHITECTURE.md)
apps/desktop application Tauri
ui/          frontend React/TypeScript
docker/      image de dev/build
scripts/     wt.sh (worktrees) + scripts exécutés dans le conteneur et en CI
docs/        documentation du projet
x.sh / x.ps1 pilote de la toolchain conteneurisée
```

## Licences et données

Code sous licence permissive (MIT/Apache-2.0, voir `deny.toml`). Aucun code sous licence copyleft
n'est porté. GeoIP : base DB-IP IP-to-Country Lite (CC BY 4.0), attribution dans « À propos ».
Les captures analysées ne quittent jamais la machine ; l'application n'émet aucun trafic réseau.
