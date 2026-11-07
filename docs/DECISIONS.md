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
