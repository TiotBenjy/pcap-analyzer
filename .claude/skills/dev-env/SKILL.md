---
name: dev-env
description: Comment construire, tester, lancer et déboguer NetSift via la toolchain conteneurisée (./x.sh avec Docker ou Podman). À consulter avant toute commande de build/test/dev, en cas d'erreur de conteneur, de cache ou de ports, ou pour travailler dans un worktree.
---

# Environnement de développement conteneurisé

Aucune toolchain sur l'hôte. Tout passe par `./x.sh` (Linux/macOS) ou `./x.ps1` (Windows),
qui exécute Rust et Node dans l'image `docker/Dockerfile`. Docker **et** Podman sont supportés
(auto-détecté ; forcer avec `ENGINE=podman` / `ENGINE=docker`). Un hook bloque cargo/npm/node/gh
directement sur l'hôte : si tu vois « Commande bloquée », reformule avec `./x.sh`.

## Commandes

| Besoin | Commande |
|---|---|
| Construire l'image | `./x.sh image` (première fois ~10 min ; lance-la en arrière-plan) |
| Gate complet (= CI) | `./x.sh check` |
| Tests Rust | `./x.sh test [args nextest]` |
| cargo arbitraire | `./x.sh cargo <args>` (ex. `./x.sh cargo add nom`) |
| Clippy / fmt / deny | `./x.sh clippy` · `./x.sh fmt` · `./x.sh deny` |
| npm dans ui/ | `./x.sh npm <args>` · `./x.sh ui <script>` |
| Serveur de dev | `./x.sh dev` (long ; voir skill `preview`) |
| Captures visuelles | `./x.sh shots [vue]` |
| Build desktop Linux | `./x.sh desktop` |
| GeoIP | `./x.sh geoip` |
| Shell dans le conteneur | `./x.sh shell` |
| Dans un worktree | `./x.sh -C .worktrees/<branche> <cmd>` |

## Première utilisation

Construis l'image en arrière-plan, puis vérifie :
```
./x.sh image        # ou laisse le premier ./x.sh la construire
./x.sh cargo --version
./x.sh npm --version
```

## Caches et parallélisme

- Un volume `netsift-cache` contient : registre cargo (`/cache/cargo`), sccache (`/cache/sccache`),
  cache npm (`/cache/npm`) et les répertoires `target` (`/cache/target/<slug-du-worktree>`).
- Chaque worktree a son propre `target` (slug dérivé du chemin) : pas de collision entre agents,
  mais les dépendances ne se recompilent pas d'un worktree à l'autre (registre + sccache partagés).
- Désactiver sccache ponctuellement : `NO_SCCACHE=1 ./x.sh …`.
- Repartir d'une image neuve : `./x.sh image` (REBUILD implicite) ; vider le cache :
  `docker volume rm netsift-cache` (ou `podman …`).

## Ports (dev)

`./x.sh dev` publie l'UI et l'API **sur 127.0.0.1 uniquement**. Les ports sont dérivés du chemin du
worktree pour éviter les collisions quand plusieurs `dev` tournent ; forcer avec
`NETSIFT_UI_PORT=5173 NETSIFT_API_PORT=7878 ./x.sh dev`. L'URL exacte est affichée au lancement.

## Dépannage

- **« ni podman ni docker »** : l'utilisateur doit installer l'un des deux. Rien d'autre n'est requis.
- **Permissions sur les fichiers créés** : Docker utilise `--user $(id -u):$(id -g)`, Podman
  `--userns=keep-id`. Si des fichiers appartiennent à root, vérifier que l'entrypoint a bien préparé
  les caches ; au besoin `./x.sh shell` puis corriger, ou `ENGINE=podman`.
- **SELinux (Fedora/RHEL, Podman)** : les montages utilisent déjà le suffixe `:z`.
- **Pas d'espace disque** : le cache `target` grossit ; supprimer `/cache/target/<slug>` d'un worktree
  fermé via `./x.sh shell`, ou recréer le volume.
- **Premier build lent / coupé** : relancer `./x.sh image` ; les couches déjà construites sont réutilisées.
- **Windows** : utiliser `./x.ps1` (mêmes sous-commandes). Docker Desktop ou Podman Desktop requis.
  Le build Windows « officiel » (installateurs signés) se fait en CI ; `./x.sh desktop-win` (cargo-xwin)
  est un dépannage local expérimental, pas le livrable.

Détail de l'architecture de build : `docs/ARCHITECTURE.md` et ADR-004 dans `docs/DECISIONS.md`.
