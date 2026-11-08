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
| Changelog / notes | `./x.sh cliff [args]` |
| Shell dans le conteneur | `./x.sh shell` |
| Nettoyer le cache de build | `./x.sh clean [--dry-run] [--all] [--images]` (voir « Disque plein ») |
| Dans un worktree | `./x.sh -C .worktrees/<branche> <cmd>` |

## Première utilisation

Construis l'image en arrière-plan, puis vérifie :
```
./x.sh image        # ou laisse le premier ./x.sh la construire
./x.sh cargo --version
./x.sh npm --version
```

## Caches et parallélisme

- Un volume `netsift-cache` contient : registre cargo (`/cache/cargo`), sccache (`/cache/sccache`,
  plafonné à 5 GiB par `SCCACHE_CACHE_SIZE`, éviction automatique), cache npm (`/cache/npm`),
  outils compilés (`/cache/tools`, `/cache/target/tools` : git-cliff) et les répertoires `target`
  (`/cache/target/<slug-du-worktree>`, 3 à 7 Go chacun).
- Chaque worktree a son propre `target` (slug = sha1 du chemin, 12 caractères) : pas de collision
  entre agents, mais les dépendances ne se recompilent pas d'un worktree à l'autre (registre +
  sccache partagés). Chaque commande écrit `/cache/target/<slug>/.origin` (chemin hôte, dernière
  utilisation) : c'est ce qui permet de reconnaître un target orphelin.
- `scripts/wt.sh rm` et `merge --cleanup` suppriment le target du worktree retiré ; `wt.sh new` et
  `merge --cleanup` lancent `./x.sh clean --auto` (orphelins seulement, silencieux).
- Désactiver sccache ponctuellement : `NO_SCCACHE=1 ./x.sh …`.
- Repartir d'une image neuve : `./x.sh image` (REBUILD implicite) ; vider tout le cache :
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
- **Disque plein** (conteneurs bloqués, `No space left on device`) : voir la section suivante.
- **Premier build lent / coupé** : relancer `./x.sh image` ; les couches déjà construites sont réutilisées.
- **Windows** : utiliser `./x.ps1` (mêmes sous-commandes). Docker Desktop ou Podman Desktop requis.
  Le build Windows « officiel » (installateurs signés) se fait en CI ; `./x.sh desktop-win` (cargo-xwin)
  est un dépannage local expérimental, pas le livrable.

## Disque plein

Le volume `netsift-cache` vit dans le stockage des conteneurs (`~/.local/share/containers` avec
Podman sans root, donc sur `/home`). Ce qui grossit : un `target` par worktree ou clone jetable
(3 à 7 Go chacun), sccache (5 GiB au plus), les images (`netsift-dev` ~3 Go, plus les anciennes
versions sans tag laissées par chaque reconstruction).

1. Voir ce qui serait libéré, sans rien supprimer :
   `./x.sh clean --dry-run` (targets orphelins avec leur taille, puis occupation du volume par
   catégorie et place libre).
2. Supprimer les orphelins : `./x.sh clean`. Est orphelin un target dont le `.origin` désigne un
   chemin disparu, ou, sans `.origin` (anciens targets), qui ne correspond à aucun worktree de
   `git worktree list` et n'a pas servi depuis 2 h. Jamais supprimés : `tools/`, un target dont le
   chemin existe, un target dont un build tient le verrou cargo.
3. Encore à court : `./x.sh clean --all` vide aussi les targets des worktrees existants (équivalent
   d'un `cargo clean` partout ; prochain build plus long). À éviter pendant qu'un agent compile.
4. Images : `./x.sh clean --images` lance `podman|docker image prune -f` (images sans tag
   uniquement, de tous les projets ; jamais `netsift-dev:latest` ni une image utilisée).
5. Dernier recours : `podman volume rm netsift-cache` (tout se recompile, git-cliff compris).

Si `/home` est à 100 %, même le conteneur de nettoyage peut échouer : libérer d'abord quelques
centaines de Mo (images sans tag : `podman image prune -f`), puis relancer `./x.sh clean`.

Détail de l'architecture de build : `docs/ARCHITECTURE.md` et ADR-004 dans `docs/DECISIONS.md`.
