#!/usr/bin/env bash
# Exécuté DANS le conteneur par `./x.sh cliff <args git-cliff>`.
# git-cliff n'est pas (encore) dans l'image : il est compilé une fois, à la version épinglée,
# dans le volume de cache (/cache/tools), puis réutilisé par tous les worktrees.
# Même version que la CI (orhun/git-cliff-action, input `version`) : docs/STACK_VERSIONS.md.
set -euo pipefail
GIT_CLIFF_VERSION="2.14.2"
PREFIX="/cache/tools/git-cliff-${GIT_CLIFF_VERSION}"
BIN="$PREFIX/bin/git-cliff"

if [[ ! -x "$BIN" ]]; then
  echo ">> Installation de git-cliff ${GIT_CLIFF_VERSION} dans le cache (une seule fois, ~3 min)…" >&2
  # Cible de compilation à part : ne pollue pas le target du worktree courant.
  cargo install --locked --quiet --root "$PREFIX" --target-dir /cache/target/tools \
    "git-cliff@${GIT_CLIFF_VERSION}" >&2
fi
exec "$BIN" "$@"
