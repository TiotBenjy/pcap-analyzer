#!/usr/bin/env bash
# PreToolUse (Bash) : empêche d'utiliser les toolchains directement sur l'hôte.
# L'utilisateur n'a ni Rust ni Node ; tout passe par ./x.sh (conteneur). Ce hook est une
# ceinture de sécurité en plus des règles deny de settings.json : il découpe la commande en
# sous-commandes et bloque si l'exécutable appelé est une toolchain hôte, en expliquant l'alternative.
#
# Entrée : JSON sur stdin (champ .tool_input.command). Sortie : exit 2 = bloqué (stderr -> Claude).
set -euo pipefail

INPUT="$(cat)"

# Extraire .tool_input.command sans dépendance (ni jq ni python garantis sur l'hôte).
# On prend tout après "command":" jusqu'au guillemet non échappé, puis on déséchappe \" \\ \n \t.
CMD="$(printf '%s' "$INPUT" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\(.*\)/\1/p')"
# Retirer la fin du JSON après la chaîne (heuristique : dernière occurrence de "} en fin).
CMD="${CMD%\"*}"
CMD="$(printf '%s' "$CMD" | sed -e 's/\\"/"/g' -e 's/\\n/\n/g' -e 's/\\t/\t/g' -e 's/\\\\/\\/g')"

[[ -z "$CMD" ]] && exit 0

# Binaires interdits en appel direct sur l'hôte.
BANNED='cargo rustc rustup npm npx node pnpm yarn gh'

# Découper en sous-commandes sur les opérateurs shell et les retours à la ligne.
normalized="$(printf '%s' "$CMD" | tr '\n' ';' | sed -e 's/&&/;/g' -e 's/||/;/g' -e 's/|/;/g' -e 's/&/;/g')"

IFS=';' read -ra parts <<< "$normalized"
for raw in "${parts[@]}"; do
  seg="$(printf '%s' "$raw" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  [[ -z "$seg" ]] && continue
  # Ignorer les affectations d'environnement en tête (VAR=val ...) et un éventuel `cd dir`.
  while [[ "$seg" =~ ^[A-Za-z_][A-Za-z0-9_]*=[^[:space:]]* ]]; do
    seg="$(printf '%s' "$seg" | sed -E 's/^[A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*[[:space:]]*//')"
  done
  first="${seg%%[[:space:]]*}"
  # Retirer un éventuel chemin : on ne vise que les appels directs (cargo, /usr/bin/cargo, ...).
  base="${first##*/}"
  for b in $BANNED; do
    if [[ "$base" == "$b" ]]; then
      cat >&2 <<EOF
Commande bloquée : « $base » ne doit pas être exécuté directement sur l'hôte.
Cette machine n'a pas de toolchain ($base) : tout passe par le conteneur via ./x.sh.

Équivalents :
  cargo <args>   ->  ./x.sh cargo <args>        (ou ./x.sh test / check / clippy / fmt)
  npm <args>     ->  ./x.sh npm <args>          (dans ui/)
  gh ...         ->  pas de gh : git local + scripts/wt.sh (voir docs/GIT_WORKFLOW.md)

Pour une commande dans un worktree :  ./x.sh -C .worktrees/<branche> <cmd>
EOF
      exit 2
    fi
  done
done

exit 0
