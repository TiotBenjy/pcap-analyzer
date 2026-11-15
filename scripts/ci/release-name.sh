#!/usr/bin/env bash
# Nom de la release GitHub du tag TAG (release.yml, job create ; docs/GIT_WORKFLOW.md) :
# « NetSift TAG — titre » si le message du tag annoté porte un titre (écrit par
# scripts/release.sh --title), « NetSift TAG » sinon. Le tag doit être l'objet tag annoté, pas
# la référence légère qu'actions/checkout crée pour un événement de tag : le job le récupère
# d'abord avec `git fetch --force origin "+refs/tags/TAG:refs/tags/TAG"`.
# Seul le nom va sur la sortie standard. Un titre ignoré (tag léger, titre invalide) donne un
# avertissement de workflow sur la sortie d'erreur, jamais un échec.
#
#   bash scripts/ci/release-name.sh TAG
set -euo pipefail
[[ $# -eq 1 ]] || { echo "usage: $0 TAG" >&2; exit 2; }

# shellcheck source=scripts/release.sh
source "$(dirname "${BASH_SOURCE[0]}")/../release.sh"

warnings="$(mktemp)"
trap 'rm -f "$warnings"' EXIT
name="$(release_name "$(git rev-parse --show-toplevel)" "$1" 2>"$warnings")" \
  || { echo "::error::tag $1 introuvable" >&2; exit 1; }
while IFS= read -r line; do
  echo "::warning::$line" >&2
done < "$warnings"
printf '%s\n' "$name"
