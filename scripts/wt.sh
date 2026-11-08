#!/usr/bin/env bash
# Gestion des worktrees git nommés comme les branches, pour le travail parallèle d'agents.
# Aucun `gh` : uniquement des commandes git locales. Voir docs/GIT_WORKFLOW.md.
#
#   scripts/wt.sh new <branche> [base=main]      crée la branche + .worktrees/<branche>
#   scripts/wt.sh list                           liste les worktrees et leur état
#   scripts/wt.sh sync <branche>                 rebase <branche> sur main (dans son worktree)
#   scripts/wt.sh check <branche>                ./x.sh check dans le worktree
#   scripts/wt.sh push <branche>                 git push -u origin <branche> (si remote)
#   scripts/wt.sh merge <branche> [--push] [--cleanup] [--no-check]
#                                                sync + check + merge --no-ff dans main
#   scripts/wt.sh rm <branche> [--delete-branch] supprime le worktree et son target de build
#
# `new` et `merge --cleanup` lancent aussi `./x.sh clean --auto` (targets orphelins du cache,
# silencieux s'il n'y a rien à supprimer) ; NETSIFT_NO_AUTO_CLEAN=1 le désactive.
# Un échec du nettoyage du cache n'est qu'un avertissement : il ne bloque jamais une commande.
set -euo pipefail

ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")/.." rev-parse --show-toplevel)"
cd "$ROOT"
WT_DIR="$ROOT/.worktrees"
MAIN="main"
LOCK="$ROOT/.git/wt-merge.lock"

die() { echo "wt: $*" >&2; exit 1; }
has_remote() { git remote | grep -q .; }
branch_exists() { git show-ref --verify --quiet "refs/heads/$1"; }
wt_path() { echo "$WT_DIR/$1"; }
warn() { echo "wt: avertissement : $*" >&2; }

# Nettoyage du cache de build (via le conteneur : les fichiers appartiennent à l'UID mappé).
clean_worktree_target() { # <chemin du worktree supprimé>
  "$ROOT/x.sh" clean --worktree "$1" || warn "target de $1 non supprimé (./x.sh clean le retrouvera)"
}
auto_clean() {
  [[ "${NETSIFT_NO_AUTO_CLEAN:-0}" == "1" ]] && return 0
  "$ROOT/x.sh" clean --auto || warn "nettoyage automatique du cache ignoré"
}

cmd_new() {
  local br="${1:?branche requise}" base="${2:-$MAIN}"
  # Points admis pour les numéros de version (chore/release-0.2.0), jamais en fin ni doublés.
  [[ "$br" =~ ^(feat|fix|perf|refactor|test|docs|chore|ci)/[a-z0-9][a-z0-9.-]*$ \
     && "$br" != *..* && "$br" != *. ]] \
    || die "nom de branche invalide : $br (attendu type/nom-court)"
  local path; path="$(wt_path "$br")"
  [[ -e "$path" ]] && die "le worktree existe déjà : $path"
  mkdir -p "$(dirname "$path")"
  git fetch --quiet origin "$base" 2>/dev/null || true
  if branch_exists "$br"; then
    git worktree add "$path" "$br"
  else
    git worktree add -b "$br" "$path" "$base"
  fi
  echo ">> Worktree prêt : $path  (branche $br sur $base)"
  echo ">> Exécuter des commandes dedans : ./x.sh -C $path <cmd>"
  auto_clean
}

cmd_list() {
  git worktree list --porcelain | awk '
    /^worktree /{wt=$2}
    /^branch /{br=$2; sub("refs/heads/","",br);
      "git -C " wt " status --porcelain" | getline dirty_line;
      print br "  @  " wt}'
  echo "---"
  git worktree list
}

cmd_sync() {
  local br="${1:?}"; local path; path="$(wt_path "$br")"
  [[ -d "$path" ]] || die "pas de worktree pour $br"
  git fetch --quiet origin "$MAIN" 2>/dev/null || true
  echo ">> Rebase de $br sur $MAIN…"
  git -C "$path" rebase "$MAIN"
}

cmd_check() {
  local br="${1:?}"; local path; path="$(wt_path "$br")"
  [[ -d "$path" ]] || die "pas de worktree pour $br"
  "$ROOT/x.sh" -C "$path" check
}

cmd_push() {
  local br="${1:?}"
  has_remote || { echo ">> Aucun remote configuré, push ignoré."; return 0; }
  git push -u origin "$br"
}

cmd_merge() {
  local br="" do_push=0 do_cleanup=0 do_check=1
  while [[ $# -gt 0 ]]; do case "$1" in
    --push) do_push=1;; --cleanup) do_cleanup=1;; --no-check) do_check=0;;
    *) br="$1";; esac; shift; done
  [[ -n "$br" ]] || die "branche requise"
  local path; path="$(wt_path "$br")"
  [[ -d "$path" ]] || die "pas de worktree pour $br"

  # Verrou : une seule fusion à la fois (agents parallèles).
  exec 9>"$LOCK"; flock 9 || die "une autre fusion est en cours"

  [[ -z "$(git -C "$path" status --porcelain)" ]] || die "$br a des modifications non commitées"
  cmd_sync "$br"
  if [[ "$do_check" == "1" ]]; then echo ">> Gate sur $br…"; "$ROOT/x.sh" -C "$path" check; fi

  [[ -z "$(git -C "$ROOT" status --porcelain)" ]] || die "le checkout racine ($MAIN) n'est pas propre"
  git -C "$ROOT" checkout "$MAIN"
  echo ">> Fusion de $br dans $MAIN (--no-ff)…"
  git -C "$ROOT" merge --no-ff "$br" -m "merge($br): intégration"

  if [[ "$do_push" == "1" ]] && has_remote; then
    git -C "$ROOT" push origin "$MAIN"
    # --cleanup : la branche fusionnée disparaît aussi du remote ; sinon elle y est sauvegardée.
    if [[ "$do_cleanup" == "1" ]]; then
      git push origin --delete "$br" 2>/dev/null || true
    else
      git push origin "$br" || true
    fi
  fi
  if [[ "$do_cleanup" == "1" ]]; then cmd_rm "$br" --delete-branch; auto_clean; fi
  echo ">> $br fusionné dans $MAIN."
}

cmd_rm() {
  local br="${1:?}" del="${2:-}"
  local path; path="$(wt_path "$br")"
  [[ -d "$path" ]] && git worktree remove "$path" --force
  git worktree prune
  [[ "$del" == "--delete-branch" ]] && branch_exists "$br" && git branch -D "$br" || true
  echo ">> Worktree $br supprimé."
  [[ -e "$path" ]] || clean_worktree_target "$path"
}

sub="${1:-}"; shift || true
case "$sub" in
  new) cmd_new "$@";;
  list|ls) cmd_list "$@";;
  sync) cmd_sync "$@";;
  check) cmd_check "$@";;
  push) cmd_push "$@";;
  merge) cmd_merge "$@";;
  rm|remove) cmd_rm "$@";;
  *) sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//';;
esac
