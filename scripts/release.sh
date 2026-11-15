#!/usr/bin/env bash
# Publie une version de NetSift de bout en bout, sans interaction (voir docs/GIT_WORKFLOW.md,
# « Publier une version »). À lancer sur l'hôte, depuis le checkout racine, sur main.
#
#   scripts/release.sh X.Y.Z [--dry-run]
#
#   1. scripts/wt.sh new chore/release-X.Y.Z
#   2. dans ce worktree : versions (Cargo.toml, Cargo.lock, fuzz/Cargo.lock, ui/package*.json),
#      check-version, CHANGELOG.md (git-cliff --tag vX.Y.Z), commit « chore(release): vX.Y.Z »
#      X.Y.Z égal à la version actuelle (première publication de la version déjà en place, par
#      exemple 0.1.0) : aucune modification de version, seulement CHANGELOG.md et le commit
#   3. scripts/wt.sh merge chore/release-X.Y.Z --push --cleanup   (gate complet ; pousse main)
#   4. tag annoté vX.Y.Z sur main (le commit de fusion), git push origin vX.Y.Z
#      -> déclenche .github/workflows/release.yml
#   5. affiche les URL (Actions, release) et la commande de suivi
#
#   --dry-run  vérifie les préconditions, affiche le plan exact (versions modifiées ou non,
#              CHANGELOG.md, fusion, tag) et les notes de la release ; aucune écriture dans le
#              dépôt (seules les références distantes sont rafraîchies).
#
# Tests : utiliser un clone jetable dont `origin` est un dépôt bare local (pas de mode sans push :
# seul `wt.sh merge --push` pousse main).
#
# Variable : RELEASE_COAUTHOR (ligne de fin du commit de release ; vide = aucune).
set -euo pipefail
export LC_ALL=C

RELEASE_COAUTHOR="${RELEASE_COAUTHOR-Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>}"
SEMVER_RE='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'

die()  { echo "release: $*" >&2; exit 1; }
info() { echo ">> $*"; }

# semver_gt A B : vrai si A > B selon SemVer 2.0.0 (§11 : prerelease < release, identifiants
# numériques comparés en nombre et inférieurs aux alphanumériques, liste plus courte inférieure).
semver_gt() {
  local a="$1" b="$2" a_pre="" b_pre="" i x y n
  [[ "$a" == *-* ]] && a_pre="${a#*-}"
  [[ "$b" == *-* ]] && b_pre="${b#*-}"
  local -a an bn ap bp
  IFS=. read -r -a an <<< "${a%%-*}"
  IFS=. read -r -a bn <<< "${b%%-*}"
  for i in 0 1 2; do
    if ((10#${an[i]} > 10#${bn[i]})); then return 0; fi
    if ((10#${an[i]} < 10#${bn[i]})); then return 1; fi
  done
  [[ -z "$a_pre" && -z "$b_pre" ]] && return 1
  [[ -z "$a_pre" ]] && return 0
  [[ -z "$b_pre" ]] && return 1
  IFS=. read -r -a ap <<< "$a_pre"
  IFS=. read -r -a bp <<< "$b_pre"
  n=${#ap[@]}; ((${#bp[@]} > n)) && n=${#bp[@]}
  for ((i = 0; i < n; i++)); do
    x="${ap[i]:-}" y="${bp[i]:-}"
    [[ -z "$x" ]] && return 1
    [[ -z "$y" ]] && return 0
    if [[ "$x" =~ ^[0-9]+$ && "$y" =~ ^[0-9]+$ ]]; then
      if ((10#$x > 10#$y)); then return 0; fi
      if ((10#$x < 10#$y)); then return 1; fi
    elif [[ "$x" =~ ^[0-9]+$ ]]; then return 1
    elif [[ "$y" =~ ^[0-9]+$ ]]; then return 0
    elif [[ "$x" > "$y" ]]; then return 0
    elif [[ "$x" < "$y" ]]; then return 1
    fi
  done
  return 1
}

# github_slug URL : "owner/repo" pour un remote GitHub (ssh ou https), vide sinon.
github_slug() {
  local url="$1"
  if [[ "$url" =~ ^(git@github\.com:|ssh://git@github\.com/|https://github\.com/)([^/]+)/([^/]+)$ ]]; then
    echo "${BASH_REMATCH[2]}/${BASH_REMATCH[3]%.git}"
  fi
}

# release_kind ACTUELLE DEMANDÉE : « bump » si la version demandée dépasse l'actuelle, « same » si
# elle lui est égale (publication de la version déjà en place : seul le tag manque), échec sinon.
release_kind() {
  if [[ "$2" == "$1" ]]; then echo same
  elif semver_gt "$2" "$1"; then echo bump
  else return 1
  fi
}

# Remplace la version de [workspace.package] dans un Cargo.toml (fichier modifié sur place).
set_workspace_version() {
  local file="$1" version="$2"
  awk -v v="$version" '
    /^\[/ { in_pkg = ($0 == "[workspace.package]") }
    in_pkg && /^version[[:space:]]*=/ && !done { print "version = \"" v "\""; done = 1; next }
    { print }
    END { if (!done) exit 1 }' "$file" > "$file.release.tmp" \
    || { rm -f "$file.release.tmp"; return 1; }
  mv "$file.release.tmp" "$file"
}

# apply_version DIR VERSION RUNNER : écrit VERSION dans le dépôt DIR. RUNNER exécute
# « RUNNER cargo <args> » à la racine de DIR et « RUNNER npm <args> » dans DIR/ui (x.sh -C DIR en
# vrai, cargo et npm directs dans scripts/tests/release.sh).
#   - Cargo.toml [workspace.package] version, puis Cargo.lock (crates du workspace seulement) ;
#   - fuzz/Cargo.lock : fuzz/ est hors workspace mais référence les crates netsift-* par chemin ;
#     cargo metadata (sans --locked) y réécrit leur version, rien d'autre (le gate le vérifie
#     ensuite avec --locked) ;
#   - ui/package.json et ui/package-lock.json (npm version, sans commit ni tag).
apply_version() {
  local dir="$1" version="$2" runner="$3"
  set_workspace_version "$dir/Cargo.toml" "$version"
  "$runner" cargo update --workspace --quiet
  if [[ -f "$dir/fuzz/Cargo.toml" ]]; then
    "$runner" cargo metadata --quiet --format-version 1 --manifest-path fuzz/Cargo.toml >/dev/null
  fi
  "$runner" npm version "$version" --no-git-tag-version --allow-same-version >/dev/null
}

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"; }

main() {
  local version="" dry_run=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run) dry_run=1 ;;
      -h|--help) usage; exit 0 ;;
      -*) usage >&2; exit 2 ;;
      *) [[ -z "$version" ]] || { usage >&2; exit 2; }; version="${1#v}" ;;
    esac
    shift
  done
  [[ -n "$version" ]] || { usage >&2; exit 2; }
  [[ "$version" =~ $SEMVER_RE ]] || die "version invalide : '$version' (SemVer X.Y.Z ou X.Y.Z-pre)"

  # Globales (pas `local`) : lues par le piège EXIT.
  root="$(git -C "$(dirname "${BASH_SOURCE[0]}")/.." rev-parse --show-toplevel)"
  tag="v$version"
  br="chore/release-$version"
  wt="$root/.worktrees/$br"

  # --- Préconditions (aucune modification avant qu'elles soient toutes vérifiées) -------
  [[ "$(git -C "$root" rev-parse --path-format=absolute --git-dir)" \
     == "$(git -C "$root" rev-parse --path-format=absolute --git-common-dir)" ]] \
    || die "à lancer depuis le checkout racine, pas depuis un worktree"
  [[ "$(git -C "$root" symbolic-ref --short -q HEAD || true)" == "main" ]] \
    || die "le checkout racine doit être sur main"
  [[ -z "$(git -C "$root" status --porcelain)" ]] || die "le checkout racine n'est pas propre"
  git -C "$root" remote get-url origin >/dev/null 2>&1 || die "aucun remote 'origin'"
  info "git fetch origin"
  git -C "$root" fetch --quiet origin || die "git fetch origin a échoué"
  [[ "$(git -C "$root" rev-parse main)" == "$(git -C "$root" rev-parse origin/main 2>/dev/null || true)" ]] \
    || die "main n'est pas égal à origin/main (fusionner ou pousser d'abord)"

  local current
  current="$(bash "$root/scripts/check-version.sh" -C "$root")" \
    || die "versions incohérentes sur main (scripts/check-version.sh)"
  local kind
  kind="$(release_kind "$current" "$version")" \
    || die "$version est inférieure à la version actuelle ($current)"

  git -C "$root" rev-parse -q --verify "refs/tags/$tag" >/dev/null && die "le tag $tag existe déjà en local"
  local rc=0
  git -C "$root" ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1 || rc=$?
  case "$rc" in
    0) die "le tag $tag existe déjà sur origin" ;;
    2) ;;
    *) die "impossible d'interroger les tags d'origin (git ls-remote, code $rc)" ;;
  esac
  git -C "$root" show-ref --verify --quiet "refs/heads/$br" && die "la branche $br existe déjà"
  [[ ! -e "$wt" ]] || die "le worktree $wt existe déjà"

  local slug
  slug="$(github_slug "$(git -C "$root" remote get-url origin)")"

  # --- Dry run ----------------------------------------------------------------------
  if [[ "$dry_run" == "1" ]]; then
    local changelog="créé"
    [[ -f "$root/CHANGELOG.md" ]] && changelog="régénéré"
    info "Préconditions OK. Plan de publication de $tag :"
    echo "   1. worktree et branche $br (scripts/wt.sh new)"
    if [[ "$kind" == "same" ]]; then
      echo "   2. version $version déjà en place (Cargo.toml, Cargo.lock, fuzz/Cargo.lock, ui/package*.json) :"
      echo "      aucune modification de version, première publication de la version courante ;"
    else
      echo "   2. version $current -> $version : Cargo.toml [workspace.package], Cargo.lock et"
      echo "      fuzz/Cargo.lock (crates netsift-*), ui/package.json, ui/package-lock.json ;"
    fi
    echo "      CHANGELOG.md $changelog (git-cliff --tag $tag), commit « chore(release): $tag »"
    echo "   3. scripts/wt.sh merge $br --push --cleanup : gate complet, fusion --no-ff dans main,"
    echo "      push de main sur origin, suppression du worktree et de la branche"
    echo "   4. tag annoté $tag sur la fusion, git push origin $tag -> release.yml (brouillon,"
    echo "      bundles Linux, Windows et macOS, SHA256SUMS.txt, publication)"
    echo "   5. suivi : scripts/release-status.sh $tag --wait"
    info "Notes de la release $tag (git-cliff --unreleased --tag $tag) :"
    echo
    "$root/x.sh" -C "$root" cliff --unreleased --tag "$tag" --strip all
    cat "$root/.github/release-notes-footer.md"
    echo
    info "Dry run : aucune modification."
    exit 0
  fi

  # --- Publication ------------------------------------------------------------------
  state="prepare"
  orig_main="$(git -C "$root" rev-parse main)"

  # En cas d'échec : nettoyage automatique tant que main n'a pas bougé, sinon instructions.
  # shellcheck disable=SC2317,SC2329 # invoquée par le piège EXIT
  on_exit() {
    local code=$?
    [[ "$code" -eq 0 ]] && return 0
    echo >&2
    echo "release: échec (étape : $state)." >&2
    local now_main origin_main
    now_main="$(git -C "$root" rev-parse main)"
    origin_main="$(git -C "$root" rev-parse origin/main 2>/dev/null || true)"
    case "$state" in
      prepare|merge)
        if [[ "$now_main" == "$orig_main" ]]; then
          echo "release: rien n'a été poussé ; suppression du worktree et de la branche $br." >&2
          git -C "$wt" rebase --abort >/dev/null 2>&1 || true
          "$root/scripts/wt.sh" rm "$br" --delete-branch >&2 || true
        elif [[ "$now_main" != "$origin_main" ]]; then
          echo "release: main contient la fusion mais n'est pas poussé. Pour annuler :" >&2
          echo "  git -C $root reset --hard $orig_main" >&2
          echo "  $root/scripts/wt.sh rm $br --delete-branch" >&2
        else
          echo "release: main est poussé, le tag ne l'est pas. Pour terminer :" >&2
          echo "  git -C $root tag -a $tag -m \"NetSift $tag\" main && git -C $root push origin $tag" >&2
        fi ;;
      tag)
        if git -C "$root" rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
          echo "release: le tag $tag existe en local, pas sur origin. Pour terminer :" >&2
          echo "  git -C $root push origin $tag" >&2
        else
          echo "release: main est fusionné, tag non créé. Pour terminer :" >&2
          echo "  git -C $root tag -a $tag -m \"NetSift $tag\" main && git -C $root push origin $tag" >&2
        fi ;;
    esac
  }
  trap on_exit EXIT

  info "1/5 Worktree $br"
  "$root/scripts/wt.sh" new "$br" main

  if [[ "$kind" == "same" ]]; then
    info "2/5 Version $version déjà en place : CHANGELOG.md, commit"
  else
    info "2/5 Versions $current -> $version, CHANGELOG.md, commit"
    # shellcheck disable=SC2329 # invoquée par apply_version
    xrun() { "$root/x.sh" -C "$wt" "$@"; }
    apply_version "$wt" "$version" xrun
  fi
  bash "$root/scripts/check-version.sh" -C "$wt" "$tag" >/dev/null
  "$root/x.sh" -C "$wt" cliff --tag "$tag" --output CHANGELOG.md

  local unexpected
  unexpected="$(git -C "$wt" status --porcelain \
    | grep -vE '^( M|M |\?\?) (Cargo\.toml|Cargo\.lock|fuzz/Cargo\.lock|ui/package\.json|ui/package-lock\.json|CHANGELOG\.md)$' || true)"
  [[ -z "$unexpected" ]] || die "modifications inattendues dans le worktree :"$'\n'"$unexpected"
  git -C "$wt" add Cargo.toml Cargo.lock fuzz/Cargo.lock ui/package.json ui/package-lock.json CHANGELOG.md
  local msg="chore(release): $tag"
  [[ -n "$RELEASE_COAUTHOR" ]] && msg+=$'\n\n'"$RELEASE_COAUTHOR"
  git -C "$wt" commit --quiet -m "$msg"

  state="merge"
  info "3/5 Fusion dans main (gate complet)"
  "$root/scripts/wt.sh" merge "$br" --push --cleanup

  state="tag"
  [[ "$(git -C "$root" log -1 --format=%s main)" == "merge($br): intégration" ]] \
    || die "HEAD de main n'est pas la fusion de $br"
  bash "$root/scripts/check-version.sh" -C "$root" "$tag" >/dev/null
  info "4/5 Tag $tag"
  git -C "$root" tag -a "$tag" -m "NetSift $tag" main

  git -C "$root" push origin "refs/tags/$tag"
  trap - EXIT

  info "5/5 Tag poussé : release.yml construit et publie la release."
  if [[ -n "$slug" ]]; then
    echo "  Actions : https://github.com/$slug/actions/workflows/release.yml?query=branch%3A$tag"
    echo "  Release : https://github.com/$slug/releases/tag/$tag (visible une fois publiée)"
  fi
  echo "  Suivi   : scripts/release-status.sh $tag --wait"
}

# Exécuté (et non sourcé par scripts/tests/release.sh) : lancer la publication.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
