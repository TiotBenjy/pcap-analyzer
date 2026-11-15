#!/usr/bin/env bash
# Publie une version de NetSift de bout en bout, sans interaction (voir docs/GIT_WORKFLOW.md,
# « Publier une version »). À lancer sur l'hôte, depuis le checkout racine, sur main.
#
#   scripts/release.sh X.Y.Z [--title "résumé court"] [--dry-run]
#
#   1. scripts/wt.sh new chore/release-X.Y.Z
#   2. dans ce worktree : versions (Cargo.toml, Cargo.lock, fuzz/Cargo.lock, ui/package*.json),
#      check-version, CHANGELOG.md (git-cliff --tag vX.Y.Z), commit « chore(release): vX.Y.Z »
#      X.Y.Z égal à la version actuelle (première publication de la version déjà en place, par
#      exemple 0.1.0) : aucune modification de version, seulement CHANGELOG.md et le commit
#   3. scripts/wt.sh merge chore/release-X.Y.Z --push --cleanup   (gate complet ; pousse main)
#   4. tag annoté vX.Y.Z sur main (le commit de fusion), git push origin vX.Y.Z
#      -> déclenche .github/workflows/release.yml
#      message du tag : « NetSift vX.Y.Z », puis, avec --title, une ligne vide et le titre ;
#      release.yml en fait le nom de la release : « NetSift vX.Y.Z — titre » (sans titre :
#      « NetSift vX.Y.Z »), que l'application affiche dans son bandeau de mise à jour
#   5. affiche les URL (Actions, release) et la commande de suivi
#
#   --title T  titre de la release (une ligne, 80 caractères au plus, sans caractère de contrôle
#              ni de mise en forme bidirectionnelle ; espaces de début et de fin retirés)
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
# Caractères d'un titre de release au plus (le nom « NetSift vX.Y.Z — titre » reste sous les
# 120 caractères gardés par l'application, netsift-api/src/updates/release.rs).
TITLE_MAX=80
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

# release_title_error TITRE : raison du refus de TITRE comme titre de release, rien s'il convient
# (une ligne d'UTF-8 valide, TITLE_MAX caractères au plus, sans caractère de contrôle, C0, DEL ou
# C1, ni de mise en forme bidirectionnelle U+200E-U+200F, U+202A-U+202E, U+2066-U+2069).
release_title_error() {
  local title="$1" bad chars
  bad=$'[\x01-\x1f\x7f]|\xc2[\x80-\x9f]|\xe2\x80[\x8e\x8f\xaa-\xae]|\xe2\x81[\xa6-\xa9]'
  if [[ -z "$title" ]]; then
    echo "titre vide"
  elif [[ "$title" =~ $bad ]]; then
    echo "le titre doit tenir sur une ligne, sans caractère de contrôle ni de mise en forme bidirectionnelle"
  elif ! printf '%s' "$title" | iconv -f UTF-8 -t UTF-8 >/dev/null 2>&1; then
    echo "le titre n'est pas de l'UTF-8 valide"
  else
    # Caractères UTF-8 : les octets qui ne sont pas des octets de continuation (10xxxxxx).
    chars="$(printf '%s' "$title" | tr -d '\200-\277' | wc -c)"
    if ((chars > TITLE_MAX)); then
      echo "titre trop long ($((chars)) caractères, $TITLE_MAX au plus)"
    fi
  fi
}

# trim TEXTE : TEXTE sans les espaces de début et de fin.
trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  printf '%s\n' "${s%"${s##*[![:space:]]}"}"
}

# shell_quote TEXTE : TEXTE entre apostrophes, à recopier tel quel dans un shell.
shell_quote() {
  local q="'\''"
  printf "'%s'\n" "${1//\'/$q}"
}

# tag_command ROOT TAG REF [TITRE] : commande (à afficher) qui crée le tag annoté TAG sur REF,
# avec le message qu'écrit ce script. --cleanup=whitespace : un titre qui commence par « # »
# n'est pas pris pour un commentaire.
tag_command() {
  local cmd="git -C $1 tag -a --cleanup=whitespace $2 -m \"NetSift $2\""
  [[ -n "${4:-}" ]] && cmd+=" -m $(shell_quote "$4")"
  printf '%s\n' "$cmd $3"
}

# release_name ROOT TAG : nom de la release GitHub de TAG (release.yml, scripts/ci/release-name.sh) :
# « NetSift TAG — titre », le titre étant la première ligne non vide du corps du message du tag
# annoté (après « NetSift TAG » et une ligne vide), ou « NetSift TAG » sans titre. Un tag léger
# n'a pas de titre (le message serait celui du commit). Un titre invalide est ignoré, avec un
# avertissement sur la sortie d'erreur. Échec si TAG n'existe pas.
release_name() {
  local root="$1" tag="$2" type title="" err
  type="$(git -C "$root" cat-file -t "refs/tags/$tag" 2>/dev/null)" || return 1
  if [[ "$type" == tag ]]; then
    title="$(git -C "$root" for-each-ref --format='%(contents:body)' "refs/tags/$tag" \
      | awk 'NF { print; exit }')"
    title="$(trim "$title")"
  else
    echo "$tag est un tag léger : release sans titre" >&2
  fi
  if [[ -n "$title" ]]; then
    err="$(release_title_error "$title")"
    if [[ -n "$err" ]]; then
      echo "titre du tag $tag ignoré : $err" >&2
      title=""
    fi
  fi
  printf '%s\n' "NetSift $tag${title:+ — $title}"
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

# remote_tag_state ROOT TAG : « present », « absent » ou « error » (git ls-remote sur origin).
remote_tag_state() {
  local rc=0
  git -C "$1" ls-remote --exit-code --tags origin "refs/tags/$2" >/dev/null 2>&1 || rc=$?
  case "$rc" in
    0) echo present ;;
    2) echo absent ;;
    *) echo error ;;
  esac
}

# release_merged ROOT VERSION : commit de main qui contient déjà la release VERSION (fusion
# « merge(chore/release-VERSION): intégration », à défaut le commit « chore(release): vVERSION »),
# vide sinon.
release_merged() {
  local root="$1" version="$2" found
  found="$(git -C "$root" log main --first-parent --format='%H %s' \
    | awk -v s="merge(chore/release-$version): intégration" 'substr($0, index($0, " ") + 1) == s { print $1; exit }')"
  if [[ -z "$found" ]]; then
    found="$(git -C "$root" log main --format='%H %s' \
      | awk -v s="chore(release): v$version" 'substr($0, index($0, " ") + 1) == s { print $1; exit }')"
  fi
  echo "$found"
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
  local version="" dry_run=0 err
  # Globale (pas `local`) : lue par le piège EXIT.
  title=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dry-run) dry_run=1 ;;
      --title)
        [[ $# -ge 2 ]] || { usage >&2; exit 2; }
        title="$(trim "$2")"
        err="$(release_title_error "$title")"
        [[ -z "$err" ]] || die "--title : $err"
        shift ;;
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

  case "$(remote_tag_state "$root" "$tag")" in
    present) die "le tag $tag existe déjà sur origin : $tag est publiée (suivi : scripts/release-status.sh $tag)" ;;
    absent) ;;
    *) die "impossible d'interroger les tags d'origin (git ls-remote)" ;;
  esac
  git -C "$root" rev-parse -q --verify "refs/tags/$tag" >/dev/null \
    && die "le tag $tag existe en local mais pas sur origin. Pour terminer :"$'\n'"  git -C $root push origin $tag"$'\n'"  scripts/release-status.sh $tag --wait"
  # Relance après un échec partiel (fusion faite, tag non créé) : jamais de seconde fusion.
  local merged
  merged="$(release_merged "$root" "$version")"
  [[ -z "$merged" ]] \
    || die "main contient déjà la release $tag (commit ${merged:0:12}) ; ne pas la fusionner une seconde fois. Il ne manque que le tag :"$'\n'"  $(tag_command "$root" "$tag" "$merged" "$title") && git -C $root push origin $tag"$'\n'"  scripts/release-status.sh $tag --wait"
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
    if [[ -n "$title" ]]; then
      echo "      titre : $title"
    else
      echo "      sans titre (option --title)"
    fi
    echo "      nom de la release : NetSift $tag${title:+ — $title}"
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
          echo "  $(tag_command "$root" "$tag" main "$title") && git -C $root push origin $tag" >&2
        fi ;;
      tag)
        if git -C "$root" rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
          echo "release: le tag $tag existe en local, pas sur origin. Pour terminer :" >&2
          echo "  git -C $root push origin $tag" >&2
        else
          echo "release: main est fusionné, tag non créé. Pour terminer :" >&2
          echo "  $(tag_command "$root" "$tag" main "$title") && git -C $root push origin $tag" >&2
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
  # Second garde-fou contre une release vide (déjà fusionnée) : rien à committer.
  [[ -n "$(git -C "$wt" status --porcelain)" ]] \
    || die "aucun changement (CHANGELOG.md identique) : $tag semble déjà fusionnée sur main. Créer et pousser le tag (COMMIT = la fusion de la release sur main) :"$'\n'"  $(tag_command "$root" "$tag" COMMIT "$title") && git -C $root push origin $tag"$'\n'"  scripts/release-status.sh $tag --wait"

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
  local -a message=(-m "NetSift $tag")
  [[ -n "$title" ]] && message+=(-m "$title")
  git -C "$root" tag -a --cleanup=whitespace "$tag" "${message[@]}" main

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
