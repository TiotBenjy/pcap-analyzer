#!/usr/bin/env bash
# NetSift — pilote de la toolchain conteneurisée (Docker ou Podman).
# Aucune toolchain n'est requise sur l'hôte : tout s'exécute dans l'image docker/Dockerfile.
#
#   ./x.sh image                 construit (ou reconstruit) l'image
#   ./x.sh check                 fmt + clippy + tests Rust + lint/tests UI (gate CI local)
#   ./x.sh test [args]           cargo nextest run [args]
#   ./x.sh cargo <args>          cargo arbitraire
#   ./x.sh clippy | fmt | fmt-check | deny
#   ./x.sh npm <args>            npm dans ui/
#   ./x.sh ui <args>             raccourci : npm run <args> dans ui/
#   ./x.sh dev                   backend + Vite (http://localhost:${NETSIFT_UI_PORT:-5173})
#   ./x.sh shots [vue]           captures Playwright multi-largeurs (assertions UI)
#   ./x.sh desktop               build Tauri Linux (AppImage + .deb) -> dist/
#   ./x.sh desktop-win           build Windows via cargo-xwin (expérimental) -> dist/
#   ./x.sh geoip                 télécharge la base GeoIP (DB-IP Lite) dans .data/geoip/
#   ./x.sh cliff [args]          git-cliff épinglé (CHANGELOG, notes de release ; cliff.toml)
#   ./x.sh fuzz [cible] [durée]  cargo-fuzz (nightly dans le conteneur)
#   ./x.sh shell                 shell interactif dans le conteneur
#   ./x.sh run <cmd...>          commande brute dans le conteneur
#   ./x.sh clean [--dry-run] [--all [--yes]] [--images]
#                                nettoie le cache de build : targets orphelins (défaut), tous les
#                                targets sauf tools/ (--all, confirmation ou --yes), images sans
#                                tag (--images)
#   ./x.sh -C <dir> <sous-cmd>   exécuter la sous-commande avec <dir> comme racine (worktree)
#
# Variables : ENGINE=docker|podman (sinon auto), NETSIFT_UI_PORT, NETSIFT_API_PORT,
#             NO_SCCACHE=1 (désactive sccache), REBUILD=1 (force image).
set -euo pipefail

# --- Résolution de la racine (support de -C <dir>) ---------------------------------
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="$ROOT"
if [[ "${1:-}" == "-C" ]]; then
  [[ -n "${2:-}" ]] || { echo "x.sh: -C requiert un chemin" >&2; exit 2; }
  WORKDIR="$(cd "$2" && pwd)"
  shift 2
fi
CMD="${1:-help}"; shift || true

IMAGE="netsift-dev:latest"
CACHE_VOL="netsift-cache"

# --- Détection du moteur de conteneur ----------------------------------------------
detect_engine() {
  if [[ -n "${ENGINE:-}" ]]; then echo "$ENGINE"; return; fi
  if command -v podman >/dev/null 2>&1; then echo podman; return; fi
  if command -v docker >/dev/null 2>&1; then echo docker; return; fi
  echo "Erreur : ni podman ni docker n'est installé. NetSift n'a besoin que de l'un des deux." >&2
  exit 1
}
# Détection paresseuse : `help` et `slug` n'exigent pas de moteur de conteneur, ni `clean` en
# mode local (NETSIFT_CACHE_ROOT, tests : le « volume » est un simple répertoire de l'hôte).
case "$CMD" in
  help|-h|--help|slug) ;;
  clean) [[ -n "${NETSIFT_CACHE_ROOT:-}" ]] || ENGINE="$(detect_engine)" ;;
  *) ENGINE="$(detect_engine)" ;;
esac

# Slug, sélection des targets orphelins : partagés avec scripts/wt.sh et testés par
# scripts/tests/cache.sh.
# shellcheck source=scripts/lib/cache.sh
source "$ROOT/scripts/lib/cache.sh"

# Podman : mapping d'UID transparent (--userns=keep-id). Docker : --user <uid:gid>.
userargs() {
  if [[ "$ENGINE" == "podman" ]]; then
    echo "--userns=keep-id"
  else
    echo "--user $(id -u):$(id -g)"
  fi
}

# Un slug stable par worktree pour isoler le répertoire target dans le cache partagé.
slug() { cache_slug "$WORKDIR"; }

# sccache évince lui-même ses entrées les plus anciennes au-delà de ce plafond (défaut 10 GiB) ;
# 5 GiB suffisent aux dépendances du workspace et laissent de la place aux targets.
SCCACHE_SIZE="5G"

# Marqueur d'origine écrit dans le target avant chaque commande (CACHE_ORIGIN_MARK, défini et
# testé dans scripts/lib/cache.sh) : chemin hôte du worktree et date de dernière utilisation.
ORIGIN_MARK="$CACHE_ORIGIN_MARK"

# CI n'est transmis que s'il est défini : certains outils (tauri-cli) refusent CI="".
CI_ENV=(); [[ -n "${CI:-}" ]] && CI_ENV=(-e "CI=${CI}")

ensure_cache_vol() { "$ENGINE" volume inspect "$CACHE_VOL" >/dev/null 2>&1 || "$ENGINE" volume create "$CACHE_VOL" >/dev/null; }

image_exists() { "$ENGINE" image inspect "$IMAGE" >/dev/null 2>&1; }

build_image() {
  echo ">> Construction de l'image $IMAGE avec $ENGINE (première fois : ~10 min)…"
  "$ENGINE" build -t "$IMAGE" -f "$ROOT/docker/Dockerfile" "$ROOT"
}

ensure_image() { if [[ "${REBUILD:-0}" == "1" ]] || ! image_exists; then build_image; fi; }

# --- Exécution dans le conteneur ---------------------------------------------------
# run_in <extra docker args...> -- <commande dans le conteneur>
run_in() {
  ensure_image; ensure_cache_vol
  local extra=(); while [[ "${1:-}" != "--" ]]; do extra+=("$1"); shift; done; shift
  local scc="sccache"; [[ "${NO_SCCACHE:-0}" == "1" ]] && scc=""
  # -i : stdin toujours transmis (permet `./x.sh run bash -s < script`).
  # -t : uniquement avec un vrai terminal, sinon le pty du conteneur masque le stdin redirigé
  #      et les sorties de scripts/agents sont polluées de séquences de contrôle.
  local tty=(-i); [[ -t 0 && -t 1 ]] && tty=(-it)
  # shellcheck disable=SC2046
  "$ENGINE" run --rm "${tty[@]}" \
    $(userargs) \
    -v "$WORKDIR":/work:z \
    -v "$CACHE_VOL":/cache:z \
    -e CARGO_TARGET_DIR="/cache/target/$(slug)" \
    -e CARGO_HOME=/cache/cargo \
    -e SCCACHE_DIR=/cache/sccache \
    -e SCCACHE_CACHE_SIZE="$SCCACHE_SIZE" \
    -e RUSTC_WRAPPER="$scc" \
    -e npm_config_cache=/cache/npm \
    -e PLAYWRIGHT_BROWSERS_PATH=/usr/local/pw-browsers \
    -e HOME=/tmp/home \
    -e NETSIFT_ORIGIN="$WORKDIR" \
    "${CI_ENV[@]}" \
    -w /work \
    "${extra[@]}" \
    "$IMAGE" bash -lc "$ORIGIN_MARK$*"
}

# Variante non-TTY (CI, scripts).
run_in_q() { local a=(); while [[ "${1:-}" != "--" ]]; do a+=("$1"); shift; done; shift
  ensure_image; ensure_cache_vol; local scc="sccache"; [[ "${NO_SCCACHE:-0}" == "1" ]] && scc=""
  # shellcheck disable=SC2046
  "$ENGINE" run --rm $(userargs) \
    -v "$WORKDIR":/work:z -v "$CACHE_VOL":/cache:z \
    -e CARGO_TARGET_DIR="/cache/target/$(slug)" -e CARGO_HOME=/cache/cargo \
    -e SCCACHE_DIR=/cache/sccache -e SCCACHE_CACHE_SIZE="$SCCACHE_SIZE" -e RUSTC_WRAPPER="$scc" \
    -e npm_config_cache=/cache/npm -e PLAYWRIGHT_BROWSERS_PATH=/usr/local/pw-browsers \
    -e HOME=/tmp/home -e NETSIFT_ORIGIN="$WORKDIR" "${CI_ENV[@]}" \
    -w /work "${a[@]}" "$IMAGE" bash -lc "$ORIGIN_MARK$*"
}

# Worktree : son `.git` est un fichier qui pointe vers le dépôt principal, hors du montage /work.
# On monte le répertoire git commun, en lecture seule, au même chemin absolu pour que git (et
# git-cliff) puissent lire l'historique.
git_mount_args() {
  [[ -f "$WORKDIR/.git" ]] || return 0
  local common; common="$(git -C "$WORKDIR" rev-parse --path-format=absolute --git-common-dir)"
  printf '%s\n' -v "$common:$common:ro,z"
}

# Ports pour dev : dérivés du slug si non fixés, pour que deux worktrees ne se marchent pas dessus.
ui_port()  { echo "${NETSIFT_UI_PORT:-$(( 5173 + (16#$(slug | cut -c1-2) % 40) ))}"; }
api_port() { echo "${NETSIFT_API_PORT:-$(( 7878 + (16#$(slug | cut -c1-2) % 40) ))}"; }

# --- Hygiène du cache de build (./x.sh clean) ---------------------------------------
# Les décisions sont prises sur l'hôte (seul à savoir si un chemin existe encore) ; listage,
# tailles et suppressions passent par un conteneur qui ne monte que le volume (les fichiers
# appartiennent à l'UID mappé du conteneur). Logique et tests : scripts/lib/cache.sh,
# scripts/ct/cache.sh, scripts/tests/cache.sh.

# Délai de grâce des targets sans marqueur .origin (écrits par un x.sh antérieur, ou clone jetable
# en cours d'utilisation) : jamais supprimés s'ils ont servi dans les 2 dernières heures.
CACHE_GRACE_S=7200

cache_ct() { # <commande de scripts/ct/cache.sh> [args...]
  if [[ -n "${NETSIFT_CACHE_ROOT:-}" ]]; then
    CACHE_ROOT="$NETSIFT_CACHE_ROOT" bash "$ROOT/scripts/ct/cache.sh" "$@"
    return
  fi
  # --entrypoint bash : ni sccache, ni création de /cache/target/root par entrypoint.sh.
  # shellcheck disable=SC2046
  "$ENGINE" run --rm -i $(userargs) --entrypoint bash -v "$CACHE_VOL":/cache:z "$IMAGE" \
    -s -- "$@" < "$ROOT/scripts/ct/cache.sh"
}

reason_label() {
  case "$1" in
    origin-gone) echo "chemin disparu" ;;
    unknown) echo "sans marqueur, aucun worktree" ;;
    all) echo "--all" ;;
    worktree-removed) echo "worktree supprimé" ;;
    origin-exists) echo "actif" ;;
    live-worktree) echo "worktree actif, sans marqueur" ;;
    recent) echo "récent, sans marqueur" ;;
    in-use) echo "build en cours" ;;
    unmanaged) echo "non géré" ;;
    *) echo "$1" ;;
  esac
}

# Champ <n> (1 = nom) de la ligne de listage du target <name>.
listing_field() { awk -F'\t' -v n="$2" -v f="$3" '$1 == n { print $f; exit }' <<<"$1"; }

cmd_clean() {
  local dry=0 all=0 images=0 auto=0 yes=0 wt=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -n|--dry-run) dry=1 ;;
      --all) all=1 ;;
      -y|--yes) yes=1 ;;
      --images) images=1 ;;
      --auto) auto=1 ;;                                  # wt.sh : silencieux, sans rapport
      --worktree) wt="${2:-}"; [[ -n "$wt" ]] || { echo "x.sh clean: --worktree <chemin>" >&2; return 2; }
                  shift ;;                               # wt.sh rm : target d'un worktree supprimé
      *) echo "x.sh clean: option inconnue : $1 (--dry-run, --all [--yes], --images)" >&2; return 2 ;;
    esac
    shift
  done
  # --all vide aussi les targets des worktrees actifs : confirmation explicite.
  if [[ "$all" == 1 && "$dry" == 0 && "$yes" == 0 && ! -t 0 ]]; then
    echo "x.sh clean: --all supprime aussi les targets des worktrees actifs ; sans terminal, ajouter --yes" >&2
    return 2
  fi

  # Aucun build d'image ni création de volume pour nettoyer.
  if [[ -z "${NETSIFT_CACHE_ROOT:-}" ]]; then
    if ! "$ENGINE" volume inspect "$CACHE_VOL" >/dev/null 2>&1; then
      [[ "$auto" == 1 || -n "$wt" ]] || echo ">> Volume $CACHE_VOL absent : rien à nettoyer."
      return 0
    fi
    if ! image_exists; then
      [[ "$auto" == 1 || -n "$wt" ]] && return 0
      echo "x.sh clean: image $IMAGE absente (./x.sh image), ou supprimer le volume : $ENGINE volume rm $CACHE_VOL" >&2
      return 1
    fi
  fi

  # Listage ; hors --dry-run, purge au passage les restes de suppressions interrompues (.trash-*).
  local raw listing trash rc=0
  if [[ "$dry" == 1 ]]; then raw="$(cache_ct list)" || rc=$?; else raw="$(cache_ct list --purge)" || rc=$?; fi
  if [[ "$rc" -ne 0 ]]; then echo "x.sh clean: échec du listage du cache (code $rc)" >&2; return 1; fi
  trash="$(grep '^#trash' <<<"$raw" || true)"
  listing="$(grep -v '^#trash' <<<"$raw" || true)"

  local decisions
  if [[ -n "$wt" ]]; then
    decisions="$(cache_select_worktree "$wt" <<<"$listing")"
  else
    local live mode=orphans
    [[ "$all" == 1 ]] && mode=all
    live="$(cache_live_slugs "$ROOT"; cache_slug "$ROOT"; cache_slug "$WORKDIR")"
    decisions="$(cache_select "$mode" "$(date +%s)" "$CACHE_GRACE_S" "$live" <<<"$listing")"
  fi

  local -a names=() args=()
  local verdict name reason size origin state freed=0 failed=0
  while IFS=$'\t' read -r verdict name reason; do
    [[ "$verdict" == delete ]] || continue
    names+=("$name")
    args+=("$name@$(listing_field "$listing" "$name" 3)")
  done <<<"$decisions"

  # Restes de suppressions interrompues : comptés dans l'espace libéré (ou libérable).
  while IFS=$'\t' read -r _ name size state; do
    [[ -n "$name" ]] || continue
    case "$state" in
      purged) freed=$((freed + ${size:-0}))
              printf '>> Cache : reste de suppression %s purgé (%s)\n' "$name" "$(cache_human "${size:-0}")" ;;
      pending) freed=$((freed + ${size:-0}))
               printf '>> Reste de suppression à purger : %s (%s)\n' "$name" "$(cache_human "${size:-0}")" ;;
      *) failed=1; echo "x.sh clean: impossible de purger $name" >&2 ;;
    esac
  done <<<"$trash"

  if [[ ${#names[@]} -gt 0 && "$all" == 1 && "$dry" == 0 && "$yes" == 0 ]]; then
    local answer=""
    printf '>> --all : %d target(s) à supprimer, worktrees actifs compris (%s). Continuer ? [o/N] ' \
      "${#names[@]}" "${names[*]}"
    read -r answer || true
    if [[ "$answer" != [oOyY]* ]]; then echo ">> Abandon, rien n'est supprimé."; return 1; fi
  fi

  if [[ ${#names[@]} -gt 0 ]]; then
    local out
    if [[ "$dry" == 1 ]]; then
      out="$(cache_ct sizes "${names[@]}")" || { echo "x.sh clean: échec du calcul des tailles" >&2; return 1; }
      echo ">> Targets à supprimer (--dry-run, rien n'est supprimé) :"
      while IFS=$'\t' read -r name size; do
        [[ -n "$name" ]] || continue
        freed=$((freed + ${size:-0}))
        reason="$(awk -F'\t' -v n="$name" '$2 == n { print $3; exit }' <<<"$decisions")"
        origin="$(listing_field "$listing" "$name" 2)"
        printf '   %s  %10s  %-30s %s %s\n' "$name" "$(cache_human "${size:-0}")" "$(reason_label "$reason")" \
          "${origin:--}" "$(listing_field "$listing" "$name" 3)"
      done <<<"$out"
    else
      rc=0
      out="$(cache_ct rm "${args[@]}")" || rc=$?
      while IFS=$'\t' read -r verdict name size; do
        case "$verdict" in
          deleted)
            freed=$((freed + ${size:-0}))
            origin="$(listing_field "$listing" "$name" 2)"
            reason="$(awk -F'\t' -v n="$name" '$2 == n { print $3; exit }' <<<"$decisions")"
            printf '>> Cache : target %s supprimé (%s, %s%s)\n' "$name" "$(cache_human "${size:-0}")" \
              "$(reason_label "$reason")" "${origin:+ : $origin}" ;;
          failed)
            failed=1
            echo "x.sh clean: target $name renommé mais non supprimé (purgé au prochain clean)" >&2 ;;
          skipped)
            [[ "$auto" == 1 ]] || printf '>> Cache : target %s conservé (%s)\n' "$name" "$size" ;;
        esac
      done <<<"$out"
      if [[ "$rc" -ne 0 ]]; then
        echo "x.sh clean: le conteneur de suppression a échoué (code $rc), lot peut-être incomplet" >&2
        failed=1
      fi
    fi
  fi

  if [[ "$images" == 1 ]]; then
    [[ -n "${ENGINE:-}" ]] || { echo "x.sh clean: --images requiert docker ou podman" >&2; return 1; }
    if [[ "$dry" == 1 ]]; then
      echo ">> Images sans tag qui seraient supprimées ($ENGINE image prune -f) :"
      "$ENGINE" images --filter dangling=true
    else
      echo ">> Images sans tag ($ENGINE image prune -f ; jamais une image taguée ni utilisée) :"
      "$ENGINE" image prune -f
    fi
  fi

  if [[ "$auto" == 1 || -n "$wt" ]]; then return "$failed"; fi

  # Rapport : espace libéré et occupation du volume par catégorie.
  local usage key bytes total=0 label
  usage="$(cache_ct usage)" || { echo "x.sh clean: échec du calcul de l'occupation" >&2; return 1; }
  echo
  if [[ "$dry" == 1 ]]; then
    echo "Libérable : $(cache_human "$freed")"
  else
    echo "Libéré : $(cache_human "$freed")"
  fi
  echo "Occupation du volume $CACHE_VOL :"
  while IFS=$'\t' read -r key bytes; do
    case "$key" in
      fs-*|"") continue ;;
      target/*)
        name="${key#target/}"
        reason="$(awk -F'\t' -v n="$name" '$2 == n { print $1 ":" $3; exit }' <<<"$decisions")"
        case "$name:$reason" in
          tools:*) label="outils compilés (conservé)" ;;
          *:delete:*) origin="$(listing_field "$listing" "$name" 2)"
                      label="à supprimer : ${origin:-sans marqueur}" ;;
          *) origin="$(listing_field "$listing" "$name" 2)"
             label="$(reason_label "${reason#*:}")${origin:+ : $origin}" ;;
        esac ;;
      sccache) label="plafond $SCCACHE_SIZE, éviction automatique" ;;
      tools) label="git-cliff (conservé)" ;;
      *) label="" ;;
    esac
    total=$((total + ${bytes:-0}))
    printf '  %-20s %10s%s\n' "$key" "$(cache_human "${bytes:-0}")" "${label:+  $label}"
  done <<<"$usage"
  printf '  %-20s %10s\n' "total" "$(cache_human "$total")"
  local avail fsize
  avail="$(awk -F'\t' '$1 == "fs-avail" { print $2 }' <<<"$usage")"
  fsize="$(awk -F'\t' '$1 == "fs-size" { print $2 }' <<<"$usage")"
  [[ -n "$avail" ]] && echo "Libre sur le système de fichiers du volume : $(cache_human "$avail") / $(cache_human "$fsize")"
  return "$failed"
}

case "$CMD" in
  image)       REBUILD=1 build_image ;;
  shell)       run_in -- "${*:-bash}" ;;
  run)         run_in -- "$*" ;;

  cargo)       run_in -- "cargo $*" ;;
  test)        run_in -- "cargo nextest run $*" ;;
  clippy)      run_in -- "cargo clippy --workspace --all-targets --all-features -- -D warnings $*" ;;
  fmt)         run_in -- "cargo fmt --all $*" ;;
  fmt-check)   run_in -- "cargo fmt --all --check" ;;
  deny)        run_in -- "cargo deny check $*" ;;

  npm)         run_in -- "cd ui && npm $*" ;;
  ui)          run_in -- "cd ui && npm run $*" ;;

  check)
    # Gate identique à la CI. S'arrête à la première erreur.
    # shellcheck disable=SC2016 # script exécuté par bash dans le conteneur, pas développé ici
    run_in_q -- '
      set -e
      echo "== version =="      && bash scripts/check-version.sh >/dev/null && bash scripts/tests/check-version.sh \
        && bash scripts/tests/release.sh \
        && { [ ! -f scripts/tests/cache.sh ] || bash scripts/tests/cache.sh; }
      echo "== rustfmt =="      && cargo fmt --all --check
      echo "== clippy =="       && cargo clippy --workspace --all-targets --all-features -- -D warnings
      echo "== cargo-deny =="   && (cargo deny check || true)   # avertit sans bloquer au début du projet
      echo "== tests Rust =="   && cargo nextest run --workspace
      echo "== bindings TS =="  && cargo test -q -p netsift-api export_bindings >/dev/null \
        && { ! git rev-parse --git-dir >/dev/null 2>&1 `# worktree : .git hors du montage` \
             || git diff --quiet -- ui/src/api/types \
             || echo "ATTENTION : bindings TS regeneres, a committer (ui/src/api/types)"; }
      if [ -d ui ] && [ -f ui/package.json ]; then
        echo "== UI : install ==" && (cd ui && npm ci || npm install)
        echo "== UI : typecheck/lint ==" && (cd ui && npm run -s lint && npm run -s typecheck)
        echo "== UI : tests unitaires ==" && (cd ui && npm run -s test -- --run)
      fi
      echo "OK"
    ' ;;

  dev)
    up="$(ui_port)"; ap="$(api_port)"
    echo ">> UI  : http://localhost:${up}"
    echo ">> API : http://localhost:${ap}  (publiée sur loopback uniquement)"
    run_in -p "127.0.0.1:${up}:${up}" -p "127.0.0.1:${ap}:${ap}" \
      -e NETSIFT_UI_PORT="$up" -e NETSIFT_API_PORT="$ap" \
      -v "$ROOT/captures":/captures:ro,z \
      -- "bash scripts/ct/dev.sh" ;;

  shots)       run_in -- "bash scripts/ct/shots.sh $*" ;;
  desktop)     run_in -- "bash scripts/ct/desktop.sh linux" ;;
  desktop-win) run_in -- "bash scripts/ct/desktop.sh windows" ;;
  geoip)       run_in -- "bash scripts/ct/geoip.sh" ;;
  cliff)       mapfile -t gm < <(git_mount_args)
               run_in "${gm[@]}" -- "bash scripts/ct/cliff.sh $*" ;;
  fuzz)        run_in -- "bash scripts/ct/fuzz.sh $*" ;;
  clean)       cmd_clean "$@" ;;
  slug)        slug ;;

  help|*)
    awk 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}" ;;
esac
