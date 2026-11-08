#!/usr/bin/env bash
# Suivi d'une release publiée par .github/workflows/release.yml, via l'API publique GitHub
# (curl + jq, sans jeton : le dépôt est public ; GITHUB_TOKEN est utilisé s'il est défini).
#
#   scripts/release-status.sh vX.Y.Z [--wait]
#
# Affiche l'état du run release.yml du tag et de chacun de ses jobs, l'état de la release
# (brouillon, publiée, prerelease) et ses fichiers. Code de sortie non nul si le run n'a pas réussi,
# si la release n'est pas publiée ou si un fichier attendu manque (.AppImage, .deb, .rpm, .exe,
# .msi sauf prerelease, .dmg, SHA256SUMS.txt).
# --wait : interroge toutes les 60 s jusqu'à la fin du run (90 min max).
# Sans jeton, l'API limite à 60 requêtes par heure : pendant l'attente, une seule requête par minute.
#
# Variable : NETSIFT_GITHUB_REPO=owner/repo (sinon déduit du remote origin).
set -euo pipefail
export LC_ALL=C

POLL_S=60
MAX_WAIT_S=$((90 * 60))
EXPECTED_EXT=(.AppImage .deb .rpm .exe .msi .dmg)
EXPECTED_FILES=(SHA256SUMS.txt)

die() { echo "release-status: $*" >&2; exit 2; }
usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"; }

tag="" wait=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --wait) wait=1 ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; exit 2 ;;
    *) [[ -z "$tag" ]] || { usage >&2; exit 2; }; tag="$1" ;;
  esac
  shift
done
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]] || { usage >&2; exit 2; }
# Prerelease (suffixe SemVer) : pas de .msi, WiX n'accepte que des versions numériques.
[[ "$tag" == *-* ]] && EXPECTED_EXT=(.AppImage .deb .rpm .exe .dmg)
command -v curl >/dev/null || die "curl est requis"
command -v jq >/dev/null || die "jq est requis"

repo="${NETSIFT_GITHUB_REPO:-}"
if [[ -z "$repo" ]]; then
  url="$(git -C "$(dirname "${BASH_SOURCE[0]}")" remote get-url origin 2>/dev/null || true)"
  if [[ "$url" =~ ^(git@github\.com:|ssh://git@github\.com/|https://github\.com/)([^/]+)/([^/]+)$ ]]; then
    repo="${BASH_REMATCH[2]}/${BASH_REMATCH[3]%.git}"
  fi
fi
repo="${repo:-TiotBenjy/pcap-analyzer}"
API="https://api.github.com/repos/$repo"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
auth=()
[[ -n "${GITHUB_TOKEN:-}" ]] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")

# api <chemin> : remplit API_STATUS (code HTTP, 000 si réseau), API_RESET (epoch) et $TMP/body.
api() {
  API_STATUS=000 API_RESET=0
  if curl -sS -L --max-time 30 -o "$TMP/body" -D "$TMP/headers" "${auth[@]}" \
       -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" \
       "$API$1"; then
    API_STATUS="$(awk 'toupper($1) ~ /^HTTP\// { s = $2 } END { print s }' "$TMP/headers")"
    API_RESET="$(tr -d '\r' < "$TMP/headers" | awk -F': ' 'tolower($1) == "x-ratelimit-reset" { r = $2 } END { print r + 0 }')"
  fi
}
rate_limited() { [[ "$API_STATUS" == 403 || "$API_STATUS" == 429 ]]; }

# Dernier run release.yml déclenché par le push du tag -> $TMP/run (JSON, vide si aucun).
fetch_run() {
  api "/actions/workflows/release.yml/runs?event=push&branch=$tag&per_page=1"
  if [[ "$API_STATUS" == 200 ]]; then
    jq -c '.workflow_runs[0] // empty' "$TMP/body" > "$TMP/run"
  else
    : > "$TMP/run"
  fi
}
run_field() { jq -r ".$1 // \"\"" "$TMP/run"; }

if [[ "$wait" == "1" ]]; then
  deadline=$(($(date +%s) + MAX_WAIT_S))
  while :; do
    fetch_run
    now=$(date +%s)
    if [[ -s "$TMP/run" && "$(run_field status)" == "completed" ]]; then
      break
    fi
    if ((now >= deadline)); then
      echo "release-status: délai de 90 min dépassé." >&2
      break
    fi
    sleep_s=$POLL_S
    if rate_limited && ((API_RESET > now)); then
      sleep_s=$((API_RESET - now + 5))
      echo "$(date +%H:%M:%S) limite de l'API atteinte, reprise dans ${sleep_s} s"
    elif [[ -s "$TMP/run" ]]; then
      echo "$(date +%H:%M:%S) run $(run_field status) : $(run_field html_url)"
    else
      echo "$(date +%H:%M:%S) aucun run release.yml pour $tag (HTTP $API_STATUS), nouvel essai"
    fi
    ((now + sleep_s <= deadline)) || sleep_s=$((deadline - now))
    sleep "$sleep_s"
  done
else
  fetch_run
fi

status=0

# --- Run et jobs ----------------------------------------------------------------------
echo "Dépôt   : $repo"
if [[ -s "$TMP/run" ]]; then
  run_status="$(run_field status)" run_conclusion="$(run_field conclusion)"
  echo "Run     : ${run_status}${run_conclusion:+ / $run_conclusion}  $(run_field html_url)"
  api "/actions/runs/$(run_field id)/jobs?per_page=100"
  if [[ "$API_STATUS" == 200 ]]; then
    jq -r '.jobs[] | "  job   : \(.name) : \(.status)\(if .conclusion then " / " + .conclusion else "" end)"' "$TMP/body"
  else
    echo "  jobs  : indisponibles (HTTP $API_STATUS)"
  fi
  [[ "$run_status" == "completed" && "$run_conclusion" == "success" ]] || status=1
else
  echo "Run     : aucun run release.yml pour $tag (HTTP $API_STATUS)"
  status=1
fi

# --- Release et fichiers -------------------------------------------------------------
api "/releases/tags/$tag"
if [[ "$API_STATUS" == 200 ]]; then
  jq -r '"Release : \(if .draft then "brouillon" else "publiée" end)\(if .prerelease then ", prerelease" else "" end)  \(.html_url)"' "$TMP/body"
  jq -e '.draft | not' "$TMP/body" >/dev/null || status=1
  jq -r '.assets[] | "  fichier : \(.name) (\(.size) octets)"' "$TMP/body"
  mapfile -t assets < <(jq -r '.assets[].name' "$TMP/body")
else
  echo "Release : introuvable (HTTP $API_STATUS ; un brouillon n'est pas visible sans jeton)"
  assets=()
  status=1
fi

missing=()
for ext in "${EXPECTED_EXT[@]}"; do
  found=0
  for a in "${assets[@]}"; do [[ "$a" == *"$ext" ]] && { found=1; break; }; done
  [[ "$found" == 1 ]] || missing+=("*$ext")
done
for f in "${EXPECTED_FILES[@]}"; do
  found=0
  for a in "${assets[@]}"; do [[ "$a" == "$f" ]] && { found=1; break; }; done
  [[ "$found" == 1 ]] || missing+=("$f")
done
if [[ ${#missing[@]} -gt 0 ]]; then
  echo "Manquant : ${missing[*]}"
  status=1
else
  echo "Fichiers : complets"
fi
exit "$status"
