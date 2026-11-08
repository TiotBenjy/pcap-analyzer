#!/usr/bin/env bash
# Sourcé par scripts/ct/shots.sh DANS le conteneur : prépare le WebKit de Playwright pour le test
# de fumée desktop (ui/tests/desktop, projet `desktop-webkit`), WebKit étant le moteur de la
# webview Linux (WebKitGTK).
#
# L'image ne contient que Chromium et l'utilisateur du conteneur n'est pas root : le navigateur et
# les quelques bibliothèques système qui lui manquent sur Ubuntu 22.04 sont téléchargés une fois
# dans le volume de cache (`apt-get download` + `dpkg -x`, sans installation), puis réutilisés.
# Exporte NETSIFT_WEBKIT_EXECUTABLE, lu par ui/playwright.config.ts.
# En CI (runner GitHub, sans /cache), `playwright install --with-deps chromium webkit` installe
# WebKit à l'emplacement par défaut et ce script ne fait rien.

netsift_webkit_setup() {
  local root browsers deps location exe
  # Sans cela, WebKit (mesa) écrit son cache de shaders dans $HOME/.cache, soit le worktree.
  export MESA_SHADER_CACHE_DISABLE=true
  [ -d /cache ] || [ -n "${NETSIFT_WEBKIT_CACHE:-}" ] || return 0
  root="${NETSIFT_WEBKIT_CACHE:-/cache/webkit}"
  browsers="$root/pw-browsers"
  deps="$root/deps"
  # Révision attendue par la version de Playwright de ui/package-lock.json.
  location="$(PLAYWRIGHT_BROWSERS_PATH="$browsers" npx playwright install --dry-run webkit \
    | awk '/Install location/ && /webkit-/ { print $3; exit }')"
  [ -n "$location" ] || { echo "Révision WebKit de Playwright introuvable." >&2; return 1; }
  exe="$location/pw_run.sh"

  if [ ! -x "$exe" ]; then
    echo ">> WebKit de Playwright -> $location…"
    # La validation des dépendances hôte échoue (pas root) : les bibliothèques viennent de $deps.
    PLAYWRIGHT_BROWSERS_PATH="$browsers" PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS=1 \
      npx playwright install webkit >/dev/null
  fi

  # Bibliothèques absentes de l'image (vérifié avec ldd sur minibrowser-wpe, Ubuntu 22.04).
  local pkgs=(libavif13 libaom3 libdav1d5 libgav1-0 libyuv0 libabsl20210324
    libevent-2.1-7 libgstreamer-plugins-bad1.0-0 libva2 libva-drm2)
  if [ ! -f "$deps/.complete" ]; then
    echo ">> Bibliothèques système de WebKit -> $deps…"
    local apt="$root/apt" opts
    mkdir -p "$apt/lists/partial" "$apt/cache/archives/partial" "$deps/debs"
    opts=(-o "Dir::State::Lists=$apt/lists" -o "Dir::Cache=$apt/cache" -o Debug::NoLocking=1)
    # Le hook de nettoyage apt de l'image vise /var/cache/apt (non inscriptible) : bruit ignoré.
    apt-get "${opts[@]}" -qq update 2>/dev/null
    local pkg deb
    for pkg in "${pkgs[@]}"; do
      compgen -G "$deps/debs/${pkg}_*.deb" >/dev/null && continue
      (cd "$deps/debs" && apt-get "${opts[@]}" -qq download "$pkg") \
        || { echo "Téléchargement de $pkg impossible." >&2; return 1; }
    done
    for deb in "$deps"/debs/*.deb; do dpkg -x "$deb" "$deps/root"; done
    local so
    for so in libavif.so.13 libevent-2.1.so.7 libgstcodecparsers-1.0.so.0; do
      [ -e "$deps/root/usr/lib/x86_64-linux-gnu/$so" ] || { echo "$so absent après extraction." >&2; return 1; }
    done
    touch "$deps/.complete"
  fi
  # Le lanceur MiniBrowser impose LD_LIBRARY_PATH=<wpe>/lib:<wpe>/sys/lib : les bibliothèques
  # extraites y sont liées plutôt que passées par l'environnement.
  local lib
  for lib in "$deps"/root/usr/lib/x86_64-linux-gnu/*.so*; do
    ln -sfn "$lib" "$location/minibrowser-wpe/sys/lib/$(basename "$lib")"
  done

  export NETSIFT_WEBKIT_EXECUTABLE="$exe"
}

netsift_webkit_setup
