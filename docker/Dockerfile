# Image de développement et de build pour NetSift.
# Ubuntu 22.04 : glibc 2.35, pour des bundles Linux (AppImage/.deb) à large compatibilité.
# Épingler les versions ici ET dans rust-toolchain.toml / ui/package.json.
FROM ubuntu:22.04

# Variables de BUILD : la toolchain s'installe à un emplacement stable dans l'image
# (/usr/local/cargo, dans le PATH). Les variables de RUNTIME (CARGO_HOME=/cache/cargo,
# SCCACHE_DIR, RUSTC_WRAPPER, CARGO_TARGET_DIR) sont injectées par x.sh / entrypoint.sh et
# ne doivent PAS être fixées ici : sinon cargo s'installerait hors du PATH et sccache serait
# invoqué avant d'exister.
ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/bin:$PATH \
    RUST_VERSION=1.99.1 \
    NODE_VERSION=22.14.0 \
    PLAYWRIGHT_VERSION=1.65.0

# --- Dépendances système : build Tauri (webkitgtk), outils, et bibliothèques Chromium/Playwright ---
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential pkg-config curl ca-certificates git file xz-utils unzip \
      cmake clang lld nasm python3 jq zip \
      libssl-dev \
      libwebkit2gtk-4.1-dev libsoup-3.0-dev \
      libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev patchelf \
      libjavascriptcoregtk-4.1-dev \
      # dépendances d'exécution Chromium (Playwright) :
      libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libdbus-1-3 \
      libxkbcommon0 libatspi2.0-0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
      libgbm1 libasound2 libpango-1.0-0 libcairo2 fonts-liberation libx11-6 libxcb1 \
      libxext6 libxi6 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# --- Rust (toolchain épinglée + cibles + composants) ---
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --profile minimal \
          --default-toolchain ${RUST_VERSION} \
          --component rustfmt --component clippy \
    && rustup target add x86_64-unknown-linux-gnu \
    && rustup target add x86_64-pc-windows-msvc \
    && rustc --version && cargo --version

# Outils cargo (binstall pour éviter de longues compilations). Versions épinglées vérifiées.
RUN curl -L --proto '=https' --tlsv1.2 -sSf \
      https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash \
    && cargo binstall -y \
        cargo-nextest@0.9.151 \
        sccache@0.19.0 \
        cargo-deny@0.20.2 \
        tauri-cli@2.12.4 \
    && rm -rf /usr/local/cargo/registry

# cargo-xwin : utile uniquement pour le build Windows local expérimental (./x.sh desktop-win).
# Best-effort : son indisponibilité ne doit pas faire échouer la construction de l'image.
RUN cargo binstall -y cargo-xwin || echo "cargo-xwin non installé (build Windows local indisponible ; la CI reste la référence)"

# --- Node (binaire officiel, pas de gestionnaire de version) ---
# On garde le npm fourni avec Node (10.9.x) : `npm install -g npm@latest` installerait npm 12,
# qui exige Node >= 22.22.2. Le npm fourni suffit pour npm ci / build. Pour prendre un npm plus
# récent, relever NODE_VERSION vers une 22.x >= 22.22.2 plutôt que de forcer npm@latest ici.
RUN curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
      | tar -xJ -C /usr/local --strip-components=1 \
    && node --version && npm --version

# Navigateur Playwright (Chromium) installé dans l'image, chemin stable partagé par l'UI.
ENV PLAYWRIGHT_BROWSERS_PATH=/usr/local/pw-browsers
RUN npx --yes playwright@${PLAYWRIGHT_VERSION} install chromium

# sccache a besoin d'un répertoire ; créé au premier run via le volume de cache.
WORKDIR /work
# L'UID/GID réel est passé par x.sh (--user) pour que les fichiers créés appartiennent à l'hôte.
# Un entrypoint minimal garantit des caches inscriptibles même avec un UID arbitraire.
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]
