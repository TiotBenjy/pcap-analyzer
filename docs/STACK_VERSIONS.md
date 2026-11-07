# Versions testées

Versions épinglées et **réellement testées ensemble** (install + typecheck strict + build de
production) le 2026-11-07. Utiliser celles-ci en phase 0 plutôt que « la dernière » au hasard ;
monter de version ensuite délibérément, en revérifiant `./x.sh check`.

## Toolchain (image Docker)

| Outil | Version | Notes |
|---|---|---|
| Rust | 1.99.1 | `rust-toolchain.toml` + `docker/Dockerfile` |
| Node | 22.14.0 | npm **fourni** 10.9.x conservé (ne pas faire `npm i -g npm@latest` : npm 12 exige Node ≥ 22.22.2) |
| Playwright | 1.65.0 | navigateur Chromium installé dans l'image |
| cargo-nextest | 0.9.151 | via cargo-binstall |
| sccache | 0.19.0 | |
| cargo-deny | 0.20.2 | |
| tauri-cli | 2.12.4 | |
| cargo-xwin | dernière (best-effort) | build Windows local expérimental uniquement |

## UI — combinaison validée (install + tsc --noEmit + vite build OK)

```
react            19.2.0
react-dom        19.2.0
vite              7.1.12
@vitejs/plugin-react 5.1.0
typescript        5.9.3
tailwindcss       4.1.16        # Tailwind 4 : config via @tailwindcss/vite + @theme dans le CSS
@tailwindcss/vite 4.1.16
echarts           6.0.0         # import modulaire + SVGRenderer
sigma             3.0.2
graphology        0.26.0
@tanstack/react-query   5.90.5
@tanstack/react-table   8.21.3
@tanstack/react-virtual 3.13.12
lucide-react      0.544.0
@types/react      19.2.0
@types/react-dom  19.2.0
```

Ajoutées en P0.3 (shell UI), épinglées exactement (`ui/.npmrc` : `save-exact=true`) et validées
par `./x.sh check` (lint + typecheck strict + tests) et `vite build` :

```
@tanstack/react-router       1.170.46   # routes code-based, historique hash (Vite, statique, Tauri)
i18next                      27.0.1
react-i18next                18.0.0
@fontsource-variable/inter   5.3.0
@fontsource/jetbrains-mono   5.3.0
vitest                       5.1.0      # pairs : vite ^6.4 || ^7 || ^8
jsdom                        29.1.1
@testing-library/react       16.3.3
@testing-library/user-event  14.6.8
@testing-library/jest-dom    7.0.1
@playwright/test             1.65.0     # = PLAYWRIGHT_VERSION du Dockerfile
eslint                       10.14.0    # config plate (eslint/config defineConfig)
@eslint/js                   10.0.1
typescript-eslint            8.72.1     # strict + stylistic, sans type-checking (rapide)
eslint-plugin-react-hooks    7.1.1      # configs.flat['recommended-latest']
eslint-plugin-react-refresh  0.5.7
globals                      17.14.0
@types/node                  22.20.5    # aligné sur Node 22
```

Restant à ajouter en phase 2/3 selon les specs (prendre une version compatible) :
`@tauri-apps/api` (2.x), `d3-chord` + `@types/d3-chord`, `flag-icons`, `world-atlas` (cartes).

## Faits constatés au test

- Tailwind 4 s'active par le plugin Vite `@tailwindcss/vite` + `@import "tailwindcss";` et `@theme`
  dans le CSS (plus de `tailwind.config.js` obligatoire). Les utilitaires issus de tokens (`text-accent`
  depuis `--color-accent`) sont bien générés.
- Le bundle initial echarts + sigma dépasse 500 Kio -> **code-splitting obligatoire** (import dynamique
  des vues et des graphes), conformément à `docs/UI_GUIDELINES.md`. Prévu dès le shell UI (P0.3).
- `echarts/core` + enregistrement explicite (`echarts.use([...])`) réduit le poids vs import global.

## Rust — à épingler lors de l'écriture du workspace (P0.2)

Versions relevées sur crates.io le 2026-11-07 (reprendre `./x.sh cargo add <crate>` qui prendra la
dernière compatible, puis figer dans les `Cargo.toml`) :
`tauri` 2.12, `tauri-build` 2.7, `tauri-plugin-dialog` 2.8, `tauri-plugin-opener` 2.7,
`pcap-file` 2.0, `etherparse` 0.21, `tls-parser` 0.12, `x509-parser` 0.18, `rusqlite` 0.41 (bundled),
`axum` 0.8, `maxminddb` 0.32, `httparse` 1.10, `simple-dns` 0.13, `hickory-proto` 0.26, `ts-rs` 12.0,
`tokio` 1.54, `flate2` 1.1, `snmp-parser` 0.11, `ldap-parser` 0.5, `nom` 8.0, `thiserror` 2.0,
`anyhow` 1.0, `tracing` 0.1, `clap` 4.6, `notify` 8.2, `rayon` 1.12, `crossbeam-channel` 0.5, `image`.
