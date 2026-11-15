# Licences

## NetSift

Double licence MIT ou Apache-2.0, au choix de l'utilisateur : `LICENSE-MIT`, `LICENSE-APACHE` à la
racine, `license = "MIT OR Apache-2.0"` dans `Cargo.toml` (workspace) et `ui/package.json`. Les deux
fichiers sont livrés dans chaque bundle (`licenses/`, ressources Tauri).

Dépendances sous licences permissives uniquement : `deny.toml` pour Rust (`cargo deny`), la même
liste dans `about.toml` pour la liste des licences tierces, plus `0BSD`, `Unlicense` et `OFL-1.1`
(polices) pour les paquets npm (`NPM_EXTRA_LICENSES`, `ui/scripts/third-party-licenses.ts`).

## Licences tierces

L'application embarque la liste des logiciels tiers qu'elle contient, avec leurs textes de licence :

| Fichier (commité) | Usage |
|---|---|
| `ui/src/views/settings/licenses/third-party-licenses.json` | « Paramètres > À propos > Licences tierces », chargé à l'ouverture du dialogue (chunk séparé, jamais téléchargé) |
| `apps/desktop/resources/licenses/THIRD-PARTY-NOTICES.txt` | texte brut livré dans chaque bundle (`licenses/`), avec l'attribution DB-IP |

Les deux fichiers sont **générés** par `./x.sh licenses` (`scripts/ct/licenses.sh`), jamais édités à
la main :

1. **Rust** : `cargo-about` (version épinglée dans `scripts/ct/licenses.sh`, compilé une fois dans le
   volume de cache comme git-cliff), configuré par `about.toml` : crates du binaire desktop
   (`apps/desktop`) pour les quatre cibles des bundles (Linux x86_64, Windows x86_64, macOS arm64 et
   x86_64), sans dépendances de développement ni de build, crates `netsift-*` exclues
   (`publish = false`). Hors ligne : `cargo fetch` puis `cargo about generate --frozen --fail`
   (aucun appel à clearlydefined.io ni aux dépôts git des crates). Pour une crate en double licence,
   le texte reproduit est celui de la première licence acceptée dans l'ordre d'`about.toml` (MIT
   en général). `ring` a une clarification épinglée par empreinte : une nouvelle version fait
   échouer la génération jusqu'à relecture de ses fichiers de licence.
2. **npm** : `ui/scripts/third-party-licenses.ts` lit les entrées de production (`dev` absent) de
   `ui/package-lock.json` et, dans `ui/node_modules` (après `npm ci`), leurs fichiers `LICENSE*`,
   `COPYING*`, `licenses/*` (code tiers intégré) et `NOTICE`. Un paquet sans fichier de licence reçoit
   le texte de référence de sa licence (marqué comme tel). Une licence hors liste fait échouer.
3. Le même script fusionne les deux listes (tri stable, textes dédupliqués, ni date, ni version, ni
   chemin absolu) et écrit les deux fichiers ; les fichiers `NOTICE` des crates sont repris aussi
   (Apache-2.0, section 4 d).

Vérification : `./x.sh check` (étape « licences tierces ») et le job `licenses` de `ci.yml` relancent
la génération avec `--check` et échouent si un fichier commité diffère. Après un changement de
dépendances (Cargo.lock, package-lock.json) : `./x.sh licenses`, puis committer les deux fichiers.

L'interface affiche les textes comme du texte brut (nœuds texte React dans un `<pre>`), jamais comme
du HTML. Aucun lien n'est ouvert : l'adresse du dépôt est affichée en texte (le plugin `opener` est
limité au dossier `exports/`).
