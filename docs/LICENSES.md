# Licences

## NetSift

Apache License 2.0 seule : `LICENSE` (texte officiel, non modifié) et `NOTICE` à la racine,
`license = "Apache-2.0"` dans `Cargo.toml` (workspace, hérité par toutes les crates et l'application
desktop ; en dur dans `fuzz/Cargo.toml`, hors workspace), `ui/package.json` et la racine de
`ui/package-lock.json`. `NOTICE` renvoie à `THIRD_PARTY_LICENSES`. Les trois fichiers sont livrés dans
chaque bundle (`licenses/`, ressources Tauri, vérifié par `apps/desktop/tests/bundle.rs`). Une
redistribution doit conserver `LICENSE` et `NOTICE` et signaler les fichiers modifiés.

Dépendances sous licences permissives, ou MPL-2.0 (copyleft faible, au niveau du fichier, utilisée
sans modification) : `deny.toml` pour Rust (`cargo deny`), la même
liste dans `about.toml` pour la liste des licences tierces, plus `0BSD`, `Unlicense` et `OFL-1.1`
(polices) pour les paquets npm (`NPM_EXTRA_LICENSES`, `ui/scripts/third-party-licenses.ts`).

## Licences tierces

L'application embarque la liste des logiciels tiers qu'elle contient, avec leurs textes de licence :

| Fichier (commité) | Usage |
|---|---|
| `ui/src/views/settings/licenses/third-party-licenses.json` | « Paramètres > À propos > Licences tierces », chargé à l'ouverture du dialogue (chunk séparé, jamais téléchargé) |
| `THIRD_PARTY_LICENSES` (racine) | texte brut cité par `NOTICE` et livré dans chaque bundle (`licenses/`) : licences, fichiers d'avis (`NOTICE`, `THIRDPARTYNOTICES`...), adresse des sources des paquets MPL-2.0, attribution DB-IP |

Les deux fichiers sont **générés** par `./x.sh licenses` (`scripts/ct/licenses.sh`), jamais édités à
la main :

1. **Rust** : `cargo-about` (version épinglée dans `scripts/ct/licenses.sh`, compilé une fois dans le
   volume de cache comme git-cliff), configuré par `about.toml` : crates du binaire desktop
   (`apps/desktop`) pour les quatre cibles des bundles (Linux x86_64, Windows x86_64, macOS arm64 et
   x86_64), sans dépendances de développement ni de build, crates `netsift-*` exclues
   (`publish = false`). Hors ligne : `cargo fetch` puis `cargo about generate --frozen --fail`
   (aucun appel à clearlydefined.io ni aux dépôts git des crates). Pour une crate en double licence,
   le texte reproduit est celui de la première licence acceptée dans l'ordre d'`about.toml` (MIT
   en général). `ring` a une clarification épinglée par empreinte (`LICENSE`, `LICENSE-BoringSSL`,
   `LICENSE-other-bits`) : une nouvelle version fait échouer la génération jusqu'à relecture de ses
   fichiers de licence. `about.toml` accepte exactement les licences de `deny.toml` (vérifié par un
   test de `ui/scripts/third-party-licenses.test.ts`).
2. **npm** : `ui/scripts/third-party-licenses.ts` lit les entrées de production (`dev` absent) de
   `ui/package-lock.json` et, dans `ui/node_modules` (après `npm ci`), leurs fichiers `LICENSE*`,
   `COPYING*`, `licenses/*` (code tiers intégré) et `NOTICE`. Un paquet sans fichier de licence reçoit
   le texte de référence de sa licence (marqué comme tel). Une licence hors liste fait échouer.
3. Le même script fusionne les deux listes (tri stable, textes dédupliqués, ni date, ni version, ni
   chemin absolu) et écrit les deux fichiers ; les fichiers `NOTICE` des crates sont repris aussi
   (Apache-2.0, section 4 d) : tout fichier dont le nom contient « notice » ;
4. pour chaque paquet sous MPL-2.0 (licence retenue), `THIRD_PARTY_LICENSES` indique où obtenir son
   code source à cette version (crates.io ou npmjs.com), comme l'exige la MPL-2.0 (section 3.2) pour
   une distribution sous forme exécutable. Aujourd'hui : `cssparser` 0.37.0, `cssparser-macros`
   0.7.1, `dtoa-short` 0.3.5, `option-ext` 0.2.0 et `selectors` 0.38.0 (Rust, tirés par Tauri et
   `dirs`) ; aucun paquet npm.

La partie npm dépend de la plateforme : les paquets optionnels propres à un système (binaires
natifs) ne sont installés, donc listés, que sur ce système. La liste de référence se génère donc
dans le conteneur ou en CI, tous deux Linux x64 ; `ui/node_modules` installé sur l'hôte (Windows,
macOS) n'est pas une source valable. Aujourd'hui aucun paquet de production n'est optionnel : la
précaution vaut pour une dépendance future.

Vérification : `./x.sh check` (étape « licences tierces ») et le job `licenses` de `ci.yml` relancent
la génération avec `--check` et échouent si un fichier commité diffère. Après un changement de
dépendances (Cargo.lock, package-lock.json) : `./x.sh licenses`, puis committer les deux fichiers.

L'interface affiche les textes comme du texte brut (nœuds texte React dans un `<pre>`), jamais comme
du HTML. Aucun lien n'est ouvert : l'adresse du dépôt est affichée en texte (le plugin `opener` est
limité au dossier `exports/`).
