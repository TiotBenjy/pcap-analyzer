# Workflow git et agents parallèles

Pas de `gh`, pas de pull requests : tout est local avec `git` et `scripts/wt.sh`.
Le dépôt distant GitHub sert à la sauvegarde des branches et à la CI.

## Conventions

- Branche : `<type>/<nom-court>` avec `type` dans `feat fix perf refactor test docs chore ci`,
  nom en minuscules, chiffres et tirets (points admis pour un numéro de version). Exemple :
  `feat/dns`, `fix/pcapng-multi-shb`, `chore/release-0.2.0`.
- Worktree : **même nom que la branche**, sous `.worktrees/` (ignoré par git) :
  `.worktrees/feat/dns`.
- Commits : Conventional Commits en anglais, impératif, ≤ 72 caractères au titre, corps si utile.
  Petits commits cohérents ; pas de commit « wip » fusionné (squasher avec `git rebase -i` n'est pas
  disponible en non-interactif : utiliser `git commit --fixup` + `git rebase --autosquash` avec
  `GIT_SEQUENCE_EDITOR=true`).
- Le checkout racine reste sur `main`, sans modification non commitée.

## Commandes `scripts/wt.sh`

```
scripts/wt.sh new <branche> [base=main]   # crée la branche + .worktrees/<branche>
scripts/wt.sh list                        # worktrees, branche, avance/retard sur main, état propre
scripts/wt.sh sync <branche>              # rebase de la branche sur main (dans son worktree)
scripts/wt.sh check <branche>             # ./x.sh check dans le worktree
scripts/wt.sh push <branche>              # git push -u origin <branche> (si un remote existe)
scripts/wt.sh merge <branche> [--push] [--cleanup] [--no-check]
                                          # sync + check + merge --no-ff dans main
                                          # --push : pousse main, et la branche (sans --cleanup)
                                          # --cleanup : supprime worktree + branche + target de
                                          #   build (avec --push : aussi la branche distante)
scripts/wt.sh rm <branche> [--delete-branch]  # supprime le worktree et son target de build
```

`new` et `merge --cleanup` lancent aussi `./x.sh clean --auto` : suppression des targets orphelins
du cache, silencieuse s'il n'y a rien à supprimer (`NETSIFT_NO_AUTO_CLEAN=1` la désactive). Un échec
de ce nettoyage n'est qu'un avertissement : il ne fait jamais échouer la commande ni la fusion.

`merge` est sérialisé par un verrou (`.git/wt-merge.lock`) : deux fusions ne peuvent pas se croiser.

## Déroulé d'une vague parallèle (orchestrateur = session principale)

1. Lire la vague dans `docs/ROADMAP.md`, vérifier que les dépendances sont fusionnées.
2. Pour chaque tâche : `scripts/wt.sh new <branche>`, puis lancer un agent `implementer`
   **en arrière-plan** avec : chemin du worktree, branche, identifiant de tâche, spec à lire,
   critères d'acceptation. Tous les agents d'une vague partent dans le même message.
3. Marquer `[~]` dans `ROADMAP.md` (commit `docs(roadmap): start wave X` sur `main`).
4. À chaque fin d'agent : lancer `reviewer` (et `ui-reviewer` si UI) sur la branche.
   Points bloquants -> renvoyer à l'implementer (SendMessage) ; sinon fusionner.
5. Fusions **une par une** : `scripts/wt.sh merge <branche> --cleanup` (le rebase + gate
   absorbe les conflits ; en cas de conflit, l'orchestrateur le résout dans le worktree).
6. Cocher `[x]` dans `ROADMAP.md`, commit sur `main`. Pousser avec `scripts/wt.sh merge --push`
   ou, pour le seul commit de roadmap, lors de la fusion suivante.

## Éviter les conflits entre agents parallèles

- Une tâche = un périmètre de fichiers clair (une crate, un module d'analyseur, un dossier de vue).
- Fichiers partagés « points d'enregistrement » (liste des analyseurs, enum `Record`, routes, sidebar,
  migrations) : chaque branche ajoute **une ligne** dans une zone dédiée, triée alphabétiquement,
  pour que les conflits soient triviaux. Les migrations sont nommées `NNNN_<analyseur>.sql` avec un
  numéro réservé par analyseur (dns 0100, http 0200, tls 0300, flows 0400, smb 0500, creds 0600,
  objects 0700, servers 0800, network 0900, ...).
- Étapes de fin d'import (`netsift-store/src/finalize.rs`, `SESSION_FINALIZERS`, ADR-014) : une ligne par
  analyseur, **dans l'ordre d'exécution** (après les étapes citées dans `after`, sinon à la fin), jamais
  triée alphabétiquement.
- Personne ne modifie `docs/ROADMAP.md` hors orchestrateur.
- Les types ts-rs générés sont regénérés après rebase (`./x.sh cargo test -p netsift-api export_bindings`).

## Conteneurs et parallélisme

Chaque worktree a son propre répertoire `target` dans le volume de cache (`/cache/target/<slug>`,
3 à 7 Go) ; le registre cargo et `sccache` sont partagés, donc les dépendances ne sont compilées
qu'une fois. x.sh écrit dans chaque target un marqueur `.origin` (chemin hôte, dernière
utilisation) : `wt.sh rm` / `merge --cleanup` suppriment le target du worktree retiré, et
`./x.sh clean` ceux dont le chemin a disparu (clones jetables, worktrees supprimés à la main).
`./x.sh dev` dans un worktree utilise des ports dérivés du nom si `NETSIFT_UI_PORT` n'est pas fixé
(voir skill `dev-env`). `./x.sh shots` n'expose aucun port et peut tourner en parallèle.

## Remote et CI

- `git remote add origin <url>` est fait par l'utilisateur. Sans remote, `push` est ignoré proprement.
- Le push d'une branche déclenche `ci.yml` ; le push d'un tag `vX.Y.Z` (par `scripts/release.sh`
  uniquement) déclenche `release.yml`. Pas de `gh` : suivi par `scripts/release-status.sh` (API
  publique GitHub) ou l'onglet Actions.

## Publier une version

Une version se publie **uniquement** par `scripts/release.sh X.Y.Z`, après accord explicite de
l'utilisateur pour ce numéro. Jamais de tag poussé à la main. Décision : ADR-011.

### Principe

- Version unique : `[workspace.package] version` de `Cargo.toml`. Tauri la lit (pas de `version`
  dans `tauri.conf.json`), l'API la renvoie (`/api/v1/health`, affichée dans Settings),
  `ui/package.json` et `ui/package-lock.json` en sont des copies synchronisées par le script.
  `scripts/check-version.sh [vX.Y.Z]` vérifie la concordance (gate `./x.sh check`, `ci.yml`,
  premier job de `release.yml` avec le tag).
- SemVer : `vX.Y.Z` donne une release, `vX.Y.Z-beta.1` (tout suffixe) une prerelease GitHub.
  **Limite des prereleases sous Linux** : Debian compare `0.2.0-beta.1` comme supérieur à `0.2.0`
  (le `.deb` de la beta ne sera pas remplacé par la version finale) et le `.rpm` garde le `-` dans
  sa version. Éviter les prereleases tant que ce n'est pas réglé (conversion `~` pour deb/rpm), ou
  accepter cette limite en connaissance de cause.
- Notes de release et `CHANGELOG.md` : générés par git-cliff (`cliff.toml`) à partir des messages
  Conventional Commits, groupés en Fonctionnalités, Corrections, Performances, Documentation,
  Build/CI, Tests, Autres. Les fusions `merge(...)`, `docs(roadmap)` et `chore(release)` sont exclues.
  Un message de commit soigné est donc une ligne de notes de version.

### Déroulé (`scripts/release.sh X.Y.Z`, sur l'hôte, depuis le checkout racine)

Préconditions vérifiées avant toute modification : checkout racine sur `main`, propre ;
`git fetch origin` fait et `main` égal à `origin/main` ; `X.Y.Z` SemVer et supérieur à la version
actuelle ; tag `vX.Y.Z` absent en local et sur `origin` ; branche `chore/release-X.Y.Z` absente.

1. `scripts/wt.sh new chore/release-X.Y.Z`.
2. Dans ce worktree : version de `Cargo.toml`, `./x.sh cargo update --workspace` (Cargo.lock,
   crates internes seulement), `./x.sh npm version X.Y.Z --no-git-tag-version`,
   `scripts/check-version.sh vX.Y.Z`, puis `./x.sh cliff --tag vX.Y.Z --output CHANGELOG.md`.
   Commit `chore(release): vX.Y.Z` (ligne `Co-Authored-By` : variable `RELEASE_COAUTHOR`).
3. `scripts/wt.sh merge chore/release-X.Y.Z --push --cleanup` : rebase, **gate complet**, fusion
   `--no-ff` et push de `main`, puis suppression du worktree, de la branche locale et de la branche
   distante. C'est le seul chemin qui pousse `main`, comme pour toute branche.
4. Tag annoté `vX.Y.Z` sur le HEAD de `main` (le commit de fusion), puis `git push origin vX.Y.Z`.
   Ce push déclenche `release.yml`.
5. Affichage des URL (page Actions du workflow, page de la release) et de la commande de suivi.

Option `--dry-run` : préconditions, versions qui seraient appliquées et notes de la release
(git-cliff). Aucune écriture dans le dépôt (seules les références distantes sont rafraîchies par le
fetch). Il n'y a pas de mode « sans push » : pour tester le script de bout en bout, utiliser un clone
jetable dont `origin` est un dépôt bare local.

En cas d'échec avant la fusion (étape 3), rien n'est poussé et le script supprime lui-même le worktree
et la branche de release. Après la fusion locale (échec du push de `main` ou du tag), il affiche les
commandes pour annuler la fusion locale ou pour terminer (tag). Rien n'est interactif (utilisable par
un agent).

### Ce que fait la CI (`release.yml`)

1. `version` : le tag désigne un commit de `main`, `scripts/check-version.sh vX.Y.Z` ; calcule
   « prerelease » (suffixe SemVer).
2. `create` : notes git-cliff de la plage tag précédent -> tag courant, plus les mentions
   d'installation (`.github/release-notes-footer.md`) ; crée la release **en brouillon**.
3. `bundle` (en parallèle) : Linux x86_64 (`.AppImage`, `.deb`, `.rpm`, Ubuntu 22.04),
   Windows x86_64 (`-setup.exe` NSIS, `.msi`), macOS universel (`.dmg`, Apple Silicon + Intel).
   Noms produits par Tauri, avec version et architecture ; le job échoue si un nom ne contient pas
   la version. Artefacts du workflow conservés 14 jours.
4. `publish` : télécharge tous les bundles, calcule `SHA256SUMS.txt`, les joint au brouillon puis
   le publie (prerelease selon le tag, « latest » sinon). Si un bundle échoue, `publish` ne tourne
   pas : le brouillon reste sans fichiers.

Bundle en échec :

- échec passager (runner, réseau) : « Re-run failed jobs » relance le même commit ; `publish` termine
  la release ;
- échec qui demande une correction de code : relancer ne sert à rien (même commit). **Recommandé :**
  corriger sur une branche, fusionner, puis publier `X.Y.Z+1` avec `scripts/release.sh`, et supprimer
  le brouillon `vX.Y.Z` dans l'interface GitHub (le tag reste, sans release). Supprimer le tag distant
  pour réutiliser `X.Y.Z` réécrirait un historique publié : à éviter.

Lancement manuel (`workflow_dispatch`) sans tag : bundles en artefacts du workflow, aucune release.

Bundles **non signés** (aucun secret) : avertissement SmartScreen sous Windows, Gatekeeper sous
macOS (signature ad hoc, sans notarisation). Les notes de release expliquent comment passer outre.

### Suivi

```
scripts/release-status.sh vX.Y.Z           # état du run, des jobs, de la release et des fichiers
scripts/release-status.sh vX.Y.Z --wait    # interroge toutes les 60 s jusqu'à la fin (90 min max)
```

Code de sortie non nul si le run n'a pas réussi, si la release n'est pas publiée ou s'il manque un
fichier attendu (`.AppImage`, `.deb`, `.rpm`, `.exe`, `.msi`, `.dmg`, `SHA256SUMS.txt`). Une
prerelease n'a pas de `.msi` (WiX n'accepte que des versions numériques) : il n'est pas attendu.
