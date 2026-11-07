# Workflow git et agents parallèles

Pas de `gh`, pas de pull requests : tout est local avec `git` et `scripts/wt.sh`.
Le dépôt distant GitHub sert à la sauvegarde des branches et à la CI.

## Conventions

- Branche : `<type>/<nom-court>` avec `type` dans `feat fix perf refactor test docs chore ci`,
  nom en minuscules, chiffres et tirets. Exemple : `feat/dns`, `fix/pcapng-multi-shb`.
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
                                          # --push : pousse main et la branche ; --cleanup : supprime worktree + branche
scripts/wt.sh rm <branche> [--delete-branch]
```

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
- Personne ne modifie `docs/ROADMAP.md` hors orchestrateur.
- Les types ts-rs générés sont regénérés après rebase (`./x.sh cargo test -p netsift-api export_bindings`).

## Conteneurs et parallélisme

Chaque worktree a son propre répertoire `target` dans le volume de cache (`/cache/target/<slug>`) ;
le registre cargo et `sccache` sont partagés, donc les dépendances ne sont compilées qu'une fois.
`./x.sh dev` dans un worktree utilise des ports dérivés du nom si `NETSIFT_UI_PORT` n'est pas fixé
(voir skill `dev-env`). `./x.sh shots` n'expose aucun port et peut tourner en parallèle.

## Remote et CI

- `git remote add origin <url>` est fait par l'utilisateur. Sans remote, `push` est ignoré proprement.
- Le push d'une branche déclenche `ci.yml` ; un tag `v*` sur `main` déclenche `release.yml`
  (binaires Linux + Windows en brouillon de release). Pas de `gh` : l'utilisateur consulte l'onglet
  Actions de GitHub.
