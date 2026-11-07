---
name: parallel
description: Orchestrer plusieurs agents implementer en parallèle sur une vague de la ROADMAP, chacun dans son worktree, puis revue et fusions locales séquentielles. À utiliser quand on attaque une vague de tâches indépendantes (ex. "lance la vague 3.A", "implémente DNS, HTTP et TLS en parallèle").
argument-hint: <id de vague ou liste de tâches>
---

# Orchestration parallèle

Tu es l'orchestrateur (session principale). Tu ne codes pas les tâches toi-même : tu prépares les
worktrees, tu délègues à des agents `implementer` en arrière-plan, tu fais relire, tu fusionnes.
Référence complète : `docs/GIT_WORKFLOW.md`.

## 1. Cadrer la vague
- Lis la vague demandée dans `docs/ROADMAP.md`. Vérifie que **toutes les dépendances** (tâches d'une
  vague précédente) sont `[x]` fusionnées dans `main`. Sinon, fais-les d'abord.
- Confirme que les tâches de la vague ont des **périmètres disjoints** (crates/modules/vues différents).
  Si deux tâches se disputent un fichier partagé, découpe ou séquence.
- Assure-toi que le checkout racine est sur `main` et propre, et que l'image est construite
  (`./x.sh image` en arrière-plan si besoin — voir skill `dev-env`).

## 2. Créer les worktrees
Pour chaque tâche, crée la branche + worktree (même nom) :
```
scripts/wt.sh new feat/dns
scripts/wt.sh new feat/http
scripts/wt.sh new feat/tls
```
Marque la vague `[~]` dans `docs/ROADMAP.md` et commit sur `main`
(`docs(roadmap): start wave 3.A`).

## 3. Lancer les implementers (en parallèle)
Dans **un seul message**, lance un agent `implementer` par tâche, en arrière-plan. Donne à chacun :
- le chemin de son worktree (`.worktrees/<branche>`) et sa branche ;
- l'ID de tâche et le nom de la spec à lire (`docs/specs/<...>.md` + section ROADMAP) ;
- les critères d'acceptation exacts ;
- le rappel : rester dans le périmètre, écrire les tests, `./x.sh -C <worktree> check` vert avant de finir,
  ne pas fusionner soi-même.

## 4. Revue à la complétion de chaque agent
Quand un implementer signale avoir fini :
- lance un agent `reviewer` sur sa branche ; si la branche touche l'UI, lance aussi `ui-reviewer`
  (après `./x.sh -C <worktree> shots <vue>`).
- Points **bloquants** -> renvoie-les à l'implementer (SendMessage au même agent, son contexte est intact).
- Sinon -> prêt à fusionner.

## 5. Fusionner (séquentiel, une branche à la fois)
`scripts/wt.sh merge` prend un verrou : n'enchaîne pas deux fusions en parallèle.
```
scripts/wt.sh merge feat/dns --cleanup        # sync(rebase) + check + merge --no-ff
```
En cas de conflit au rebase, résous-le dans le worktree (`.worktrees/<branche>`), relance le check,
puis refais `merge`. Après chaque fusion, coche `[x]` la tâche dans `docs/ROADMAP.md` (commit sur `main`).
Les branches suivantes se rebasent sur le `main` à jour (le `merge` le fait), donc fusionne d'abord la
plus structurante.

## 6. Pousser et clôturer
- Si un remote existe : `scripts/wt.sh merge <dernière> --push`, ou `scripts/wt.sh push <branche>` au fil de l'eau
  (déclenche la CI). Pas de `gh` : l'utilisateur regarde l'onglet Actions de GitHub.
- Quand toute la vague est `[x]`, résume à l'utilisateur ce qui a été fusionné et propose de montrer le
  résultat (skill `preview`).

## Règles
- Seul toi modifies `docs/ROADMAP.md`.
- Ne lance pas une vague dont les dépendances ne sont pas fusionnées.
- Nombre d'implementers simultanés raisonnable (3–4) pour ne pas saturer le disque/CPU du conteneur.
- Si une tâche s'avère plus grosse que prévu, scinde-la dans la ROADMAP plutôt que de la laisser déborder.
