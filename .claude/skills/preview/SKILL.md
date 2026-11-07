---
name: preview
description: Montrer l'application à l'utilisateur pendant le développement, soit en direct dans le navigateur (./x.sh dev), soit via des captures d'écran (./x.sh shots), soit en construisant l'app desktop (./x.sh desktop). À utiliser quand l'utilisateur veut voir l'avancement visuel.
---

# Prévisualiser l'application

L'utilisateur veut voir l'UI régulièrement, même si le livrable final est construit en CI.
Trois moyens, du plus léger au plus complet.

## 1. Captures d'écran (rapide, sans interaction)
```
./x.sh shots            # toutes les vues implémentées
./x.sh shots overview   # une vue
```
Produit `.artifacts/screens/<vue>-<largeur>-<theme>.png` en 375/768/1280/1920, clair et sombre, en
appliquant les vérifications de `docs/UI_GUIDELINES.md` (débordement, chevauchement). **Envoie les PNG
pertinents à l'utilisateur** avec `SendUserFile` (au moins 1280 clair + 375 clair pour juger du responsive).
C'est le moyen par défaut pour montrer l'avancement sans bloquer une session.

## 2. Serveur de dev en direct (interaction réelle)
`./x.sh dev` est un processus **long**. Lance-le en arrière-plan, attends l'URL affichée
(`http://localhost:<port>`), vérifie qu'elle répond, puis donne l'URL à l'utilisateur ; il ouvre dans
son navigateur. L'API et l'UI sont publiées sur loopback uniquement. Pour arrêter : termine le processus.
Monte des captures de démonstration en déposant un dossier dans `captures/` (monté en lecture seule dans
le conteneur), ou génère une session de fixtures.

## 3. Application desktop (le vrai livrable)
```
./x.sh desktop          # Linux : AppImage + .deb dans dist/
```
Pour Windows, le build de référence est la CI (`release.yml`, runner `windows-latest`). Localement,
`./x.sh desktop-win` (cargo-xwin) peut produire un `.exe` de dépannage, non signé et sans installateur.
Envoie l'AppImage/.deb à l'utilisateur avec `SendUserFile` s'il veut tester l'app réelle sous Linux.

## Choix
- Montrer un écran vite -> **shots** + SendUserFile.
- Laisser l'utilisateur cliquer -> **dev** + URL.
- Livrer un binaire testable -> **desktop** + SendUserFile (Linux) ou CI (Windows).
