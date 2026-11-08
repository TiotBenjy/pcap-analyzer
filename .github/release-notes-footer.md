
### Installation

| Système | Fichier |
|---|---|
| Linux (Debian, Ubuntu) | `.deb` |
| Linux (Fedora, RHEL, openSUSE) | `.rpm` |
| Linux (toutes distributions) | `.AppImage` |
| Windows 10/11 | `-setup.exe` (NSIS) ou `.msi` |
| macOS 11+ (Apple Silicon et Intel) | `.dmg` (universel) |

Les bundles **ne sont pas signés** (pas de certificat éditeur ; macOS : signature ad hoc seulement,
sans notarisation).

- Windows : SmartScreen affiche « Windows a protégé votre ordinateur » ; cliquer
  « Informations complémentaires », puis « Exécuter quand même ».
- macOS : Gatekeeper bloque le premier lancement. Ouvrir Réglages Système > Confidentialité et
  sécurité > « Ouvrir quand même » (macOS 15+), ou clic droit sur l'application > « Ouvrir »
  (macOS 14 et avant). Si macOS indique que l'application est endommagée :
  `xattr -dr com.apple.quarantine /Applications/NetSift.app`.

Vérifier un téléchargement : `sha256sum -c SHA256SUMS.txt --ignore-missing`.
