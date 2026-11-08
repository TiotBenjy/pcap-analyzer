# Règles d'interface

Cible : un outil professionnel d'analyse, sobre, dense mais lisible, qui reste propre
quelle que soit la quantité de données. Les captures de `docs/reference/` servent pour
**les fonctionnalités et l'organisation** ; leurs défauts visuels sont à éviter (voir fin du document).

## Principes

1. **Sobriété** : fond neutre, une seule couleur d'accent, pas de dégradés, pas de lueurs,
   pas d'ombres portées marquées, pas d'effets 3D, pas d'animations décoratives.
2. **Aucun emoji ni caractère décoratif**, nulle part (UI, libellés, graphiques, toasts, docs générées).
   Icônes : `lucide-react` uniquement, taille 16 px (20 px dans la sidebar), trait 1,75.
   Drapeaux : `flag-icons` (SVG), jamais d'emoji drapeau (non rendus sous Windows).
   Pas de logos de marques (OS, éditeurs) : texte simple.
3. **Rien ne se chevauche, rien ne déborde** : c'est vérifié automatiquement (voir « Tests visuels »).
4. **Données d'abord** : chiffres alignés (`tabular-nums`), unités cohérentes (octets en IEC :
   Kio/Mio/Gio en fr, KiB/MiB/GiB en en), dates ISO locales avec fuseau affiché dans l'en-tête de session.
5. **Ton** : libellés courts, factuels, sans point d'exclamation ni formule marketing.

## Jetons de design (Tailwind 4, `@theme`)

- Police : Inter (paquet `@fontsource-variable/inter`, embarquée) ; mono : JetBrains Mono (embarquée).
- Tailles : 12 (méta), 13 (tableaux), 14 (corps), 16 (titres de carte), 20 (titre de page). Pas plus grand.
- Neutres : échelle `zinc` ; fond app `zinc-50` / sombre `zinc-950` ; surfaces `white` / `zinc-900`.
- Accent : `blue-600` (sombre `blue-500`), réservé aux éléments actifs, liens et focus.
- Sémantique : succès `emerald-600`, avertissement `amber-600`, erreur `red-600` — en texte ou petites
  pastilles, jamais en grands aplats.
- Rayons : 6 px (contrôles), 8 px (cartes). Bordures 1 px `zinc-200` / `zinc-800`. Ombre : aucune ou `shadow-xs`.
- Espacements : grille de 4 px ; padding de carte 16 px (12 px en mobile).
- Thèmes clair et sombre (suit le système, bascule dans les réglages). Contraste AA minimum.

## Palette des graphiques

- Catégorielle (8 teintes, ordre fixe, lisible en daltonisme) :
  `#2563eb #0d9488 #d97706 #7c3aed #db2777 #65a30d #0891b2 #737373` (la dernière = « Autres »).
- Une même catégorie garde la **même couleur dans toute l'application** (ex. HTTP toujours la même teinte) :
  mapping centralisé dans `ui/src/charts/palette.ts`.
- Catégories d'adresses (légende réseau) : LAN, Serveur, Public, Broadcast, Multicast, Link-local, Loopback —
  couleur + forme de nœud, définies une seule fois.
- Séquentielle (cartes choroplèthes, heatmaps) : une seule teinte de bleu en 5 paliers.

## Choisir le bon graphique

| Besoin | Graphique | Règles |
|---|---|---|
| Part de ≤ 5 catégories | donut | libellés dans la légende, pas sur le graphique ; total au centre |
| Part de > 5 catégories | barres horizontales | top 10 + « Autres », libellé tronqué + infobulle |
| Évolution temporelle | aires empilées / lignes | ≤ 2 000 points, zoom par brush, échelle lin/log |
| Deux dimensions croisées | heatmap | (remplace les nuages de bulles) |
| Répartition géographique | carte choroplèthe + liste top pays | pas de points superposés illisibles |
| Relations entre hôtes | graphe sigma.js | voir « Graphes » |
| Flux entre top N extrémités | chord d3 (≤ 15 nœuds) | sous 768 px : remplacé par une liste classée |
| Termes fréquents | liste classée avec barres | **pas de nuage de mots** |

Interdits : camemberts 3D ou avec ombre, nuages de mots, légendes tronquées sans infobulle,
graphique vide sans état vide explicite.

## Implémentation des graphiques

- ECharts avec `renderer: 'svg'` (permet les tests de chevauchement sur le DOM), encapsulé dans
  un composant unique `<Chart option=... />` qui gère `ResizeObserver`, thème clair/sombre,
  états chargement / vide / erreur, et la palette.
- Hauteurs fixes par type (donut 240 px, barres `min(40 px x n, 400 px)`, série temporelle 320 px)
  pour éviter les sauts de mise en page.
- `grid.containLabel: true`, `axisLabel.hideOverlap: true`, `labelLayout.hideOverlap: true`,
  libellés d'axe tronqués à 24 caractères avec infobulle.
- Légendes : en dessous du graphique quand **son conteneur** fait moins de 1024 px de large, à droite au-delà
  (la largeur de la carte compte, pas celle de la fenêtre : sidebar et grilles la réduisent) ; `type: 'scroll'` si
  trop d'entrées.
- Infobulles : valeur formatée + pourcentage + unité.

## Graphes (onglets Network, DNS, Credentials)

- sigma.js + graphology, mise en page ForceAtlas2 dans un Web Worker, figée après convergence.
- Libellés affichés seulement pour les nœuds principaux (`labelRenderedSizeThreshold`, `labelDensity`)
  et au survol ; jamais tous les libellés en même temps.
- Agrégation par défaut au-delà de 150 nœuds : hôtes publics regroupés par pays (nœud cluster dépliable).
- Panneau latéral de détail au clic ; recherche qui centre et met en surbrillance ; export PNG/SVG.
- Les tailles de nœuds sont bornées (min 4, max 18 px) ; les arêtes sont fines et semi-transparentes.

## Mise en page et responsive

Points de rupture : `sm` 640, `md` 768, `lg` 1024, `xl` 1280, `2xl` 1536.

- **≥ 1024 px** : sidebar fixe 240 px (repliable en 56 px icônes seules), contenu fluide max 1600 px.
- **< 1024 px** : sidebar en tiroir (bouton menu dans l'en-tête).
- Grilles de cartes : 1 colonne (< 640), 2 (≥ 640), 3 (≥ 1024), 4 (≥ 1280).
- Rangée de graphiques : `grid` avec `minmax(320px, 1fr)` ; jamais de largeur fixe en px supérieure à 320.
- Barres de filtres (bascules + recherche) : retour à la ligne propre (`flex-wrap`, `gap-2`) ;
  sous 768 px, les bascules passent dans un menu « Filtres ».
- Tableaux : en-tête collant, virtualisés (TanStack Virtual) au-delà de 200 lignes, colonnes
  redimensionnables ; sous 768 px, défilement horizontal **à l'intérieur** du conteneur du tableau
  (la page elle-même ne défile jamais horizontalement) ou affichage en cartes empilées selon la spec.
- Texte long (URL, noms DNS, hash) : `truncate` + infobulle + bouton copier ; police mono pour IP, ports, hash.
- La sidebar affiche le nombre d'éléments par onglet (badge neutre), estompe les onglets à 0.

## Composants communs (`ui/src/components/`)

`AppShell`, `Sidebar`, `PageHeader` (titre, sous-titre, actions), `Card`, `StatCard`, `Chart`,
`DataTable`, `FilterBar` (bascules avec compteurs, recherche, Tout activer / Tout désactiver),
`Toggle`, `Badge`, `Tabs`, `Endpoint` (IP:port + drapeau + nom résolu), `SecretValue`
(masqué, révéler, copier), `CopyButton`, `EmptyState`, `ErrorState`, `Skeleton`, `Pagination`.
Une vue n'invente pas de composant visuel ad hoc s'il en existe un.

## États

Chaque bloc a trois états soignés : chargement (squelette de la taille finale), vide
(icône lucide neutre + phrase courte, ex. « Aucun serveur LDAP détecté »), erreur (message + Réessayer).

Une erreur non rattrapée dans une vue affiche `RouteError` (`defaultErrorComponent` du routeur), jamais
l'écran par défaut de TanStack Router : message court, l'erreur elle-même, « Recharger » et « Copier les
détails » (erreur, stack, motif de route sans identifiant de session, user agent ; aucune donnée de
capture). La navigation reste utilisable autour. Une build release n'a pas de devtools : c'est le seul
moyen de diagnostiquer un bug du desktop.

## Accessibilité

Navigation clavier complète, focus visible (`ring-2` accent), rôles ARIA sur bascules et onglets,
cibles tactiles ≥ 32 px, pas d'information portée uniquement par la couleur.

## Tests visuels (obligatoires pour toute vue)

`./x.sh shots [vue]` lance l'UI sur une session de fixtures et, pour chaque vue, en largeurs
375, 768, 1280 et 1920, en clair et en sombre :

1. enregistre `.artifacts/screens/<vue>-<largeur>-<theme>.png` ;
2. échoue si `document.documentElement.scrollWidth > window.innerWidth` (débordement horizontal) ;
3. échoue si deux éléments `text`/`tspan` d'un même graphique SVG ont des boîtes qui se recouvrent
   (tolérance 1 px), ou si un libellé sort de son conteneur ;
4. échoue si un élément marqué `data-testid="truncatable"` n'a pas d'attribut `title`.

L'agent `ui-reviewer` relit ensuite les captures produites.

`./x.sh shots` (quelle que soit la vue, ou seul avec `./x.sh shots desktop`) lance ensuite le test de
fumée desktop `ui/tests/desktop` sous WebKit et Chromium : `Object.prototype` gelé comme le fait Tauri,
faux `window.__TAURI_INTERNALS__`, puis dialogue d'import natif, Overview et Sources. Il échoue sur toute
erreur de page ou de console et sur tout écran d'erreur de route. Le WebKit de Playwright et ses
bibliothèques sont téléchargés une fois dans le volume de cache (`scripts/ct/webkit.sh`).

## Défauts observés dans les références, à ne pas reproduire

- Libellés de graphe empilés et illisibles (Network, DNS) -> agrégation + libellés à la demande.
- Camemberts avec ombre et légendes coupées (« Broadcas », « Multicas ») -> donut plat ou barres.
- Nuage de mots « 3D » illisible (HTTP) -> listes classées.
- Grands blancs et graphiques vides (Open Ports) -> états vides explicites, mises en page en grille.
- Emoji dans les titres de cartes et les nœuds (Servers, Network) -> icônes lucide.
- Images de tailles très variables posées sans grille (Pictures) -> grille régulière de vignettes.
