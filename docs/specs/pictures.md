# Pictures

Référence : `docs/reference/pictures.png`.

## But

Parcourir les images transférées en HTTP (clair), reconstruites depuis les corps de réponse.

## Données

Depuis `objects` (analyseur `http`, branche `feat/http`) filtrés sur les types image
(`image/png|jpeg|gif|webp|bmp|svg+xml`, détectés par magic). Miniatures PNG générées **côté Rust**
(crate `image`, décodeurs purs Rust ; dimensions bornées, délai borné, images malformées ignorées proprement) ;
le SVG n'est **pas rendu** dans la webview (vignette « SVG » générique, téléchargement possible).
`objects` : SHA-256, type MIME, taille, dimensions, transaction d'origine, URL, serveur, ts.
API (ADR-016) : `GET /sessions/{id}/objects?kind=image&q=&type=&host=&sort=` (paginé, keyset) et
`/objects/stats` ; miniature `GET /sessions/{id}/objects/{sha256}/thumb` (PNG de 320 px au plus), aperçu
`.../preview` (PNG de 1 600 px au plus, rendu à la demande) ; original `GET /sessions/{id}/objects/{sha256}`,
toujours en pièce jointe `application/octet-stream`, jamais affiché. La webview affiche les PNG en URL
`data:` (lus avec le jeton, autorisés par `img-src`).

## Mise en page

- **Grille régulière** de vignettes de taille fixe (ratio conservé, recadrage centré, fond neutre),
  `grid` responsive (`repeat(auto-fill, minmax(140px, 1fr))`) — correction directe du défaut de la référence
  (images de tailles disparates posées sans alignement). Lazy-loading, virtualisation au-delà de ~300 items.
- Survol : URL tronquée + taille. Clic : visionneuse (aperçu PNG ré-encodé de 1 600 px au plus, sur fond neutre ;
  métadonnées, bouton Télécharger, navigation précédent/suivant au clic et aux flèches). Barre de filtres : recherche URL, type, hôte.
- Vignette = image statique servie par le backend (jamais le contenu distant ; aucune requête réseau sortante).

## Critères d'acceptation

- Fixture : un PNG et un GIF transférés en HTTP, un JPEG tronqué -> deux vignettes valides, le tronqué ignoré
  proprement (pas de panique du générateur de miniatures).
- Aucune requête réseau émise par la webview au chargement de la grille (CSP `img-src 'self' http://127.0.0.1:*`).
- `./x.sh shots pictures` vert (grille alignée, pas de débordement).
