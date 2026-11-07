# HTTP Headers

Référence : `docs/reference/http-headers.png`.

## But

Parcourir et rechercher les en-têtes HTTP (requêtes et réponses) pour repérer cookies, jetons,
agents, serveurs, en-têtes inhabituels.

## Données

Réutilise `http_transactions` et `http_headers` (analyseur `http`, branche `feat/http`).
API : `/http/headers/stats` (méthodes avec compteurs), `/http/headers?method=&q=&name=` (paginé, FTS).

## Mise en page

1. Graphique Méthodes (donut, ≤ 5 catégories sinon barres).
2. Barre de filtres : bascules de méthode avec compteurs, Tout activer / Tout désactiver, recherche texte
   (porte sur noms et valeurs d'en-têtes), filtre « nom d'en-tête » avec autocomplétion.
3. Liste : badge méthode + chemin (mono) + host + statut ; ligne dépliée = deux colonnes Requête / Réponse
   (une seule colonne sous 1024 px), table nom/valeur en mono, valeurs longues repliées avec « afficher tout »,
   en-têtes sensibles (`Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`) masqués par défaut
   avec `SecretValue`.
4. Pagination serveur (« Page n », précédent / suivant) ou défilement infini virtualisé — au choix, identique
   à la vue HTTP.

## Améliorations par rapport à la référence

- Lignes « GET / » identiques indifférenciables -> ajout de host, endpoint serveur et statut sur la ligne.
- Mise en évidence du terme recherché dans les valeurs.

## Critères d'acceptation

- Recherche d'une valeur de cookie retrouve la bonne transaction ; en-tête `Authorization` masqué par défaut.
- `./x.sh shots http-headers` vert.
