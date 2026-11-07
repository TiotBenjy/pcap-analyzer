# HTTP

Référence : `docs/reference/http.png`.

## But

Voir les transactions HTTP en clair : qui parle à qui, quoi, résultat, contenu transféré.

## Données

Analyseur `http` sur le flux TCP réassemblé (détection par contenu, pas seulement par port) :
- HTTP/1.0 et 1.1, pipelining et keep-alive, `Transfer-Encoding: chunked`, `Content-Encoding` gzip/deflate/br
  (corps décompressé borné à 64 Mio, ratio de décompression borné contre les bombes), requête sans réponse.
- `http_transactions` : ts requête/réponse, flux, client, serveur, méthode, host, chemin, query, version, statut,
  raison, content-type, tailles (en-têtes, corps sur le fil, corps décodé), user-agent, referer, sha256 objet.
- `http_headers` : (transaction, direction, ordre, nom, valeur) + FTS sur nom/valeur.
- Corps de réponse et de requête -> `objects` (blob SHA-256) si taille ≤ borne ; type MIME par **contenu**
  (magic) et par en-tête, les deux conservés.
- Émet `Record::Credential` pour Authorization Basic et formulaires (champs `pass`, `pwd`, `password`...),
  utilisé par l'onglet Credentials.

API : `/http/stats` (méthodes, classes de statut, statuts, content-types top 10 + autres, top hosts,
top user-agents), `/http/transactions` (paginé, filtres méthode/statut/host/texte), `/http/transactions/{id}`.

## Mise en page

1. Rangée de graphiques : Méthodes (donut ≤ 5 sinon barres), Codes de réponse (barres groupées par classe
   2xx/3xx/4xx/5xx, couleur par classe), Types de contenu (barres top 10 + Autres).
2. Rangée « Tops » (remplace le nuage de mots) : Hôtes les plus contactés, User-Agents, Noms d'en-têtes
   rares/notables — listes classées avec barre de proportion, 10 entrées, « voir tout » vers la liste filtrée.
3. Barre de filtres : bascules de méthode avec compteurs (GET, POST, HEAD, OPTIONS, PUT, PATCH, DELETE, CONNECT,
   autres), Tout activer / Tout désactiver, recherche texte.
4. Liste des transactions (virtualisée) : heure, client `Endpoint`, serveur `Endpoint` + host, méthode (badge),
   chemin (mono, tronqué), statut (badge par classe), taille, content-type. Ligne dépliée :
   onglets Requête / Réponse (en-têtes en table clé/valeur mono), Corps (aperçu texte échappé ≤ 64 Kio,
   ou vignette si image, ou bouton Télécharger), Flux (5-tuple, durées).

Sous 768 px : lignes compactes sur deux lignes (méthode + chemin / endpoints + statut).

## Améliorations par rapport à la référence

- Nuage de mots « 3D » supprimé au profit de listes classées lisibles.
- Légendes non tronquées ; ports colorés supprimés (le port reste en gris dans `Endpoint`).

## Critères d'acceptation

- Fixtures : keep-alive avec 3 requêtes, chunked + gzip, réponse coupée entre deux chunks, requête sans réponse ->
  transactions exactes (snapshot insta).
- Bombe gzip synthétique -> corps tronqué à la borne, pas de dépassement mémoire (test).
- `./x.sh shots http` vert.
