# Connections

Références : `docs/reference/connections-1.png`, `docs/reference/connections-2.png`.

## But

Qui échange le plus de données avec qui, et où se situent géographiquement les sources et destinations.

## Données

Table `flows` (moteur) agrégée par paire d'extrémités (`conversations` : IP A, IP B, octets A->B, B->A, paquets,
flux, protocoles applicatifs, premier/dernier ts). Classification et pays via `netsift-geo`.
API : `/connections/stats` (top pays source/destination en octets), `/connections/top?n=10|20|50&exclude_dns=`
(matrice pour le chord), `/connections` (paginé, tri par octets, filtres from/to/protocole/catégorie).

## Mise en page

1. Deux cartes géographiques côte à côte (empilées sous 1024 px) : « Sources de téléchargement » et
   « Destinations » — choroplèthe (octets par pays, palette séquentielle), survol = pays, octets, nb d'hôtes ;
   à côté de chaque carte, top 5 pays en liste. Pays inconnu / adresses privées comptés à part (texte).
2. Carte « Répartition du trafic entre extrémités » : sélecteur Top 10 / 20 / 50, bascule « Inclure DNS »,
   légende des catégories (Privé, Public, Broadcast, Multicast, Link-local, Loopback).
   - ≥ 768 px : diagramme chord (d3-chord, SVG), max 15 nœuds affichés (au-delà de 15 : top 15 + « Autres »),
     libellés **à l'extérieur**, orientés radialement, tronqués à 18 caractères, sans chevauchement
     (espacement angulaire minimal ; libellés des arcs trop petits masqués et visibles au survol),
     survol d'un arc = mise en évidence de ses rubans + infobulle.
   - < 768 px : liste classée des paires avec barres.
3. Tableau des conversations : De (IP ou nom), Vers, Octets (total et par sens), Paquets, Flux, Protocoles, Durée,
   Première / dernière activité. Filtres texte dans l'en-tête de colonnes De/Vers.

## Améliorations par rapport à la référence

- Libellés du chord qui débordent et légende tronquée -> libellés gérés, légende complète.
- Cartes à points violets superposés -> choroplèthe + top pays.
- Ajout du sens du trafic et des protocoles dans le tableau.

## Critères d'acceptation

- Fixture avec 30 extrémités -> Top 10 cohérent avec le tri SQL (test API).
- Test visuel : aucun `text` du chord ne se chevauche à 768, 1280, 1920 px.
- `./x.sh shots connections` vert.
