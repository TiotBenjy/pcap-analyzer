# DNS

Références : `docs/reference/dns-1.png`, `docs/reference/dns-2.png`.

## But

Quels noms ont été résolus, par qui, auprès de quels serveurs, avec quels résultats ; repérer
NBNS/LLMNR/mDNS (indices d'environnement Windows, WPAD) et les échecs.

## Données

Analyseur `dns` (UDP/TCP 53, 5353 mDNS, 137 NBNS, 5355 LLMNR) :
- `dns_messages` : ts, flux, client, serveur, protocole (dns/mdns/nbns/llmnr), id, qname, qtype, opcode,
  rcode, flags, latence de réponse, réponses (JSON compact : type, valeur, TTL).
- Appariement requête/réponse par (5-tuple, id) avec fenêtre de 5 s en temps paquet ; requêtes sans réponse
  -> rcode `timeout`.
- Les réponses alimentent `hosts.names` (nom -> IP).
- NBNS : décodage des noms encodés (première partie, suffixe de type), requêtes de nom et enregistrements.

API : `/dns/stats` (par protocole, par rcode, par qtype, par pays du serveur), `/dns/servers` (avec géoloc),
`/dns/pairs` (client -> serveur -> liste de noms, paginé), `/dns/messages` (détail, paginé, recherche FTS).

## Mise en page

1. Rangée de 4 petits graphiques (grille `minmax(320px,1fr)`) :
   - Protocoles (donut : DNS, mDNS, NBNS, LLMNR) ;
   - Résultats (barres : NOERROR, NXDOMAIN, SERVFAIL, REFUSED, timeout...) ;
   - Types de requête (barres top 10 : A, AAAA, PTR, SRV, TXT...) ;
   - Pays des serveurs (barres top 10, drapeau SVG + nom).
2. Carte des serveurs DNS (choroplèthe légère + points proportionnels, survol = IP, nb requêtes).
3. Barre de filtres : bascules DNS / mDNS / NBNS / LLMNR / Erreurs uniquement (avec compteurs), recherche IP ou nom.
4. Tableau principal groupé : Client, Serveur (`Endpoint`), Protocole, Noms (5 premiers + « n de plus » dépliable),
   requêtes, erreurs. Ligne dépliée -> messages détaillés (heure, qname, qtype, rcode, réponses, latence).

## Améliorations par rapport à la référence

- Le graphe force-directed client/serveur illisible est remplacé par le tableau groupé et, en option,
  un diagramme de Sankey client -> serveur (≤ 20 liens, reste agrégé) ; pas de libellés superposés.
- Donuts sans ombre, légendes complètes ; ajout des types de requête et de la latence.

## Critères d'acceptation

- Fixture : 10 requêtes A, 1 NXDOMAIN, 1 sans réponse, 2 NBNS (dont WPAD), réponse dans le chunk suivant ->
  compteurs exacts, appariement correct à cheval sur deux chunks (test).
- Recherche « wpad » retrouve la requête NBNS.
- `./x.sh shots dns` vert.
