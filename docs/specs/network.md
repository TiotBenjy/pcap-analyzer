# Network (carte des communications)

Référence : `docs/reference/network.png`.

## But

Visualiser les hôtes et leurs communications, filtrables par protocole, pour comprendre la topologie observée.

## Données

Noeuds = hôtes (`hosts`), arêtes = conversations (`flows` agrégés) avec protocoles applicatifs et volumes.
Classification et pays via `netsift-geo`.
API : `/network/graph?protocols=&include_orphans=&resolve_dns=&aggregate_country=` -> `{ nodes, edges }`
déjà **bornés et agrégés** côté serveur (voir ci-dessous) ; `/network/node/{ip}` pour le panneau de détail.

## Rendu (sigma.js + graphology)

- ForceAtlas2 dans un Web Worker, figé après convergence ; `nodeReducer`/`edgeReducer` pour le thème et le survol.
- Catégories de nœud (couleur + forme, légende fixe) : LAN, Serveur, Public, Broadcast, Multicast, Link-local,
  Loopback. Taille de nœud bornée (4–18 px) selon le volume (échelle log).
- **Libellés** : jamais tous affichés. Seuls les nœuds importants (degré ou volume) au repos
  (`labelRenderedSizeThreshold`, `labelDensity` réglés), tous les libellés au survol/voisinage, recherche qui
  centre et surligne. C'est la correction directe du principal défaut de la référence (libellés empilés illisibles).
- **Agrégation** : au-delà de 150 nœuds publics, regroupement par pays en un nœud cluster dépliable
  (double-clic). Les nœuds orphelins (aucune arête après filtrage) masqués par défaut (bascule « Masquer les
  orphelins » comme la référence).
- Arêtes fines, semi-transparentes, épaisseur bornée selon le volume.

## Contrôles (barre supérieure, `flex-wrap`)

Bascules de protocole avec compteurs : DNS, HTTP, HTTPS, SSH, FTP, Telnet, RDP, SMB, TCP, UDP, Autres ;
Tout activer / Tout désactiver ; Masquer les orphelins ; Résoudre les noms DNS ; Afficher IPv6 ;
Exporter (PNG/SVG) ; recherche IP ou nom. Sous 768 px, les bascules passent dans un menu « Filtres ».

## Panneau de détail (clic sur un nœud)

IP, MAC(s), noms (DNS/NBNS/DHCP), catégorie, pays, ports ouverts, protocoles, octets entrants/sortants,
nb de pairs, premier/dernier vu ; liens vers les autres onglets filtrés sur cet hôte.

## Critères d'acceptation

- Fixture de 200 hôtes publics -> agrégation par pays active, ≤ ~60 nœuds rendus par défaut (test API : le graphe
  renvoyé est borné).
- Aucun chevauchement de libellés au repos (seuls quelques libellés affichés) — vérifié visuellement par `ui-reviewer`.
- Filtrer sur HTTPS ne laisse que les hôtes concernés ; « Masquer les orphelins » retire les nœuds isolés.
- `./x.sh shots network` vert (pas de débordement ; le canvas sigma occupe la zone sans pousser la page).
