# Data Overview

Référence : `docs/reference/overview.png`.

## But

Vue d'ensemble d'une session : volume de trafic dans le temps par protocole, résumé, accès aux modules.

## Données / API

- `GET /api/v1/sessions/{id}/summary` : période, durée, paquets, octets, chunks, linktypes, hôtes, flux,
  anomalies, compteurs par module.
- `GET /api/v1/sessions/{id}/timeseries?from&to&points=1000&protocols=` : séries par protocole
  (octets et paquets), rééchantillonnées côté serveur (somme par bucket), ≤ 2 000 points.
- Protocoles de la série : DNS, HTTP, TLS, SMB, NetBIOS, SSH, QUIC, DHCP, SNMP, 802.11 mgmt, Other TCP,
  Other UDP, Other. Couleurs fixes (palette centrale).

## Mise en page

1. Bandeau résumé (grille de `StatCard`) : durée capturée, paquets, volume, hôtes, flux, chunks (+ anomalies).
2. Carte « Trafic par protocole » :
   - contrôles : échelle Linéaire / Log (bascule), métrique Octets / Paquets, sélecteur multi-protocoles
     (avec Tout / Aucun), réinitialiser le zoom ;
   - aires empilées, axe Y en unités IEC, axe X horodaté (format adapté à la durée), brush de zoom
     (dataZoom inside + slider fin) ; infobulle listant les protocoles du bucket triés par valeur ;
   - sous 640 px : légende masquée au profit du sélecteur, hauteur 240 px.
3. Grille des modules (1/2/3/4 colonnes) : une carte par onglet (icône lucide, titre, description d'une ligne,
   compteur). Compteur à 0 -> carte estompée et non cliquable. Les onglets de phase 5 n'apparaissent pas tant
   qu'ils ne sont pas implémentés.

## Améliorations par rapport à la référence

- Pas d'emoji dans le libellé « View » ; pas de carte vide « 0 » cliquable.
- Ajout du bandeau résumé et du choix octets/paquets.
- Zoom temporel (préparation du filtre global de phase 5).

## Critères d'acceptation

- Fixture mixte (DNS, HTTP, TLS) : les trois protocoles apparaissent avec les bons totaux (test API).
- Session de 24 h simulée : la série renvoie ≤ 2 000 points (test API) et s'affiche en < 500 ms.
- `./x.sh shots overview` vert aux 4 largeurs, clair et sombre.

## Notes d'implémentation (P2.4)

- Routes : `crates/netsift-api/src/overview.rs`, requêtes : `crates/netsift-store/src/traffic.rs`.
  `timeseries?from_us&to_us&points&metric&protocols` : `points` vaut 1000 par défaut, borné à 1..=2000 ;
  intervalles « ronds » (1 s, 2 s, 5 s ... 1 min, 2 min ... 1 h ... jours) alignés sur l'horloge ;
  `metric=bytes|packets` omet l'autre mesure ; `protocols=` vide = aucun ; 409 pendant l'import ou après échec.
- Les libellés stockés (`timeseries.proto`, classification par port du core) sont repliés dans les séries
  de la spec : `ftp`, `imap`, `ldap`, `pop3`, `rdp`, `smtp`, `telnet`, `tcp` -> Other TCP ; `ntp`, `sip`,
  `ssdp`, `syslog`, `udp` -> Other UDP ; `kerberos`, `icmp`, `ip`, `non_ip` et libellés inconnus -> Other.
  QUIC et 802.11 mgmt n'apparaîtront que lorsque le core produira ces libellés.
- Compteurs de modules : registre `MODULES` (une ligne triée par module, `(id de vue, table)`), présent
  seulement si la table existe dans la session. Aujourd'hui : `connections` (flows) et `hosts`.
- L'UI demande 500 points (200 sous 640 px) ; zoom côté client (dataZoom) sur la série chargée.
