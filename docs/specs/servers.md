# Servers

Référence : `docs/reference/servers.png`.

## But

Identifier les hôtes jouant un rôle d'infrastructure (DNS, DHCP, LDAP, et par extension NTP, Kerberos, SMB),
avec la preuve observée.

## Données

Déduit des analyseurs et des flux :
- DNS : IP ayant répondu à des requêtes DNS (depuis l'analyseur `dns`).
- DHCP : IP émettant des OFFER/ACK (UDP 67) — analyseur DHCP léger à ajouter dans `feat/servers`.
- LDAP : IP répondant sur 389/636 (depuis `ldap-parser`, déjà utilisé pour les binds).
- Extensions : NTP (123), Kerberos (88), SMB (445), serveur HTTP (bannières/headers `Server`).
`servers` : IP, rôle, preuve (type + nombre d'occurrences + premier/dernier ts), nom résolu, pays.
API : `/servers` groupé par rôle.

## Mise en page

Grille de cartes, une par rôle (DNS, DHCP, LDAP, NTP, Kerberos, SMB, HTTP) : titre avec icône lucide,
liste des IP (`Endpoint`, nom résolu, nb de preuves). Rôle sans donnée -> `EmptyState` « Aucun serveur <rôle> détecté »
(pas de carte « No Data » vide et muette comme la référence). Clic sur une IP -> future fiche hôte (copie d'ici là).

## Critères d'acceptation

- Fixture : un répondeur DNS, un serveur DHCP (OFFER/ACK) -> cartes DNS et DHCP peuplées, LDAP en état vide.
- `./x.sh shots servers` vert.
