# Servers

Référence : `docs/reference/servers.png`.

## But

Identifier les hôtes jouant un rôle d'infrastructure (DNS, DHCP, LDAP, et par extension NTP, Kerberos, SMB),
avec la preuve observée.

## Données

Déduit des analyseurs et des flux, à la lecture (vue SQL `server_evidence`, ADR-017) :
- DNS : IP ayant répondu à des requêtes DNS unicast (analyseur `dns`), port 53 ouvert.
- DHCP : IP émettant des OFFER/ACK/NAK (analyseur `servers`, option 54 sinon l'émetteur).
- LDAP : port 389/636/3268/3269 ouvert (`open_ports`), cible d'un SRV `_ldap._tcp` / `_gc._tcp`.
- NTP : réponses mode 4 (strate, référence) ; Kerberos : réponses KDC (AS-REP, TGS-REP, KRB-ERROR,
  royaume), port 88 ouvert, SRV `_kerberos` ; SMB : sessions (`smb_sessions`) et annonces du service
  serveur ou de contrôleur de domaine (`smb_announces`) ; HTTP : réponses émises.
Preuve : type, nombre d'occurrences, clients distincts, premier/dernier ts, exemple.
API : `GET /sessions/{id}/servers?role=&category=&limit=` groupé par rôle (tous les rôles, top `limit`
par rôle et total), `analyzed: false` pour une session importée avant la vue.

## Mise en page

Grille de cartes, une par rôle (DNS, DHCP, LDAP, NTP, Kerberos, SMB, HTTP) : titre avec icône lucide,
liste des IP (`Endpoint`, nom résolu, nb de preuves). Rôle sans donnée -> `EmptyState` « Aucun serveur <rôle> détecté »
(pas de carte « No Data » vide et muette comme la référence). Clic sur une IP -> future fiche hôte (copie d'ici là).

## Critères d'acceptation

- Fixture : un répondeur DNS, un serveur DHCP (OFFER/ACK) -> cartes DNS et DHCP peuplées, LDAP en état vide.
- `./x.sh shots servers` vert.
