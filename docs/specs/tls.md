# SSL/TLS

Références : `docs/reference/tls-1.png`, `docs/reference/tls-2.png`.

## But

Inventorier les sessions TLS : versions, suites, SNI, empreintes client, certificats et leurs faiblesses.

## Données

Analyseur `tls` (détection par contenu sur flux TCP réassemblé ; DTLS plus tard) via `tls-parser` + `x509-parser` :
- `tls_sessions` : flux, client, serveur, ts, version proposée / négociée (supported_versions inclus),
  suite négociée, SNI, ALPN proposés / retenu, JA3 + hash, JA4 (client, TLS uniquement), compression,
  extensions (liste), résumption, alerte éventuelle, issue (handshake complet / partiel).
- `tls_client_hellos` / `tls_server_hellos` : détail brut décodé (suites, groupes, sigalgs, extensions).
- `tls_certificates` : SHA-256 (DER dans `objects`), sujet, émetteur, SAN, validité, algorithme de clé et taille,
  algorithme de signature, auto-signé, expiré à la date de capture, CA, position dans la chaîne.
- TLS 1.3 : certificats chiffrés -> marqué « non visible », pas d'erreur.

API : `/tls/stats` (versions, suites top 15, matrice version x suite, SNI top), `/tls/sessions` (paginé, filtres
version/suite/SNI/serveur), `/tls/sessions/{id}`, `/tls/certificates` (+ téléchargement DER/PEM).

## Mise en page

1. Rangée : Versions (donut), Suites de chiffrement (barres horizontales top 15 + Autres, suites faibles —
   RC4, 3DES, NULL, EXPORT, CBC-SHA1 — signalées par une pastille ambre dans le libellé).
2. Heatmap « Version x Suite » (remplace le nuage de bulles de la référence).
3. Barre de filtres : version, suite, SNI/serveur (recherche), « faibles uniquement », « certificats problématiques ».
4. Tableau des sessions : client `Endpoint`, serveur `Endpoint` + SNI, version (badge), suite, ALPN, JA3/JA4 (mono,
   copiable), certificat (CN + badge expiré/auto-signé). Ligne dépliée : onglets Aperçu, Client Hello,
   Server Hello, Certificats (n) — chaîne affichée en liste avec champs clés et boutons DER/PEM.
5. Onglet secondaire « Certificats » : liste unique dédupliquée par SHA-256 avec nombre de sessions.

## Améliorations par rapport à la référence

- Liste de cartes très hautes (une session = un écran) -> tableau dense avec détail dépliable.
- Ajout SNI, ALPN, JA3/JA4, détection de faiblesses, vue certificats dédupliquée.

## Critères d'acceptation

- Fixture : TLS 1.2 avec certificat auto-signé expiré, TLS 1.3 avec SNI et ALPN h2 -> champs exacts, JA3 conforme
  à une valeur de référence calculée à la main dans le test.
- ClientHello fragmenté sur deux segments TCP et à cheval sur deux chunks -> correctement analysé.
- `./x.sh shots tls` vert.
