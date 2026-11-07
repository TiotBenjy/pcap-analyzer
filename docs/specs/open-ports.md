# Open Ports

Référence : `docs/reference/open-ports.png`.

## But

Identifier les services en écoute observés dans la capture (pas de scan actif).

## Données

Dérivé des flux : port TCP ouvert = SYN-ACK observé depuis ce port (ou données serveur sur un flux établi
dont le début est hors capture) ; port UDP « répondant » = réponse depuis ce port à une requête.
`open_ports` : hôte, proto, port, service IANA (table embarquée générée depuis le registre IANA, CSV dans
`crates/netsift-analyze/data/`), service détecté par contenu (http, tls, ssh, smb...), nb de clients, premier/dernier ts,
bannière éventuelle (SSH, FTP, SMTP, ≤ 256 octets).
API : `/ports/stats` (top ports par nb d'hôtes), `/ports` (groupé par hôte, filtres catégorie/port/service/texte).

## Mise en page

1. Bascules : Privé, Public, afficher les noms DNS (comme la référence) + recherche hôte ou port.
2. Graphique « Ports les plus exposés » : barres horizontales (port/service -> nombre d'hôtes), top 15.
   Remplace la grande zone vide de la référence.
3. Tableau groupé par hôte : Hôte (`Endpoint`, nom résolu), Ports (badges `443 https`, `1863 msnp`, port seul si
   inconnu ; badge ambre si le service détecté diffère du service IANA), nb clients, bannière (dépliable).

## Critères d'acceptation

- Fixture : SYN-ACK sur 80/443, RST sur 22 (fermé -> absent), réponse UDP 53 -> exactement 3 entrées.
- `./x.sh shots open-ports` vert.
