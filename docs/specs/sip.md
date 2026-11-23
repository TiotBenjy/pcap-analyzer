# SIP

Tâche ROADMAP P5.6 (`feat/sip`, vague 5.A). Référence : `docs/reference/private/sip.png` (non publiée).

## Référence

La plateforme d'origine montre un histogramme « SIP Methods Usage » (une barre par méthode, abscisse
étiquetée par l'URI de l'émetteur en diagonale, échelle fractionnaire pour des comptes entiers), puis une
liste de paires source -> destination dont chaque ligne se déplie sur les messages bruts en police à
chasse fixe, en-têtes colorés. L'exemple est un balayage `friendly-scanner` (SIPVicious) : des `OPTIONS`
sans réponse. On reprend les **fonctionnalités** (méthodes, échanges par paire, messages bruts), pas le
graphique, et on ajoute ce que la référence n'a pas : appels et dialogues, enregistrements, user-agents
et scanners, flux RTP, identifiants.

## But

Répondre à « qui téléphone à qui sur ce réseau, avec quel équipement, les appels aboutissent-ils, qui
s'enregistre auprès de quel serveur, et le réseau est-il balayé par un outil d'attaque SIP ? ». SIP
(RFC 3261) signale les appels de la téléphonie IP ; son corps SDP (RFC 4566) annonce les adresses et
ports des flux RTP de la voix, sans qu'il soit besoin de lire l'audio.

## Données

### Parseur `netsift_dissect::sip` (pur, sans I/O, fuzzé)

- Message SIP texte (RFC 3261, section 7) : ligne de requête `<méthode> <URI> SIP/2.0` ou ligne de
  statut `SIP/2.0 <code> <raison>`, en-têtes, ligne vide, corps. Fins de ligne CRLF ou LF seul, lignes
  d'en-tête repliées (continuation par espace ou tabulation) rattachées à l'en-tête précédent, formes
  compactes (section 7.3.3 : `i` Call-ID, `f` From, `t` To, `m` Contact, `v` Via, `c` Content-Type,
  `l` Content-Length, `s` Subject, `k` Supported, `e` Content-Encoding) reconnues. Un contenu dont la
  première ligne n'est ni une requête ni un statut SIP n'est pas un message SIP (`None`).
- Bornes : 16 Kio lus par message (`MAX_PARSE`), 64 en-têtes au plus (au-delà, les suivants sont
  ignorés et le message est marqué `headers_truncated`), chaque champ extrait coupé à 512 octets
  (`MAX_FIELD`) sur une frontière de caractère, Call-ID à 256 octets, message brut conservé sur 4 096
  octets (`MAX_RAW`) : UTF-8 avec remplacement, fins de ligne en LF, caractères de contrôle autres que
  tabulation et LF, et caractères de mise en forme bidirectionnelle ou invisibles (U+200B à U+200F,
  U+202A à U+202E, U+2066 à U+2069, U+FEFF), remplacés par U+FFFD. Jamais interprété : l'UI l'affiche
  comme texte.
- Secrets masqués dans le brut, **avant stockage** (`redact_auth`) : dans la tête du message, la valeur
  des en-têtes `Authorization`, `Proxy-Authorization`, `WWW-Authenticate`, `Proxy-Authenticate` et
  `Authentication-Info`, lignes repliées comprises (rejointes à leur en-tête), est réécrite. Schéma
  `Digest` : `username`, `realm`, `uri`, `algorithm`, `qop`, `stale` et `domain` restent lisibles, toute
  autre valeur (`response`, `nonce`, `cnonce`, `opaque`, `nc`...) devient `<masked>`. `Basic`, schéma
  inconnu et `Authentication-Info` : toute la valeur devient `<masked>`. Ni le stockage, ni l'API, ni
  l'UI (affichage et copie) ne voient donc ces secrets ; les `Debug` des types qui portent le brut ne
  l'impriment jamais.
- Champs extraits : méthode ou code et raison, URI de requête, Call-ID, From et To (nom affiché, URI,
  `tag`), CSeq (numéro et méthode), `User-Agent`, `Server`, `Contact` (URI), premier `Via` (transport et
  émetteur), `Expires`, `Content-Type`, `Content-Length`, `Reason`, royaume du défi
  (`WWW-Authenticate` / `Proxy-Authenticate`), et l'en-tête `Authorization` / `Proxy-Authorization` de
  schéma `Digest` (RFC 3261 section 22, RFC 2617) : `username`, `realm`, `uri`, `algorithm`, `qop`.
- Découpage TCP (`message_len`) : fin des en-têtes puis `Content-Length` (absent = 0, section 18.3) ;
  au-delà de 64 Kio (`MAX_MESSAGE`) le message est refusé. Les battements de maintien CRLF
  (RFC 5626, section 4.4.1) entre deux messages sont sautés.
- SDP (`Content-Type: application/sdp`, corps borné à 8 Kio) : seules les lignes utiles sont lues,
  `c=` de session et de média (`IN IP4` / `IN IP6`, adresse ; une adresse multicast avec TTL garde
  l'adresse), `m=` (type de média, port, protocole, formats), `a=rtpmap:` (nom des codecs),
  `a=sendrecv` / `sendonly` / `recvonly` / `inactive`. Au plus 8 médias par corps SDP et 16 codecs
  par média (et 16 médias distincts par dialogue, `MAX_DIALOG_MEDIA`). Un
  port 0 (média refusé) est conservé mais jamais joint aux flux.

### Analyseur `sip` (`crates/netsift-analyze/src/sip/`)

- UDP : tout datagramme dont le port source **ou** destination est 5060 et qui est un message SIP
  (un datagramme = un message, section 18.1.1 ; le corps est coupé à `Content-Length`). Un datagramme
  qui n'est pas du SIP n'est pas enregistré (balayage de port brut : vue Connexions).
- TCP 5060 (l'un ou l'autre côté) : flux réassemblé découpé par `message_len`, tampon borné à 128 Kio
  par sens (un message de 64 Kio au plus et la suite) ; une livraison plus grande est lue par morceaux,
  les messages complets étant découpés après chaque morceau. Un sens est abandonné après un trou
  (`gap_before`), un contenu non SIP ou un message trop grand. SIP sur TLS (5061) n'est pas déchiffré : la session apparaît dans la vue TLS.
- Un enregistrement par message (`Record::Sip`), sans état partagé entre flux.
- Scanners : un `User-Agent` (ou `Server`) contenant le nom d'un outil de balayage SIP connu marque le
  message (`scanner`, nom canonique de l'outil) : `friendly-scanner`, `sipvicious` et `sipvicious_*`
  (SIPVicious), `sipsak`, `sipcli`, `sip-scan` / `sipscan`, `smap`, `iWar`, `sundayddr`,
  `VaxSIPUserAgent`. Indice, pas preuve : l'en-tête est déclaratif (un outil peut le changer, un
  logiciel légitime pourrait le reprendre) ; l'UI le dit.
- Identifiants : chaque requête portant `Authorization` ou `Proxy-Authorization: Digest` émet un
  `Record::Credential` de type `sip-digest`, état `metadata-only` : identifiant (`username`), domaine
  (`realm`), détails `method`, `uri`, `algorithm`, `qop`, `header`. Masqués par défaut comme tous les
  identifiants (vue Credentials). Au plus 128 par flux (`credentials::MAX_PER_FLOW`).
  La ligne de récupération hors ligne n'est **pas** produite par cette tâche (voir « Écarts »).

### Tables (migration `1300_sip.sql`, plage réservée 1300-1399)

- `sip_messages` : un enregistrement par message (`ts`, extrémités, `transport` `udp` / `tcp`,
  `flow_id`, `kind` `request` / `response`, `method` (méthode de la requête, ou méthode du CSeq pour une
  réponse), `status`, `reason`, `request_uri`, `call_id`, `from_name`, `from_uri`, `from_tag`,
  `to_name`, `to_uri`, `to_tag`, `cseq`, `user_agent`, `server`, `software` (`User-Agent`, sinon
  `Server`), `scanner`, `contact`, `via`, `expires`, `content_type`, `auth_user`, `auth_realm`,
  `challenge_realm`, `media` (JSON des médias SDP), `size`, `raw`, `raw_truncated`).
- `sip_dialogs` (étape de fin d'import `sip`) : un enregistrement par Call-ID. Les messages d'un même
  Call-ID passent par des flux et donc des shards différents (requête et réponse UDP sur des ports
  distincts, re-INVITE, BYE de l'autre côté) : le regroupement se fait après l'import, sur la table
  complète, en un parcours par l'index `(call_id, ts)` avec un départage total (`ts`, adresse et port
  source, CSeq, type, brut) : le résultat ne dépend ni de l'ordre d'arrivée ni du nombre de shards.
  Colonnes : `call_id`, `method` (`INVITE` si le dialogue en a un, sinon la méthode de la première
  requête), `first_ts`, `last_ts`, client et serveur (émetteur et destinataire de la première requête),
  `from_uri`, `from_name`, `to_uri`, `to_name`, `user_agent` (première valeur côté client),
  `server_agent` (première valeur côté serveur), `requests`, `responses`, `invite_ts`, `ringing_ts`
  (premier 180 / 183), `answer_ts` (premier 2xx à un INVITE), `bye_ts`, `cancelled` (CANCEL vu),
  `final_status` (INVITE : le premier 2xx, sinon la dernière réponse finale ; autres méthodes : la
  dernière réponse finale), `state`, `duration_ns`, `auth_user`, `challenged` (401 / 407 vu), `scanner`,
  `media_count`.
- `state` :
  - INVITE : `completed` (2xx puis BYE ; durée = BYE - 2xx), `answered` (2xx sans BYE ; durée = dernier
    message - 2xx, signalée « en cours ou fin non vue »), `cancelled` (CANCEL ou 487), `rejected`
    (réponse finale >= 300, y compris un 401 / 407 resté sans suite), `no-answer` (aucune réponse
    finale) ;
  - autres méthodes (REGISTER, OPTIONS, MESSAGE...) : `ok` (dernière réponse finale 2xx), `rejected`
    (>= 300), `no-answer`.
- `sip_media` (même étape) : un enregistrement par (dialogue, type de média, adresse, port) annoncé
  dans un SDP du dialogue : protocole, codecs, direction, émetteur de l'offre et heure de la première
  annonce, puis les flux UDP dont une extrémité est cette adresse et ce port, qui chevauchent
  `[première annonce, fin du dialogue + 10 s]` et qui ont commencé au plus 60 s (délai d'expiration des
  flux UDP) avant l'annonce : nombre de flux, paquets, octets, premier flux (plus petit identifiant).
  Aucune lecture du contenu RTP. Jointure linéaire en nombre de flux : extrémités distinctes dans une
  table temporaire, flux en destination par l'index `flows_service`, flux en source par un seul
  parcours de `flows` (une passerelle média peut émettre des centaines de milliers de flux d'une même
  adresse), puis agrégation par lectures d'index bornées.
- Index (différés pendant l'import, ADR-023, sauf ceux des tables remplies par l'étape) :
  `(ts)` pour la liste, `(call_id, ts)` pour l'étape et le filtre de dialogue, `(kind, method, ts)` et
  `(status, reason, ts)` pour les compteurs et filtres, `(software, scanner, ts)` pour les user-agents,
  `(scanner, src_ip, dst_ip, method, ts)` pour les scanners, `(src_ip, ts)` pour le filtre d'émetteur ;
  `sip_dialogs (first_ts, last_ts, method, state, duration_ns)` (ordre de la liste, chevauchement et
  compteurs sous plage, couvrant), `(method, first_ts)` (liste d'un type), `(method, state, duration_ns)`
  (compteurs sans plage, couvrant) ; `sip_media (dialog_id, ...)` (contrainte d'unicité).

### API (`crates/netsift-api/src/sip.rs`)

| Méthode | Route | Réponse |
|---|---|---|
| GET | `/sessions/{id}/sip/stats` | `SipStats` : `messages`, `requests`, `responses`, `dialogs`, `calls` et leur répartition par état, `registrations`, `scanner_messages`, `senders`, top 10 des méthodes (requêtes), des codes de réponse (avec une de leurs raisons, la plus petite), des user-agents (avec `scanner`) |
| GET | `/sessions/{id}/sip/dialogs?type=call\|register\|other&state=&q=&limit=&cursor=` | `Page<SipDialogInfo>` : dialogues par début croissant (keyset `(first_ts, id)`), avec leurs médias (au plus 8, une requête pour la page) ; `q` cherche dans le Call-ID, From, To, user-agent, identifiant |
| GET | `/sessions/{id}/sip/messages?kind=&method=&call_id=&src=&scanner=&q=&limit=&cursor=` | `Page<SipMessageInfo>` : messages par horodatage croissant (keyset `(ts, id)`), message brut compris ; `q` cherche dans le Call-ID, From, To, URI de requête et user-agent |
| GET | `/sessions/{id}/sip/scanners` | `Vec<SipScannerInfo>` : émetteurs marqués scanner (outil, adresse, messages, méthodes distinctes, cibles distinctes, première et dernière activité), au plus 50 |

Valeurs invalides (`type`, `state`, `kind`, `src`, `scanner`, curseur) : 400 problem+json.
`total_estimate` est le compte exact des lignes filtrées.

### Compteur de module

`MODULES` : `("sip", "sip_messages")` ; sous plage, `ModuleRows::Sip` = messages dont `ts` est dans la
plage (`scope: "range"`).

## Filtre temporel (ADR-030)

La vue est dans `timeFilterViews.ts` dès sa création ; ses routes passent par `ApiRange` et la
normalisation commune.

| Route | Règle |
|---|---|
| `/sip/messages` | *ponctuel(`ts`)* |
| `/sip/stats` | messages, méthodes, codes, user-agents, émetteurs sur les messages *ponctuel(`ts`)* ; `dialogs`, `calls`, états et `registrations` = dialogues qui *chevauchent(`first_ts`, `last_ts`)* |
| `/sip/dialogs` | dialogues qui *chevauchent(`first_ts`, `last_ts`)* ; compteurs de messages, état et durée **de la session** |
| `/sip/scanners` | messages *ponctuel(`ts`)* regroupés par émetteur |

Un dialogue est un élément replié : il est compté en entier s'il chevauche la plage, avec la mention
« session entière » sous l'en-tête de la colonne Messages (composant commun d'en-tête de colonne
repliée) et dans la carte mobile. Ses messages, eux, suivent la plage (bouton « Voir les messages »).

## Mise en page

Ordre des blocs (une colonne sous 768 px) :

1. En-tête : titre « SIP », sous-titre (nom de session), compteur de messages.
2. Bandeau de chiffres (`StatCard`, 2 colonnes sous `sm`, 3 jusqu'à `xl`, 6 au-delà) : Messages,
   Appels (indice « aboutis / échoués »), Durée cumulée des appels terminés, Enregistrements,
   User-agents, Messages de scanners.
3. Trois cartes de classement (`BarList`, grille auto-fit de 320 px minimum) : « Méthodes » (requêtes
   par méthode, à la place de l'histogramme de la référence), « Réponses » (codes avec leur raison
   standard), « User-agents » (mention « scanner » sur les outils). Un clic sur une méthode ou un
   user-agent filtre la liste des messages (pastille retirable).
4. Carte « Scanners » (absente sans scanner) : phrase d'explication (outil de balayage SIP, recherche
   d'extensions et de mots de passe faibles ; en-tête déclaratif), puis une ligne par émetteur : outil,
   `Endpoint`, messages, méthodes, cibles, première et dernière activité, bouton « Voir les messages ».
5. Carte « Appels et dialogues » : bande `filters` avec `SearchInput` et contrôle segmenté (Appels,
   Enregistrements, Autres ; liste déroulante sous 640 px). Liste dépliable paginée (rangées : début,
   From -> To, état en badge, statut final, durée, messages ; cartes empilées sous `md`). Détail :
   Call-ID (copie), client et serveur (`Endpoint`), étapes datées (INVITE, sonnerie, réponse, BYE ou
   CANCEL), user-agents des deux côtés, identifiant d'authentification, flux RTP associés (média,
   `Endpoint` adresse et port, codecs, direction, flux, paquets, octets ; « aucun flux observé » sinon),
   bouton « Voir les messages » (filtre la liste des messages sur le Call-ID et y fait défiler).
   Les enregistrements montrent l'AOR (To), le contact, le serveur, l'identifiant et le résultat.
6. Carte « Messages » : bande `filters` avec `SearchInput`, contrôle segmenté (Tous, Requêtes,
   Réponses), pastilles des filtres actifs (méthode, Call-ID, émetteur, user-agent, scanners). Liste
   paginée (`ExpandableList`, 200 lignes par page) : heure, badge (méthode, ou code et méthode du CSeq),
   source -> destination (`Endpoint`, port grisé), transport, Call-ID tronqué. Détail : message brut dans
   un bloc à chasse fixe défilable à l'intérieur, texte React échappé, bouton de copie, mention
   « tronqué à 4 096 octets » le cas échéant.

États : chargement (squelettes), erreur (réessayer), session en import ou en échec (`SessionGate`),
aucune donnée SIP (« Aucun message SIP »), plage vide (« Rien dans la plage » avec « Effacer la plage »).

## Améliorations par rapport à la référence

- Histogramme illisible remplacé par trois classements `BarList` (méthodes, réponses, user-agents).
- Appels reconstitués par Call-ID avec état, statut final et durée ; enregistrements ; flux RTP
  associés d'après le SDP ; scanners expliqués ; identifiants Digest dans Credentials.
- En-têtes non colorés, message brut en texte simple ; source et destination en `Endpoint`.
- Bouton flottant « To Details » supprimé.

## Écarts assumés

- Identifiants Digest en `metadata-only` : identifiant, domaine et URI, sans ligne de récupération hors
  ligne. À décider avec l'utilisateur dans une tâche à part (suivi).
- Pas de graphe d'échanges (« ladder diagram ») : les étapes datées du dialogue en tiennent lieu.
- SIP sur TLS (5061) et SIP sur WebSocket (RFC 7118) non analysés ; SIP sur un port autre que 5060
  non reconnu.
- Pas de lecture ni d'export audio du RTP (hors périmètre, ROADMAP).
- Les flux RTP joints sont comptés en entier : un flux UDP qui porte plusieurs appels (même adresse et
  même port réutilisés en moins de 60 s, délai d'expiration des flux UDP) est rattaché à chacun avec
  tous ses paquets.

## Critères d'acceptation

- Fixtures synthétiques `netsift_fixtures::sip` : appel complet (INVITE, 100, 180, 200 avec SDP, ACK,
  RTP dans les deux sens, BYE, 200), appel rejeté (486), appel annulé (CANCEL, 487), REGISTER avec défi
  401 puis Digest et 200, balayage `friendly-scanner` (OPTIONS sans réponse vers plusieurs adresses),
  appel sur TCP (messages coupés entre segments et deux messages dans un segment), message aux en-têtes
  surdimensionnés.
- Tests du parseur : requêtes, réponses, formes compactes, lignes repliées, LF seul, SDP, Digest,
  découpage TCP, malformés (binaire, première ligne invalide, `Content-Length` invalide), bornes.
- Tests de l'analyseur (snapshot `insta`), du store (étape `sip` : états, durées, médias joints) et
  test d'équivalence fichier unique / chunks avec 1, 4 et 7 shards sur les tables SIP.
- Tests d'API : compteurs égaux entre liste, `stats` et module, filtres, validation, plage ponctuelle
  et chevauchement, plage couvrant la session identique à sans plage, pages keyset sans doublon ni
  trou, snapshot `insta`.
- UI (Vitest) : rendu des blocs, segmenté des dialogues, dépliage d'un appel avec ses flux RTP, message
  brut échappé, pastilles de filtre, mention « session entière » sous plage.
- `./x.sh shots sip all`, `sip-range` (plage active) et `sip-call` (premier appel déplié) verts à 375,
  768, 1280 et 1920 px, en `en` et `fr`.
- Moins de 300 ms par requête sur une session synthétique volumineuse (mesure notée ci-dessous).

## Notes d'implémentation

- Parseur : `crates/netsift-dissect/src/sip.rs` (+ `sdp.rs`), fuzzé par la cible `udp_services` ;
  analyseur : `crates/netsift-analyze/src/sip/` ; store : `crates/netsift-store/src/sip.rs` (étape
  `sip`) ; API : `crates/netsift-api/src/sip.rs` ; UI : `ui/src/views/sip/`.
- Démonstration : `add_sip` dans `crates/netsift-cli/src/demo.rs` (vitrine puis un appel toutes les
  `SIP_EVERY_SECONDS`, et un renouvellement d'enregistrement un tour sur deux).
- Mesure (`sip::tests::timings`, ignoré, mode release, 1 M de messages et 325 000 flux UDP, machine de
  développement chargée) : `/sip/stats` 249 à 283 ms sur la session, 32 ms sur 1 h, 275 à 288 ms sur la
  moitié ; pages de messages 3 à 26 ms, d'appels 14 à 40 ms ; scanners 2 à 30 ms ; étape `sip` 8,3 à
  8,8 s, dont 1,6 s pour joindre 250 000 médias aux flux (`docs/PERFORMANCE.md`).
