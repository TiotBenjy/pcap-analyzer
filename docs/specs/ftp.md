# FTP

Tâche ROADMAP P5.8 (`feat/ftp`, vague 5.B). Référence : `docs/reference/private/ftp.png` (non publiée).
Décision structurante : ADR-032 (association du canal de données au contrôle).

## Référence

La plateforme d'origine liste les sessions de contrôle sous forme de rangées « client -> serveur »
dépliables. Une rangée dépliée montre la transcription brute en police à chasse fixe sur fond sombre :
codes de réponse et arguments des commandes en couleur, verbes en gras, et le mot de passe de `PASS`
**en clair**. Aucune information sur la session repliée (utilisateur, nombre de fichiers, durée), aucun
lien vers les fichiers transférés, aucune indication du canal de données ni du résultat du transfert.
On reprend les **fonctionnalités** (une session = une transcription dépliable, arguments mis en
évidence), pas le style (grand aplat sombre, rangées sans contenu, secret affiché).

## But

Répondre à « qui s'est connecté à quel serveur FTP, avec quel compte, qu'a-t-il fait, et quels fichiers
ont été téléchargés ou déposés ? ». FTP (RFC 959) transporte commandes, identifiants et fichiers en clair :
la transcription montre l'activité, les fichiers sont extraits comme objets de la session.

## Données

### Parseur (`crates/netsift-dissect/src/ftp.rs`)

Fonctions pures, sans I/O, sans panique, fuzzées (cible `lineproto`) :

- commande : verbe de 1 à 8 caractères ASCII alphanumériques (insensible à la casse, mis en
  majuscules), puis argument après une espace ; une ligne qui ne commence pas par un verbe valide reste
  un texte sans verbe ;
- réponse : code à 3 chiffres (premier chiffre 1 à 5) suivi d'une espace (dernière ligne) ou d'un tiret
  (début d'une réponse multiligne, RFC 959 4.2) ; les lignes intermédiaires d'une réponse multiligne
  sont du texte, la réponse se termine à la ligne « même code + espace » ;
- adresses du canal de données : argument de `PORT` (`h1,h2,h3,h4,p1,p2`), réponse `227` (six nombres
  n'importe où dans le texte, entre parenthèses ou non), argument d'`EPRT` (`|1|ipv4|port|`,
  `|2|ipv6|port|`, délimiteur quelconque ASCII 33-126, RFC 2428) et réponse `229`
  (`(|||port|)`, RFC 2428). Chaque nombre est borné (0-255, port 1-65535) ; un argument hors de ces
  formes est ignoré (pas d'attente de canal).

`LPRT` / `LPSV` (RFC 1639) ne sont pas reconnus.

### Analyseur `ftp` (`crates/netsift-analyze/src/ftp/`)

- **Sessions de contrôle** : flux TCP dont le port serveur est 21 (aussi un flux pris en cours dont le
  côté client vu est le port 21). Port non standard : non reconnu (limite). FTPS implicite (990) : vu
  comme TLS par l'onglet TLS.
- **Transcription** : lignes de chaque sens découpées sur `\n` (`\r` retiré), texte UTF-8 avec
  remplacement, caractères de contrôle et caractères de mise en forme invisibles ou bidirectionnels
  (U+200B-U+200F, U+202A-U+202E, U+2066-U+2069, U+FEFF) remplacés par U+FFFD. Bornes : 1 024 octets de
  texte gardés par ligne (au-delà, ligne marquée tronquée et suite ignorée jusqu'à la fin de ligne),
  2 000 lignes et 256 Kio par session ; au-delà, les compteurs continuent et la session est marquée
  « transcription tronquée ». Les lignes sont émises au fil de l'eau (pas de transcription en mémoire).
- **Secrets** : l'argument de `PASS` et d'`ACCT` est stocké avec `secret = 1` ; l'API le sert dans la
  transcription d'une session (route de détail), l'UI le masque par défaut (`SecretValue`), comme le
  détail d'un identifiant. `Debug` des enregistrements le remplace par `<redacted>` : il n'apparaît dans
  aucun log. L'identifiant lui-même (USER/PASS, résultat) reste émis par l'analyseur `credentials`
  (`credentials/lineproto.rs`, inchangé) : la session FTP porte l'utilisateur et le résultat de la
  connexion (`230` acceptée, `530` refusée), l'onglet Credentials garde le secret replié.
- **AUTH TLS / AUTH SSL** : une réponse `234` à `AUTH` ajoute une note « suite chiffrée » à la
  transcription, marque la session `tls` et arrête l'analyse des deux sens (la suite est du TLS).
- **Perte de données** (`gap_before`) : note « octets manquants » dans la transcription, ligne en cours
  abandonnée.
- **Réponses et commandes** : file des commandes en attente de leur réponse définitive (au plus 32) ;
  une réponse `1xx` est préliminaire, toute autre réponse termine la commande la plus ancienne (ordre
  RFC 959, pipelinage toléré, `ABOR` : la `426` termine le transfert, la `226` suivante l'`ABOR`).
- **Canal de données** (ADR-032) : `PORT` / `EPRT` (actif) et réponses `227` / `229` (passif) donnent
  l'adresse attendue du flux de données. Un flux TCP du même shard est associé au contrôle si son
  extrémité répondante est cette adresse, ou à défaut si son port est le port attendu et qu'il relie les
  deux mêmes adresses que le contrôle (NAT : `227` annonçant une adresse interne) ; il doit avoir été
  créé après la commande qui a demandé le canal (`FlowId` = index de trame, ADR-022). La première
  correspondance consomme l'attente. Le flux est rattaché au transfert en cours, ou au suivant si le
  client ouvre le canal avant d'envoyer `RETR` (mode passif).
- **Transferts** : commandes `RETR` (téléchargement), `STOR`, `STOU`, `APPE` (dépôt), `LIST`, `NLST`,
  `MLSD` (listage). Pour chacun : horodatage de la commande, chemin tel qu'envoyé (borné à 1 024
  octets), sens, mode (actif / passif), flux de données, octets reçus sur le canal, réponse définitive
  (`226`, `250`, `426`, `451`, `550`...), décalage `REST` éventuel, drapeau `truncated` (octets
  manquants dans le flux de données, ou plus de 64 Mio). Un transfert est émis quand sa réponse
  définitive et la fin de son flux de données sont vues, sinon à la fin du contrôle ou de la capture.
  Au plus 1 000 transferts par session (au-delà : comptés, non listés).
- **Fichiers** : le contenu d'un dépôt ou d'un téléchargement est stocké comme objet
  (`RecordSink::put_object`, blobs SHA-256 dédupliqués, budget de session) si la réponse est `2xx`,
  le flux de données vu sans perte, sans `REST` non nul, entre 1 octet et 64 Mio (borne des objets,
  `ARCHITECTURE.md`). Le type est détecté par le contenu (signatures des objets HTTP, sinon
  `application/octet-stream`). Un transfert interrompu (`426`) ou tronqué garde ses métadonnées sans
  contenu, comme une réponse HTTP incomplète. Les données sont tenues en mémoire pendant le transfert,
  dans un budget de 128 Mio partagé par tous les shards ; au-delà, le transfert est compté sans
  contenu (`truncated`). En mode ASCII (`TYPE A`), le contenu est stocké tel que transmis (fins de
  ligne CRLF).
- **Listages** : les 4 Kio premiers octets de la réponse d'un `LIST` / `NLST` / `MLSD`, nettoyés comme
  la transcription, sont gardés en texte (jamais un objet).
- Bornes par shard : 4 096 sessions de contrôle et 1 024 flux de données suivis en même temps ; au-delà,
  les nouveaux ne sont pas analysés (le résultat ne dépend alors du nombre de shards que parce qu'une
  borne est atteinte, comme ADR-023).

### Tables (migration `1400_ftp.sql`, plage réservée 1400-1499)

- `ftp_sessions` : une ligne par contrôle (`flow_id` = flux de contrôle), extrémités, `first_ts`,
  `last_ts`, bannière `220`, utilisateur (dernier `USER`), `login` (`accepted`, `rejected`, NULL),
  `tls`, compteurs `commands`, `replies`, `files` (dépôts et téléchargements), `listings`, `bytes`
  (octets de données des transferts), `lines` (lignes stockées), `transcript_truncated`, `gaps`.
- `ftp_lines` : transcription, clé `(flow_id, seq)` : `ts`, `dir` (`c` commande, `s` réponse, `n`
  note), `head` (verbe, ou code suivi de son séparateur `230` / `230-`, NULL pour une ligne de
  continuation), `text` (argument ou texte de la réponse, ou nature de la note : `tls`, `gap`),
  `secret`, `truncated`.
- `ftp_transfers` : un transfert par ligne, clé `(flow_id, seq)` et `id` de pagination : `ts`, `end_ts`,
  `command`, `path`, `direction` (`download`, `upload`, `listing`), `mode` (`active`, `passive`, NULL),
  `data_flow_id`, `status`, `status_text`, `bytes`, `restart_offset`, `truncated`, `sha256`, `mime`,
  `listing`.
- `objects.source` (`http` ou `ftp`, colonne ajoutée par la même migration) ; l'étape de fin d'import
  `objects` réunit les corps HTTP et les fichiers FTP (première occurrence = plus petit
  `(ts, flow_id, seq)`, `uri` = chemin FTP, `host` NULL, `flow_id` / `seq` = contrôle et transfert) :
  Pictures montre les images reçues ou déposées par FTP, Documents (P5.11) les autres.
- Toutes les lignes sont écrites une fois par le shard du contrôle (`INSERT ... ON CONFLICT DO NOTHING`
  pour les rejeux) : le contenu ne dépend ni de l'ordre d'arrivée ni du nombre de shards.
- Index (différés pendant l'import, ADR-023) : `ftp_sessions (first_ts, last_ts)` (liste et plage),
  `ftp_transfers (ts)`, `(flow_id, seq)` (clé), `(sha256, ts)` (objets sous plage), `(direction, ts)`.

### API (`crates/netsift-api/src/ftp.rs`)

| Méthode | Route | Réponse |
|---|---|---|
| GET | `/sessions/{id}/ftp/stats` | `FtpStats` : sessions, serveurs, clients, utilisateurs distincts, connexions acceptées / refusées, sessions TLS, transferts, téléchargements, dépôts, listages, transferts en échec, octets |
| GET | `/sessions/{id}/ftp/sessions?q=&login=&limit=&cursor=` | `Page<FtpSessionInfo>` par début croissant (keyset `(first_ts, flow_id)`) ; `q` cherche dans les adresses, l'utilisateur et la bannière ; `login` = `accepted`, `rejected`, `none` |
| GET | `/sessions/{id}/ftp/sessions/{flow}` | `FtpSessionDetail` : la session, ses lignes (au plus 2 000, secret compris) et ses transferts |
| GET | `/sessions/{id}/ftp/transfers?direction=&q=&session=&limit=&cursor=` | `Page<FtpTransferInfo>` par horodatage croissant (keyset `(ts, id)`) ; `q` cherche dans le chemin ; `session` = flux de contrôle |

Aucune liste ne sert de secret : seule la route de détail d'une session le contient. Valeurs invalides
de `login` / `direction` / `session` : 400 problem+json. Session inconnue : 404.

### Compteur de module

`MODULES` : `("ftp", "ftp_sessions")` ; sous plage, `ModuleRows::FtpSessions` = sessions qui chevauchent
la plage. `ModuleRows::Pictures` compte aussi les images déposées ou reçues par FTP dans la plage.

## Filtre temporel (ADR-030)

| Route | Règle |
|---|---|
| `/ftp/sessions` | *chevauche(`first_ts`, `last_ts`)* ; compteurs de commandes, fichiers, octets **de la session** (mention « session entière » sous plage) |
| `/ftp/transfers` | *ponctuel(`ts`)* (commande de transfert) |
| `/ftp/stats` | sessions, serveurs, clients, utilisateurs, connexions, TLS : sessions qui *chevauchent* ; transferts et octets : transferts *ponctuels* |
| `/ftp/sessions/{flow}` | non filtrée : détail par identifiant |
| `/objects`, `/objects/stats` | un objet est dans la plage si une transaction HTTP **ou un transfert FTP** de la plage le porte |

## Mise en page

Ordre des blocs (une colonne sous 768 px) :

1. En-tête : titre « FTP », sous-titre (nom de session), compteur de sessions.
2. Bandeau de chiffres (`StatCard`) : Sessions, Connexions acceptées (indice : refusées), Fichiers
   (indice : téléchargés / déposés), Octets transférés, Sessions TLS.
3. Carte « Sessions » : bande `filters` avec `SearchInput` et contrôle segmenté de connexion (Toutes,
   Acceptées, Refusées, Sans connexion). Liste dépliable (`ExpandableList`) : rangée = client ->
   serveur (`Endpoint`, port grisé), utilisateur, badge de connexion (Acceptée, Refusée, TLS), commandes,
   fichiers, durée, début (`Timestamp`) ; cartes empilées sous `md`. Sous plage, les colonnes de
   compteurs portent l'en-tête de colonne repliée « session entière ».
   Détail déplié : bannière, utilisateur avec lien « Voir dans Credentials », transcription dans un
   bloc à chasse fixe (fond `subtle`, pas d'aplat sombre), défilant à l'intérieur du bloc : une ligne
   par commande ou réponse, verbe en gras, argument en couleur d'accent, code de réponse en gris
   (rouge pour `4xx` / `5xx`), argument de `PASS` en `SecretValue`, notes (`suite chiffrée`,
   `octets manquants`, `transcription tronquée`) en italique ; liste des transferts de la session.
4. Carte « Fichiers transférés » : bande `filters` avec `SearchInput` et contrôle segmenté du sens (Tous,
   Téléchargés, Déposés, Listages). Tableau (`DataTable`, cartes sous `md`) : heure, sens (badge),
   chemin (mono, troncature au milieu), taille, statut (code et libellé : Terminé, Interrompu, Échec,
   Sans réponse ; Tronqué), client -> serveur, action : « Voir dans Pictures » pour une image stockée,
   « Télécharger » (pièce jointe, ADR-016) pour tout autre fichier stocké, rien sinon. Un listage se
   déplie sur son texte (bloc à chasse fixe, échappé).

États : chargement (squelettes), erreur (réessayer), session en import ou en échec (`SessionGate`),
aucune session FTP (« Aucune session FTP »), plage vide (état vide commun « Rien dans la plage »).

## Améliorations par rapport à la référence

- Rangée repliée informative (utilisateur, connexion, compteurs, durée) au lieu d'un simple couple
  d'adresses.
- `PASS` masqué par défaut, révélable et copiable comme dans Credentials.
- Canal de données associé : chaque transfert a un sens, une taille, un statut et, s'il est complet,
  son fichier téléchargeable ou visible dans Pictures.
- AUTH TLS et pertes de capture signalées dans la transcription.
- Pas de grand aplat sombre : bloc de code au fond neutre du thème, lisible en clair et en sombre.

## Critères d'acceptation

- Fixtures `netsift_fixtures::ftp` : session passive (`PASV`) avec `RETR` d'une image et `STOR` d'un
  fichier texte, session active (`PORT`, données depuis le port 20) avec `LIST`, session `EPSV` en IPv6,
  échec de connexion (`530`), transfert interrompu (`426`), `AUTH TLS` accepté.
- Tests du parseur (commandes, réponses multilignes, `PORT` / `227` / `EPRT` / `229` valides et
  malformés, bornes), de l'analyseur (snapshot `insta` des enregistrements, secret absent de `Debug`,
  bornes de transcription), du store (pages, plage, objets FTP dans `objects`) et de l'API (compteurs,
  filtres, validation, plage, détail, aucune liste avec secret, snapshot `insta`).
- Test d'équivalence : fichier unique et chunks, 1, 4 et 7 shards, tables FTP et objets identiques.
- UI (Vitest) : rendu, dépliage de la transcription avec `PASS` masqué, liens des fichiers.
- `./x.sh shots ftp` vert à 375, 768, 1280 et 1920 px, en `en` et `fr`.
- Moins de 300 ms par requête (mesure sur une session synthétique volumineuse, notée ci-dessous).

## Notes d'implémentation

(Complétées à la fin de la tâche : mesures, écarts.)
