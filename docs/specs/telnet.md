# Telnet

Tâche ROADMAP P5.9 (`feat/telnet`, vague 5.B). Référence : `docs/reference/private/telnet.png` (non publiée).

## Référence

La plateforme d'origine montre, pour chaque connexion Telnet, un titre `client -> serveur:23` repliable
et, dessous, un grand bloc noir à chasse fixe avec la transcription de la session : bannière, invite
`login:` suivie du nom saisi, invite `Password:` suivie du **mot de passe en clair**, puis les commandes
tapées et leur sortie. La négociation d'options est invisible, les échos du serveur ne sont pas doublés.
On reprend les **fonctionnalités** (une transcription lisible par session, l'identifiant saisi), pas le
style (bloc noir pleine largeur, mot de passe affiché, aucune métadonnée de session).

## But

Répondre à « qui s'est connecté en Telnet, à quel équipement, avec quel compte, et qu'a-t-il tapé ? ».
Telnet (RFC 854) transporte la frappe et les mots de passe en clair : chaque session est une preuve
d'usage d'un protocole à remplacer (SSH) et un journal de ce qui a été fait sur l'équipement.

## Données

### Décodage Telnet (`crates/netsift-dissect/src/telnet.rs`)

Parseur pur, sans I/O, incrémental (un état par sens, alimenté segment par segment) et fuzzé
(cible `telnet`). D'après RFC 854 (NVT, IAC), RFC 855 (sous-négociation) et les RFC des options :

- `IAC IAC` -> octet de données `0xFF` ;
- `IAC WILL|WONT|DO|DONT <option>` -> négociation ;
- `IAC SB <option> ... IAC SE` -> sous-négociation : contenu dé-échappé (`IAC IAC`), borné à
  512 octets (au-delà : indicateur `truncated`, la suite est ignorée jusqu'à `IAC SE`). Une
  sous-négociation sans `IAC SE` est abandonnée après 4 096 octets : le reste redevient des données
  (un flux cassé ne masque pas toute la session). `IAC` suivi d'autre chose que `IAC` ou `SE` dans une
  sous-négociation la termine (écart à la RFC toléré) ;
- autres commandes (`EC`, `EL`, `AYT`, `GA`, `NOP`, `IP`, `BRK`, `AO`, `DM`, `EOR`) signalées ;
- toute séquence peut être coupée entre deux segments ; un trou de réassemblage remet l'état à zéro.

Décodage des sous-négociations courantes : `TTYPE IS <nom>` (RFC 1091, nom borné à 64 caractères),
`NAWS <largeur> <hauteur>` (RFC 1073), `NEW-ENVIRON IS|INFO` (RFC 1572 : `VAR` / `USERVAR`, `VALUE`,
`ESC` ; au plus 32 variables, noms et valeurs bornés à 128 caractères), `LINEMODE` (RFC 1184, option
notée sans décoder ses modes). Noms d'options connus : BINARY, ECHO, SGA, STATUS, TIMING-MARK, TTYPE,
EOR, NAWS, TSPEED, LFLOW, LINEMODE, XDISPLOC, ENVIRON, AUTHENTICATION, ENCRYPT, NEW-ENVIRON ; les autres
sont notés par leur numéro.

### Analyseur `telnet` (`crates/netsift-analyze/src/telnet/`)

Connexions TCP dont le port serveur (ou client, pour une connexion prise en cours) est **23** ou
**2323**. Un enregistrement par connexion qui a porté des données, émis à la fin du flux.

**Transcription** : les deux sens entrelacés dans l'ordre d'arrivée des données réassemblées, en
« runs » successifs étiquetés `client`, `server` ou `secret`.

- Fins de ligne : `CR LF`, `CR NUL`, `CR` seul et `LF` seul -> une fin de ligne.
- Séquences ANSI/VT retirées (CSI `ESC [ ... final`, OSC `ESC ] ... BEL|ST`, chaînes DCS/PM/APC,
  échappements à deux octets), bornées (au-delà de 256 octets, l'état revient au texte).
- Caractères de contrôle : retour arrière (`BS`, `DEL`, `IAC EC`) efface le dernier caractère de la
  ligne courante ; `^U` et `IAC EL` effacent la saisie du client sur la ligne ; `^W` efface le dernier
  mot saisi ; tabulation conservée ; les autres contrôles envoyés par le client sont rendus en notation
  `^C`, `^D`... ; ceux du serveur (cloche, `NUL`, `SI`/`SO`...) sont retirés.
- Échos fusionnés : chaque caractère (ou fin de ligne, ou effacement) tapé par le client est attendu en
  écho ; les octets du serveur qui reproduisent cette attente dans l'ordre (y compris `BS espace BS`
  pour un effacement) sont absorbés au lieu d'être affichés une seconde fois. Au premier octet du
  serveur qui diffère, l'attente est vidée (le serveur n'écho pas, ou affiche autre chose). File
  d'attente bornée à 512 éléments.
- Bornes par session : 64 Kio de texte et 2 000 lignes (et 8 192 runs) ; au-delà, la transcription
  s'arrête et l'indicateur `truncated` est posé (la détection des identifiants continue). Budget de
  32 Mio de transcriptions en cours par shard : chaque session y impute la plus grande taille atteinte
  par son texte (au plus 64 Kio), si bien qu'un texte effacé puis retapé (indicateur de progression
  `|/-\`) ne coûte rien de plus ; au-delà, les nouvelles données ne sont plus transcrites (`truncated`).

**Options négociées** : une option est « active » si un côté l'a proposée (`WILL`) et l'autre acceptée
(`DO`), dans un ordre quelconque. Résumé enregistré : liste des options actives, type de terminal
(premier `TTYPE IS` du client), taille de fenêtre (dernier `NAWS` du client), variable `USER` de
`NEW-ENVIRON` (envoyée par le client, ouverture de session automatique de `telnet -l`).

**Identifiants** (`Record::Credential`, protocole et type `telnet`, secret `plaintext`) :

- l'invite est la ligne courante du serveur au premier caractère tapé par le client sur une ligne
  (sans casse, espaces finaux ignorés) :
  - saisie du nom : se termine par `:` précédé de `login`, `username`, `user name`, `user`, `login as`,
    `utilisateur`, `nom d'utilisateur`, `identifiant`, `benutzername`, `benutzer` ou `usuario` ;
  - saisie du mot de passe : se termine par `password`, `passwd`, `passcode`, `mot de passe`,
    `passwort`, `kennwort`, `contraseña`, `senha` ou `wachtwoord` (suivi ou non de `:` ou `?`), ou
    contient l'un d'eux et se termine par `:` (`Password for jdoe:`, `Enter password`, `Mot de passe :`) ;
- écho absent : une ligne tapée touche par touche (au moins deux segments), sans qu'aucun caractère ne
  revienne en écho ni que le serveur n'envoie quoi que ce soit pendant la frappe, alors qu'il a annoncé
  `WILL ECHO`, est suspecte. La décision attend la première réponse du serveur après la fin de ligne :
  si elle commence par l'écho de la ligne (lien lent), c'est une saisie ordinaire ; sinon c'est un mot
  de passe quelle que soit l'invite (invite inconnue, ou absente de la capture), rendu secret dans la
  transcription, dont l'identifiant porte le détail `detected=no-echo`. Sans réponse avant la fin du
  flux, la ligne est masquée sans identifiant. Une seule ligne est suspecte à la fois : celles tapées
  avant la réponse sont lues normalement (un mot de passe suivi d'une commande tapée d'avance : seul le
  mot de passe est jugé). Une frappe anticipée pendant une sortie du serveur n'est jamais suspecte ;
- la saisie va jusqu'à la fin de ligne, effacements appliqués, bornée (256 caractères pour le nom,
  512 pour le mot de passe) ;
- un mot de passe saisi crée un identifiant (avec le dernier nom saisi, sinon la variable `USER` de
  `NEW-ENVIRON`) qui attend la suite pour son résultat :
  - `rejected` si une ligne du serveur contient `incorrect`, `failed`, `failure`, `invalid`, `denied`
    ou `bad password`, ou si le client retape à une invite de nom ou de mot de passe ;
  - `accepted` si une ligne du serveur contient `last login` ou `welcome`, ou si le client tape à une
    invite de shell (ligne qui se termine par `$`, `#`, `>` ou `%`) ;
  - sans résultat à la fin du flux si rien n'a tranché ;
- au plus 128 identifiants par connexion (`MAX_PER_FLOW` des credentials). Jamais dans un log : le
  `Debug` des structures masque saisies, transcriptions et secrets.

**Mot de passe dans la transcription** : les caractères tapés à une invite de mot de passe reconnue,
ou sur une ligne détectée par l'écho absent, forment un run `secret` (y compris un éventuel écho du
serveur, absorbé). Après un trou de réassemblage côté client, une saisie de mot de passe le reste
jusqu'à la fin de sa ligne, y compris quand le trou a emporté ses premières touches et que la suite
arrive après d'autres sorties du serveur : une invite de mot de passe terminée ou coupée sans saisie
est mémorisée, et la première ligne du client qui arrive après un trou est alors secrète. La valeur,
incomplète, ne donne pas d'identifiant. Un trou côté serveur ne touche pas à la saisie en cours.
Choix retenu :

- le texte de la transcription stockée (`telnet_transcripts.transcript`) ne contient pas les runs
  secrets : un run secret y est un marqueur vide, et les valeurs sont rangées à part, dans l'ordre,
  dans la colonne `secrets` (comme `credentials.secret`, même base) ;
- la recherche `q` porte sur `transcript`, jamais sur `secrets`, et la liste des sessions ne renvoie
  aucune transcription ;
- un mot de passe que ces règles ne reconnaissent pas reste un run `client` en clair, stocké dans
  `transcript` et trouvé par `q`. Cas connus :
  - frappe anticipée : tout envoyé d'un bloc avant les invites (`(echo user; echo pass) | telnet`), ou
    client en mode ligne sans écho du serveur, si l'invite n'est pas reconnue ;
  - invite absente de la capture (connexion reprise en cours) et serveur sans `WILL ECHO` ;
  - invite non reconnue (autre langue, `Code :`) quand le serveur ne fait pas d'écho négocié ou que
    la ligne part d'un bloc ;
  - mot de passe tapé par erreur à l'invite `login:` (renvoyé en écho, il est lu comme un nom) ;
  - à l'inverse, si un trou emporte toute la ligne du mot de passe, la ligne suivante du client qui
    arrive après un trou (une commande) est masquée par excès de prudence ;
- seul le détail d'une session (`/telnet/sessions/{flow}`) recompose les runs avec leur valeur, comme le
  détail d'un identifiant (`/credentials/{entry}`, ADR-019) ; l'UI l'affiche dans `SecretValue`, donc
  masqué par défaut (longueur seule), avec Révéler et Copier.

Variante écartée : servir les secrets par une route à part, à la demande. Elle aurait demandé un
`SecretValue` asynchrone propre à cette vue, pour une protection identique à celle de Credentials,
dont les secrets sont déjà servis par une route de détail.

La recherche `q` compare le texte cherché à sa forme JSON (`"` et `\` échappés comme dans `transcript`) ;
elle ne trouve pas un texte à cheval sur deux runs (une invite et la saisie qui la suit).

### Tables (migration `1500_telnet.sql`, plage réservée 1500-1599)

`telnet_sessions`, une ligne par connexion (`flow_id` clé primaire, `INSERT ... ON CONFLICT DO NOTHING`
car un flux n'est terminé qu'une fois) : `first_ts`, `last_ts` (du flux), extrémités, `client_bytes`,
`server_bytes` (octets sur le fil par sens, comme Connections), `username` (nom de la connexion
acceptée, sinon du dernier essai, sinon `USER` de `NEW-ENVIRON`), `env_user`, `login`
(`accepted` / `rejected` / NULL), `login_attempts`, `terminal`, `window_cols`, `window_rows`, `options`
(JSON), `transcript_bytes`, `transcript_lines`, `truncated`.

`telnet_transcripts` (même `flow_id`), à part pour que compteurs et listes ne lisent jamais le texte :
`transcript` (JSON des runs `[qui, texte]`, `c` client, `s` serveur, secrets remplacés par `["p", ""]`)
et `secrets` (JSON, dans l'ordre des runs `p`).
Index (différés pendant l'import, ADR-023) : `(first_ts, flow_id)` pour l'ordre de la liste et
`(first_ts, last_ts)` pour le chevauchement d'une plage.

### API (`crates/netsift-api/src/telnet.rs`)

| Méthode | Route | Réponse |
|---|---|---|
| GET | `/sessions/{id}/telnet/stats` | `TelnetStats` : `sessions`, `clients`, `servers` (adresses distinctes), `logins` (sessions avec au moins un mot de passe saisi), `accepted`, `rejected`, `truncated` |
| GET | `/sessions/{id}/telnet/sessions?q=&login=&limit=&cursor=` | `Page<TelnetSessionInfo>` : sessions par début croissant (keyset `(first_ts, flow_id)`), sans transcription ; `login` = `accepted`, `rejected`, `unknown` (mot de passe saisi, résultat inconnu), `none` (aucun mot de passe saisi) ; `q` cherche dans les adresses, le nom, le terminal et le texte de la transcription (hors secrets) |
| GET | `/sessions/{id}/telnet/sessions/{flow}` | `TelnetSessionDetail` : la session et sa transcription (`runs` : `client`, `server`, `secret`), secrets compris ; 404 si inconnue |

`total_estimate` est le compte exact des lignes filtrées. `login` invalide : 400 problem+json.

Compteur de module : `MODULES` `("telnet", "telnet_sessions")` ; sous plage, `ModuleRows::Telnet` =
sessions qui chevauchent la plage.

## Filtre temporel (ADR-030)

La vue est dans `timeFilterViews.ts` ; les routes passent par l'extracteur `ApiRange`.

| Route | Règle |
|---|---|
| `/telnet/sessions` | *chevauche(`first_ts`, `last_ts`)* ; durée, octets et transcription **de la session entière** |
| `/telnet/stats` | mêmes sessions |
| `/telnet/sessions/{flow}` | non filtrée : détail par identifiant |

Une session est un élément replié : elle est retenue si elle a été active pendant la plage, et ses
compteurs (octets) restent ceux de la connexion, avec la mention « Session entière » sous l'en-tête de
la colonne Octets (composant commun d'en-tête de colonne repliée) et dans la carte mobile. Découper la
transcription selon la plage n'aurait pas de sens pour la lecture (une commande et sa sortie).

## Mise en page

Ordre des blocs (une colonne sous 768 px) :

1. En-tête : titre « Telnet », sous-titre (nom de session), compteur de sessions.
2. Bandeau de chiffres (`StatCard`) : Sessions, Clients, Serveurs, Connexions (indice « acceptées /
   refusées »), Tronquées.
3. Carte « Sessions » : bande `filters` avec `SearchInput` et liste du résultat de connexion (Tous,
   Acceptée, Refusée, Résultat inconnu, Sans mot de passe). Liste dépliable (`ExpandableList`) : rangées client -> serveur
   (`Endpoint`, port grisé), utilisateur (ou « inconnu »), début (`Timestamp`), durée, octets (client +
   serveur, détail en infobulle), badges « refusée » / « acceptée » et « tronquée ». Sous 768 px,
   cartes empilées.
   Détail déplié :
   - ligne de métadonnées : terminal, fenêtre `80 x 24`, options actives en pastilles, `USER`
     d'environnement, octets par sens ;
   - transcription dans un bloc à chasse fixe (`whitespace-pre-wrap`, coupure des mots longs, jamais de
     défilement horizontal, largeur bornée à 100 caractères, sans défilement propre : la liste des
     sessions défile, deux niveaux de défilement au plus avec la page), texte React échappé ;
     la saisie du client en couleur d'accent atténuée, le serveur en couleur de texte ; un run secret
     est un `SecretValue` en ligne (masqué par défaut) ;
   - mention « Transcription tronquée à 64 Kio / 2 000 lignes » le cas échéant.
   Les lignes sont repliées au chargement, même pour une session unique (la référence la montre
   dépliée) : le composant commun `ExpandableList` n'a pas d'état initial déplié (suivi).

États : chargement (squelettes), erreur (réessayer), session en import ou en échec (`SessionGate`),
aucune session (« Aucune session Telnet »), plage vide (état vide commun « Rien dans la plage » avec
« Effacer la plage »).

## Améliorations par rapport à la référence

- Mot de passe masqué par défaut dans la transcription (`SecretValue`), identifiants reportés dans
  Credentials avec leur résultat.
- Métadonnées de session (utilisateur, durée, octets, terminal, taille de fenêtre, options) visibles
  sans ouvrir la transcription ; recherche dans les transcriptions.
- Saisie du client distinguée de la sortie du serveur.
- Bloc de transcription aux couleurs du thème (pas de bloc noir pleine largeur), sans débordement
  horizontal à 375 px.

## Critères d'acceptation

- Fixtures `netsift_fixtures::telnet` : connexion réussie (frappe caractère par caractère avec échos),
  échec puis succès, négociation riche (TTYPE, NAWS, NEW-ENVIRON USER, LINEMODE, SGA, ECHO), session
  tronquée (sortie volumineuse), segments coupant une séquence `IAC` (y compris dans une
  sous-négociation et un `IAC IAC`).
- Tests du parseur : commandes, sous-négociations, `IAC IAC`, coupures à chaque octet, bornes, flux
  hostiles (sous-négociation sans fin, octets aléatoires).
- Tests de l'analyseur (snapshot `insta` des transcriptions et identifiants) : échos fusionnés,
  retour arrière, ANSI retiré, mot de passe en run secret, résultats accepté / refusé, bornes.
- Tests du store (insertion, pages, plage, recherche sans secret) et de l'API (compteurs égaux entre
  liste, `stats` et module, filtres, validation, plage, détail avec secrets, 404, keyset).
- UI (Vitest) : liste, dépliage de la transcription, secret masqué puis révélé, filtre de résultat,
  mention « Session entière » sous plage.
- `./x.sh shots telnet all` et `telnet-range` verts à 375, 768, 1280 et 1920 px, en `en` et `fr`, sans
  débordement ni chevauchement, aucun mot de passe en clair sur les captures.
- Moins de 300 ms par requête (mesure sur une session synthétique volumineuse).

## Notes d'implémentation

- Décodage : `crates/netsift-dissect/src/telnet.rs` (cible de fuzz `telnet`, avec l'analyseur) ; analyseur :
  `crates/netsift-analyze/src/telnet/` (`transcript.rs`, `login.rs`) ; store : `crates/netsift-store/src/telnet.rs` ;
  API : `crates/netsift-api/src/telnet.rs` ; UI : `ui/src/views/telnet/`.
- Fixture : `netsift_fixtures::telnet` (`telnet_showcase`, `telnet_round`), ajoutée à la session de démonstration
  (vitrine puis une connexion au commutateur toutes les 30 s).
- Mesure (`telnet::tests::timings`, ignoré, mode release, 100 000 sessions de 2 Kio de transcription) : statistiques
  142 ms au pire, pages 2 à 23 ms, recherche dans les transcriptions 252 ms au pire, détail 0,5 ms
  (`docs/PERFORMANCE.md`).
- Limites : une session reprise en cours (sans les invites) n'a pas d'identifiant ; l'écho n'est fusionné que s'il
  suit la frappe dans l'ordre (une frappe anticipée pendant une sortie du serveur peut apparaître deux fois) ;
  les écrans plein écran (éditeurs, `top`) ne sont pas rejoués, seul leur texte reste, séquences retirées ;
  le budget de transcriptions est par shard (et non global comme les bornes d'ADR-023) : au-delà de 32 Mio
  de transcriptions en cours dans un shard, quelles sessions sont tronquées dépend du nombre de shards ;
  mots de passe laissés en clair : voir « Mot de passe dans la transcription ».
