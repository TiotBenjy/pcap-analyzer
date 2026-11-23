# MQTT

Tâche ROADMAP P5.15 (`feat/mqtt`, vague 5.B). Spécifications suivies : OASIS MQTT Version 3.1.1 (2014,
avec l'errata 01), OASIS MQTT Version 5.0 (2019), et MQTT V3.1 (publication IBM / Eurotech, 2010) pour le
nom de protocole `MQIsdp`. WebSocket : RFC 6455 et section 6 des deux specs OASIS. Aucun code GPL
(Wireshark ou autre) n'est porté.

**Statut : validée par l'utilisateur le 2026-11-23** (disposition et réponses de la section
« Décisions »). Aucune capture de référence : la disposition de la vue (section « Mise en page ») est une
proposition de cette spec. La tâche est découpée en deux branches (« Découpage ») : P5.15a (`feat/mqtt`,
MQTT sur TCP et vue) puis P5.15b (`feat/mqtt-ws-tls`, WebSocket et TLS).

## Référence

Aucune. La plateforme d'origine n'a pas d'onglet MQTT. Les blocs ci-dessous reprennent l'organisation des
onglets récents (SIP, FTP, Telnet) : bandeau de chiffres, signalements expliqués, listes dépliables,
transcription d'une connexion.

## But

Répondre à « quels objets et applications parlent MQTT sur ce réseau, à quels brokers, avec quels
identifiants, que publient-ils et sur quels topics, qui écoute tout, et qu'est-ce qui passe en clair ou
vers Internet ? ». MQTT est le protocole de messagerie de l'IoT et de l'industrie (capteurs, automates,
domotique) : un broker relaie les messages publiés sur des topics hiérarchiques vers les abonnés. En
clair (TCP 1883 ou WebSocket), tout est lisible : identifiants de CONNECT, topics, contenus.

## Données

### Rappel du protocole (ce qui est décodé)

- **En-tête fixe** : octet 1 = type (4 bits de poids fort) et drapeaux (4 bits) ; puis la longueur restante,
  entier à longueur variable de 1 à 4 octets (7 bits par octet, bit 7 = suite), au plus 268 435 455.
  Types : 1 CONNECT, 2 CONNACK, 3 PUBLISH, 4 PUBACK, 5 PUBREC, 6 PUBREL, 7 PUBCOMP, 8 SUBSCRIBE, 9 SUBACK,
  10 UNSUBSCRIBE, 11 UNSUBACK, 12 PINGREQ, 13 PINGRESP, 14 DISCONNECT, 15 AUTH (5.0 seulement). Type 0 :
  réservé, invalide. Drapeaux imposés : `0010` pour PUBREL, SUBSCRIBE, UNSUBSCRIBE, `0000` pour les autres
  sauf PUBLISH (DUP bit 3, QoS bits 2-1, RETAIN bit 0 ; QoS 3 invalide).
- **Versions** (CONNECT : nom de protocole et niveau) : `MQIsdp` niveau 3 = **3.1**, `MQTT` niveau 4 =
  **3.1.1**, `MQTT` niveau 5 = **5.0**. Un niveau dont le bit 7 est posé (`0x83`, `0x84`, `0x85`) est
  accepté et marqué `bridge` (convention de pont non normalisée, répandue chez les brokers libres).
  Le niveau détermine la grammaire de toute la connexion (propriétés 5.0 ou non).
- **CONNECT** : drapeaux (bit 0 réservé = 0, Clean Session / Clean Start, Will, Will QoS, Will Retain,
  Password, User Name), Keep Alive (secondes), propriétés 5.0, puis dans l'ordre : identifiant client,
  propriétés du testament (5.0), topic et charge du testament, nom d'utilisateur, mot de passe.
  3.1 : identifiant de 1 à 23 caractères, mot de passe en chaîne UTF-8. 3.1.1 et 5.0 : mot de passe en
  données binaires (jusqu'à 65 535 octets) ; 3.1.1 interdit un mot de passe sans nom (noté
  `protocol_error`, le mot de passe est quand même lu), 5.0 le permet.
- **CONNACK** : Session Present, code de retour (3.1 / 3.1.1 : 0 acceptée, 1 version refusée,
  2 identifiant refusé, 3 serveur indisponible, 4 nom ou mot de passe incorrect, 5 non autorisé) ou code de
  raison 5.0 (0x00 succès, 0x80 à 0x9F : erreur non précisée, paquet malformé, erreur de protocole,
  version non prise en charge, identifiant invalide, **0x86 nom ou mot de passe incorrect**, **0x87 non
  autorisé**, serveur indisponible, occupé, **0x8A banni**, **0x8C méthode d'authentification
  incorrecte**, paquet trop grand, quota dépassé, utiliser un autre serveur, serveur déplacé, débit de
  connexion dépassé...), propriétés 5.0.
- **PUBLISH** : topic (chaîne UTF-8, sans joker), identifiant de paquet si QoS > 0, propriétés 5.0, charge
  utile (le reste du paquet, longueur = longueur restante moins l'en-tête variable).
- **Accusés** : PUBACK (QoS 1), PUBREC / PUBREL / PUBCOMP (QoS 2), avec code de raison 5.0 facultatif.
- **SUBSCRIBE** : identifiant de paquet, propriétés 5.0, liste de (filtre, options) ; options = QoS
  demandée (bits 1-0), et en 5.0 No Local, Retain As Published, Retain Handling. **SUBACK** : un code par
  filtre (QoS accordée, ou 0x80 et plus = refus). **UNSUBSCRIBE** / **UNSUBACK** : filtres, codes 5.0.
- **PINGREQ / PINGRESP**, **DISCONNECT** (code de raison et propriétés 5.0, dans les deux sens en 5.0),
  **AUTH** (5.0, authentification étendue : code 0x18 continuer, 0x19 réauthentifier, méthode).
- **Propriétés 5.0** décodées (identifiant, type ; les autres sont sautées par leur type) :
  0x01 Payload Format Indicator, 0x02 Message Expiry Interval, 0x03 Content Type, 0x08 Response Topic,
  0x09 Correlation Data (longueur et 32 premiers octets en hexa), 0x0B Subscription Identifier,
  0x11 Session Expiry Interval, 0x12 Assigned Client Identifier, 0x13 Server Keep Alive,
  0x15 Authentication Method, 0x16 Authentication Data (**longueur seulement, jamais le contenu**),
  0x17 Request Problem Information, 0x18 Will Delay Interval, 0x19 Request Response Information,
  0x1A Response Information, 0x1C Server Reference, 0x1F Reason String, 0x21 Receive Maximum,
  0x22 Topic Alias Maximum, 0x23 Topic Alias, 0x24 Maximum QoS, 0x25 Retain Available, 0x26 User Property,
  0x27 Maximum Packet Size, 0x28 Wildcard Subscription Available, 0x29 Subscription Identifier Available,
  0x2A Shared Subscription Available. Un identifiant inconnu rend le reste des propriétés illisible :
  le paquet est gardé avec `props_error`, ses champs hors propriétés restent lus si la longueur des
  propriétés est cohérente.
- **Topic Alias** (5.0) : chaque sens a sa table (un alias posé par le client ne vaut que du client vers
  le broker). Un PUBLISH avec un topic et un alias pose `alias -> topic` ; un PUBLISH au topic vide et
  avec un alias est résolu par la table du sens. Alias 0 ou supérieur au Topic Alias Maximum annoncé par
  l'autre côté : `protocol_error`, alias quand même appliqué. Alias inconnu (connexion prise en cours) :
  topic NULL, `topic_source = 'unresolved'`.

### Parseur `netsift_dissect::mqtt` (pur, sans I/O, fuzzé)

- `fixed_header(&[u8]) -> Option<Header>` (type, drapeaux, longueur restante, taille de l'en-tête) avec
  état « incomplet » distinct d'« invalide » ; un entier variable de plus de 4 octets est invalide ; une
  forme non minimale est tolérée.
- `parse_packet(header, body_prefix, level)` : décode l'en-tête variable et la charge d'un paquet dont
  `body_prefix` est un préfixe du corps (au plus `MAX_PACKET_PREFIX`) : un PUBLISH de 10 Mio est décodé
  sur ses premiers 64 Kio (topic, propriétés, début de charge) et sa taille vient de l'en-tête. Toute
  longueur interne (chaîne, propriétés, liste de filtres) est vérifiée contre la longueur restante.
- Chaînes UTF-8 : invalide ou contenant U+0000 -> paquet `malformed` (spec : erreur fatale), sauf la
  charge utile, jamais interprétée.
- Bornes des champs gardés (coupés sur une frontière de caractère, indicateur `_truncated`) : identifiant
  client, nom d'utilisateur 256 octets ; mot de passe 1 024 ; topic et filtre 1 024 ; topic de testament
  1 024 ; Content Type, Response Topic, Reason String, Server Reference, méthode d'authentification
  256 ; 16 User Properties par paquet (nom et valeur à 256 octets) ; 64 filtres par SUBSCRIBE /
  UNSUBSCRIBE / SUBACK (les suivants comptés) ; 8 Subscription Identifiers par PUBLISH.
- Texte stocké pour affichage (identifiant, topic, raison...) : caractères de contrôle et caractères de
  mise en forme bidirectionnelle ou invisibles (U+200B à U+200F, U+202A à U+202E, U+2066 à U+2069,
  U+FEFF) remplacés par U+FFFD, comme SIP ; la valeur exacte reste utilisée pour l'arbre des topics.
- WebSocket (`netsift_dissect::websocket`, P5.15b) : décodeur de trames RFC 6455 incrémental (FIN, RSV,
  opcode, longueur 7/16/64 bits, masque) ; la charge est démasquée par morceaux sans jamais allouer selon
  la longueur annoncée ; trames de contrôle (ping, pong, close) de 125 octets au plus, code et raison de
  `close` lus ; RSV1 posé sans extension négociée, ou opcode réservé : flux abandonné.

### Analyseur `mqtt` (`crates/netsift-analyze/src/mqtt/`)

Le moteur de connexion (`mqtt::Conn` : découpage des paquets d'un flux d'octets, état par sens, alias,
accusés, compteurs, émission des enregistrements) est indépendant du transport : l'analyseur `mqtt`
l'alimente avec les données TCP réassemblées, l'analyseur `http` avec les charges WebSocket démasquées
(P5.15b). Une connexion TCP est toujours traitée par le même shard (`shard_hash` sur la paire d'adresses,
ADR-032) : alias, accusés et compteurs n'ont besoin d'aucun état partagé.

**Détection** (connexion TCP, données réassemblées) :

1. **Port 1883** (côté serveur, ou côté client pour une connexion prise en cours) : le premier contenu du
   client doit être un CONNECT valide (règles ci-dessous) ; sinon voir « Connexion prise en cours ».
2. **Tout autre port** : la connexion est MQTT si et seulement si son premier contenu du client est un
   CONNECT valide en entier : octet `0x10` exactement, longueur restante valide, nom `MQTT` (niveau 4 ou
   5, bit 7 permis) ou `MQIsdp` (niveau 3), bit réservé des drapeaux à 0, Will QoS différent de 3, Will
   QoS et Will Retain à 0 sans Will, chaînes UTF-8 valides, et champs qui remplissent **exactement** la
   longueur restante (aucun octet en trop, aucun en moins). Le CONNECT peut être coupé entre segments :
   les 4 premiers segments du client et 64 Kio au plus sont accumulés pour décider. Le côté qui envoie le
   CONNECT est le client (quel que soit le sens vu par la table de flux).
3. **Anti faux positifs** : un contenu qui commence par une requête HTTP, un ClientHello TLS ou tout
   autre octet que `0x10` n'est pas MQTT hors port 1883 ; la décision est définitive après le premier
   paquet (pas de recherche plus loin dans le flux) ; un CONNECT dont la longueur restante dépasse 64 Kio
   est jugé sur ses champs jusqu'au nom d'utilisateur compris (le testament seul peut être grand).
   Aucune connexion UDP n'est examinée (MQTT-SN : P5.16).
4. **Connexion prise en cours** (port 1883 seulement : capture commencée après le CONNECT, coupure de
   chunk) : le premier segment de chaque sens doit commencer par un en-tête fixe valide d'un type permis
   dans ce sens (client : PUBLISH, accusés, SUBSCRIBE, UNSUBSCRIBE, PINGREQ, DISCONNECT, AUTH ; broker :
   CONNACK, PUBLISH, accusés, SUBACK, UNSUBACK, PINGRESP, DISCONNECT, AUTH), et au moins deux paquets
   consécutifs doivent se décoder. Le niveau est deviné : 5.0 si tous les paquets décodés jusque-là se
   lisent avec propriétés et pas sans, sinon 3.1.1 ; la connexion est marquée `partial` (sans CONNECT,
   version supposée).

**Découpage et pertes** :

- Tampon par sens borné à `MAX_PACKET_PREFIX` = 64 Kio plus l'en-tête fixe : au-delà, la suite du paquet
  est sautée (comptée) jusqu'à sa fin d'après la longueur restante. Plusieurs paquets dans un segment et
  paquets coupés à n'importe quel octet sont gérés.
- Paquet invalide (type 0, drapeaux imposés faux, chaîne invalide, longueur interne incohérente) :
  `malformed` incrémenté, premier type et décalage notés, le sens est abandonné (la spec impose de couper
  la connexion ; la suite n'est pas fiable).
- Trou de réassemblage (`gap_before`) : s'il tombe dans un paquet dont la fin est connue et que le trou
  y tient, le paquet est marqué incomplet et l'alignement est conservé ; sinon le sens se resynchronise
  au début d'un segment suivant qui commence par un en-tête fixe valide d'un type permis dans ce sens et
  dont les paquets se décodent jusqu'à la fin du segment (ou au-delà, paquet en cours) ; au plus 64
  segments essayés, puis le sens est abandonné. Compteur `gaps`.

**Accusés et fusion** (ce qui rend la transcription lisible et borne le stockage) :

- PUBACK, PUBREC, PUBREL, PUBCOMP sont rattachés au PUBLISH de même identifiant de paquet envoyé par
  l'autre côté : le PUBLISH porte `ack_state` (`none` QoS 0, `acked` PUBACK ou PUBCOMP, `received` PUBREC
  sans PUBCOMP, `missing` aucun accusé, `error` code >= 0x80), `ack_reason` et `ack_ns` (délai). SUBACK et
  UNSUBACK sont rattachés à leur SUBSCRIBE / UNSUBSCRIBE (code par filtre). Un accusé sans paquet
  d'origine est gardé comme paquet à part.
- Un paquet en attente d'accusé est tenu en mémoire jusqu'à l'accusé, au paquet suivant de même
  identifiant, ou à la fin de la connexion ; au plus 1 024 en attente par connexion et 32 Mio par shard
  (au-delà, il est émis sans attendre, `ack_state = 'missing'`). Son numéro d'ordre (`seq`) est pris à
  l'arrivée : l'ordre de la transcription ne dépend pas du moment de l'émission.
- PINGREQ / PINGRESP ne sont pas stockés un par un : compteurs et dernier horodatage de la connexion.

**Bornes** :

- Paquets stockés par connexion : 10 000 (CONNECT, CONNACK, PUBLISH, SUBSCRIBE, UNSUBSCRIBE, DISCONNECT,
  AUTH, accusés orphelins). Au-delà, `packets_truncated` : les compteurs, topics et abonnements continuent.
- Extrait de charge utile stocké : 512 premiers octets (`MAX_EXCERPT`), taille réelle à part.
- Topics agrégés par connexion et par sens : 4 096 ; au-delà, un seau « autres topics » (topic NULL).
- Abonnements gardés par connexion : 1 024.
- Tables d'alias : 1 024 entrées par sens.
- Connexions suivies en même temps : 65 536 au total, réparties entre les shards par le moteur (au moins
  16 par shard), comme FTP ; au-delà, les nouvelles ne sont pas analysées (le résultat ne dépend alors du
  nombre de shards que parce qu'une borne est atteinte, ADR-023).

**Identifiants** (`Record::Credential`, protocole `mqtt`, type `mqtt`) :

- Émis au CONNECT qui porte un nom et/ou un mot de passe, complété par le CONNACK s'il arrive (le
  CONNECT est tenu jusqu'au CONNACK ou à la fin de la connexion).
- Mot de passe présent : état `plaintext`, secret = mot de passe (UTF-8 valide et imprimable tel quel,
  sinon `hex:` suivi de l'hexadécimal en minuscules ; détail `password_encoding`). Nom seul : état
  `metadata-only`. Authentification étendue 5.0 (méthode `SCRAM-SHA-256`, `GS2-KRB5`...) : entrée
  `metadata-only` avec la méthode, sans aucune donnée d'authentification.
- Détails (non secrets) : `version`, `client_id`, `transport` (`tcp`, `ws`), `result` (`accepted`,
  `rejected`), `connack` (code et libellé), `auth_method`.
- Repli des observations identiques par l'empreinte existante (un capteur qui se reconnecte toutes les
  minutes donne une entrée avec un nombre d'observations). Pas de ligne hashcat (secret en clair).
  Export CSV par l'export existant de Credentials, sans changement.
- Jamais dans un log : le `Debug` des structures qui portent un mot de passe ou des données
  d'authentification les remplace par `<redacted>`.

**Logiciel du broker** : un PUBLISH du broker sur `$SYS/broker/version` (topic système publié par
plusieurs brokers libres) donne la version annoncée du logiciel, gardée sur la connexion (128 octets,
texte nettoyé). Indice déclaratif, comme les user-agents SIP.

### MQTT sur WebSocket (P5.15b)

- Aujourd'hui l'analyseur `http` arrête la connexion à la réponse `101` (`Phase::Tunnel`). Il garde
  désormais l'en-tête de la requête d'Upgrade : si la réponse 101 porte `Upgrade: websocket` et un
  `Sec-WebSocket-Protocol` choisi parmi `mqtt` (3.1.1, 5.0) ou `mqttv3.1` (3.1), ou si la requête
  proposait l'un d'eux et que la réponse n'en choisit aucun, la connexion passe en phase `WebSocket` :
  trames des deux sens décodées par `netsift_dissect::websocket`, charges des trames binaires (et de leurs
  continuations) concaténées et données au moteur `mqtt::Conn` partagé, qui émet les mêmes enregistrements
  avec `transport = 'ws'`, le chemin et l'hôte de la requête, le sous-protocole choisi.
- Sans sous-protocole MQTT, la connexion WebSocket n'est retenue que si son premier message binaire du
  client est un CONNECT valide (règle de détection 2) ; sinon elle reste ignorée comme aujourd'hui.
- Un paquet MQTT peut être coupé entre trames et une trame peut en contenir plusieurs (section 6 des
  specs) : le moteur ne voit qu'un flux d'octets. Trames texte : non conformes, comptées, ignorées.
  Trame `close` : code et raison gardés (`ws_close_code`).
- `permessage-deflate` négocié : les trames compressées (RSV1) ne sont pas décodées, la connexion est
  marquée `ws_compressed` et ne porte que ses métadonnées (décision 7).
- La transaction HTTP de l'Upgrade reste dans `http_transactions` comme aujourd'hui.

### MQTT sur TLS (P5.15b)

- Aucun déchiffrement. Les sessions de `tls_sessions` dont le port serveur est **8883** (IANA
  `secure-mqtt`) ou dont l'ALPN retenu ou proposé est `mqtt` ou `x-amzn-mqtt-ca` (ALPN de MQTT sur 443
  d'un grand fournisseur IoT) sont listées comme « MQTT chiffré », avec la raison (`port`, `alpn`).
- Lecture à la demande dans `tls_sessions` (pas de copie) : index partiel ajouté par la migration MQTT
  (`tls_sessions (ts, id) WHERE server_port = 8883 OR alpn IN ('mqtt', 'x-amzn-mqtt-ca') OR
  instr(alpn_offered, '"mqtt"') > 0 OR instr(alpn_offered, '"x-amzn-mqtt-ca"') > 0`).
- MQTT sur WebSocket chiffré (`wss`, souvent 443 ou 8084) n'est pas reconnaissable sans ALPN ni SNI
  propre : il reste dans l'onglet TLS seulement.

### Classification du trafic

Nouveau libellé `mqtt` (`AppProto::Mqtt`) pour TCP 1883 dans `classify.rs` et la palette de l'UI
(Overview, Connexions). 8883 reste `tls`, comme 443 et 8443. Une connexion MQTT détectée sur un autre
port garde son libellé de port (`tcp`), comme les autres protocoles.

### Tables (migration `1600_mqtt.sql`, plage proposée 1600-1699)

Plage 1600-1699 à réserver dans `schema.rs` (P5.10 WiFi n'a pas encore de plage : l'orchestrateur
tranche si les deux branches tournent en même temps). P5.15b ajoute `1601_mqtt_tls.sql` (index partiel
de `tls_sessions`).

- `mqtt_connections` (une ligne par connexion, `flow_id` clé primaire, `INSERT ... ON CONFLICT DO
  NOTHING`) : `first_ts`, `last_ts` (du flux), `client_ip`, `client_port`, `server_ip`, `server_port`,
  `transport` (`tcp`, `ws`), `ws_path`, `ws_host`, `ws_subprotocol`, `ws_close_code`, `ws_compressed`,
  `version` (3, 4, 5, NULL si inconnu), `bridge`, `partial`, `client_id`, `assigned_client_id`,
  `clean_start`, `keep_alive`, `server_keep_alive`, `session_expiry`, `username`, `has_password`,
  `password_len`, `auth_method`, `auth` (`none`, `username`, `password`, `enhanced` ; NULL si `partial`),
  `will_topic`, `will_qos`, `will_retain`, `will_payload_len`, `will_excerpt` (BLOB), `connect_props`
  (JSON borné : Receive Maximum, Maximum Packet Size, Topic Alias Maximum, User Properties...),
  `connack_ts`, `connack_code`, `session_present`, `connack_props` (JSON borné : Maximum QoS, Retain
  Available, Reason String, Server Reference...), `login` (`accepted`, `rejected`, NULL sans CONNACK),
  `end_kind` (`disconnect`, `close`, `reset`, `capture`), `disconnect_ts`, `disconnect_by` (`client`,
  `broker`), `disconnect_reason`, `broker_software`, compteurs `packets_c2s`, `packets_s2c`,
  `publish_c2s`, `publish_s2c`, `payload_bytes_c2s`, `payload_bytes_s2c`, `subscribe_count`, `pings`,
  `last_ping_ts`, `bytes_c2s`, `bytes_s2c` (octets sur le fil, comme Connexions), `stored_packets`,
  `packets_truncated`, `malformed`, `protocol_errors`, `gaps`.
- `mqtt_connect_secrets` (`flow_id`, `password`) : à part pour qu'aucune liste ni compteur ne lise le
  secret ; servi seulement par la route de détail d'une connexion (comme `telnet_transcripts.secrets`).
- `mqtt_packets` : `id` (pagination), `flow_id`, `seq` (unique avec `flow_id`), `ts`, `dir` (`c` client
  vers broker, `b` broker vers client), `ptype` (1 à 15), `flags`, `packet_id`, `qos`, `retain`, `dup`,
  `topic`, `topic_alias`, `topic_source` (`name`, `alias`, `unresolved`), `size` (paquet entier),
  `payload_len`, `payload` (BLOB, `MAX_EXCERPT`), `payload_format` (Payload Format Indicator),
  `content_type`, `reason_code`, `reason_string`, `ack_state`, `ack_reason`, `ack_ns`, `filters` (JSON des
  filtres d'un SUBSCRIBE / UNSUBSCRIBE avec options et code accordé), `props` (JSON borné des autres
  propriétés : Message Expiry, Response Topic, Correlation Data, Subscription Identifiers, User
  Properties), `incomplete` (trou dans le paquet), `malformed`.
- `mqtt_topic_flows` (agrégat par connexion, topic et sens, émis à la fin de la connexion) : `flow_id`,
  `dir`, `topic` (NULL = seau « autres topics »), `messages`, `payload_bytes`, `first_ts`, `last_ts`,
  `qos_mask`, `retained`, `max_payload`. Compte **tous** les PUBLISH, même au-delà de la borne de paquets
  stockés.
- `mqtt_subscriptions` : `flow_id`, `seq`, `ts`, `filter`, `qos`, `options`, `granted` (code du SUBACK),
  `shared_group` (`$share/<groupe>/...`, 5.0), `unsubscribed_ts`.
- `mqtt_topics` (étape de fin d'import `mqtt`) : un nœud par niveau de l'arbre des topics, construit
  depuis `mqtt_topic_flows` : `path` (topic complet ou préfixe), `parent`, `name` (dernier niveau, chaîne
  vide permise : `a//b` et `/a` ont des niveaux vides), `depth`, `is_topic` (un PUBLISH a eu ce chemin
  exact), `children`, `topics` (topics sous le nœud, lui compris), `messages_pub` (client vers broker),
  `messages_del` (broker vers client, livraisons aux abonnés), `payload_bytes`, `publishers` (connexions
  distinctes qui publient sous le nœud), `retained`, `first_ts`, `last_ts`. Profondeur au plus 32 niveaux
  (au-delà, le reste du topic est le nom du 32e nœud). Au plus 1 000 000 topics distincts : au-delà,
  les topics de moindre volume (puis de plus grand nom) sont repliés dans un nœud « autres topics » de
  leur parent, et `meta` note le nombre de topics repliés. Calcul sur la table complète dans un ordre
  total (`topic`, puis `flow_id`) : le résultat ne dépend ni des chunks ni du nombre de shards.
- Index (différés pendant l'import, ADR-023, sauf ceux de `mqtt_topics` remplie par l'étape) :
  `mqtt_connections (first_ts, flow_id)` (liste), `(first_ts, last_ts)` (chevauchement),
  `(server_ip, server_port, transport)` (brokers), `(client_id, first_ts)` (clients),
  `(login, auth, first_ts)` (signalements), `(client_ip, server_ip, server_port, login)` (échecs répétés) ;
  `mqtt_packets (flow_id, seq)` (transcription, unique), `(ts, id) WHERE ptype = 3` (messages),
  `(topic, ts) WHERE ptype = 3` (messages d'un topic, derniers messages) ; `mqtt_topic_flows (topic, dir)`,
  `(first_ts, last_ts)`, `(flow_id)` ; `mqtt_subscriptions (filter)`, `(flow_id, seq)` ;
  `mqtt_topics (parent, name)`, `(path)` unique.

Ordre de grandeur : un PUBLISH stocké coûte environ 150 octets plus son extrait ; 10 000 paquets par
connexion bornent une connexion de télémétrie de plusieurs jours à quelques Mio.

### Étape de fin d'import `mqtt`

Après `indexes` (lit `mqtt_topic_flows` par son index `(topic, dir)`). Construit `mqtt_topics` en un
parcours ordonné par topic (préfixes communs cumulés à la volée, mémoire bornée par la profondeur).
Rejouée à l'ouverture si elle manque (ADR-014). Une session sans connexion MQTT la marque faite sans
rien écrire.

### API (`crates/netsift-api/src/mqtt.rs`)

| Méthode | Route | Réponse |
|---|---|---|
| GET | `/sessions/{id}/mqtt/stats` | `MqttStats` : `connections` (par transport et par version), `clients`, `brokers`, `public_brokers`, `logins` acceptés / refusés / sans réponse, `anonymous_accepted`, `credentials`, `publish` par sens, `payload_bytes`, `subscriptions`, `topics`, `encrypted` (sessions TLS MQTT, P5.15b), top 10 des codes CONNACK (avec libellé), compteurs des signalements |
| GET | `/sessions/{id}/mqtt/connections?q=&login=&auth=&version=&transport=&broker=&client_id=&signal=&limit=&cursor=` | `Page<MqttConnectionInfo>` par début croissant (keyset `(first_ts, flow_id)`), sans secret ; `q` cherche dans les adresses, l'identifiant client, le nom d'utilisateur et le chemin WebSocket ; `login` = `accepted`, `rejected`, `none` ; `auth` = `none`, `username`, `password`, `enhanced` ; `version` = `3.1`, `3.1.1`, `5.0`, `unknown` ; `broker` = `ip:port` ; `signal` = un des signalements |
| GET | `/sessions/{id}/mqtt/connections/{flow}` | `MqttConnectionDetail` : la connexion, CONNECT / CONNACK / DISCONNECT décodés, testament (extrait rendu), propriétés, abonnements, 50 topics principaux de la connexion, **mot de passe** (secret, comme le détail d'une session FTP ou Telnet) ; 404 si inconnue |
| GET | `/sessions/{id}/mqtt/connections/{flow}/packets?type=&limit=&cursor=` | `Page<MqttPacketInfo>` : transcription par `seq` croissant (keyset `seq`), extrait rendu (voir « Rendu des charges ») |
| GET | `/sessions/{id}/mqtt/clients?q=&limit=&cursor=` | `Page<MqttClientInfo>` : connexions regroupées par identifiant client (identifiant vide ou inconnu : regroupé par adresse client) : adresses (au plus 8), noms d'utilisateur (au plus 4), brokers (au plus 4), versions, connexions, acceptées / refusées, PUBLISH par sens, topics publiés, abonnements, première et dernière activité ; keyset `(client_key)` |
| GET | `/sessions/{id}/mqtt/brokers?q=&limit=&cursor=` | `Page<MqttBrokerInfo>` : regroupés par (adresse, port, transport) : catégorie d'adresse, `public`, logiciel annoncé, versions, connexions, clients distincts, connexions anonymes acceptées, refus, PUBLISH, topics, première et dernière activité ; tri par connexions décroissantes (keyset `(connections, ip, port, transport)`) |
| GET | `/sessions/{id}/mqtt/topics?parent=&q=&limit=&cursor=` | `Page<MqttTopicNode>` : enfants directs de `parent` (absent = racine) par nom (keyset `name`) ; avec `q`, topics complets qui contiennent le texte (au plus 200, sans arbre) |
| GET | `/sessions/{id}/mqtt/topics/node?path=` | `MqttTopicDetail` : nœud, éditeurs (au plus 20 : identifiant client, `Endpoint`, messages), abonnements dont le filtre couvre le chemin (au plus 20, jokers `+` et `#` appliqués selon la spec, `$` exclus des jokers de premier niveau), répartition des QoS, messages retenus, 5 derniers messages (extrait rendu) |
| GET | `/sessions/{id}/mqtt/messages?topic=&prefix=&dir=&qos=&retain=&client_id=&broker=&flow=&q=&limit=&cursor=` | `Page<MqttMessageInfo>` : PUBLISH stockés par horodatage croissant (keyset `(ts, id)`) ; `q` cherche dans le topic et l'identifiant client (pas dans la charge) |
| GET | `/sessions/{id}/mqtt/signals` | `Vec<MqttSignal>` : signalements (définitions ci-dessous), au plus 50 lignes par type, chacune avec ses compteurs et le filtre de liste à appliquer |
| GET | `/sessions/{id}/mqtt/tls?q=&limit=&cursor=` | `Page<MqttTlsSessionInfo>` (P5.15b) : sessions TLS MQTT par horodatage (keyset `(ts, id)`), avec la raison (`port`, `alpn`) et les champs de `/tls/sessions` |

Valeurs invalides (`login`, `auth`, `version`, `transport`, `dir`, `qos`, `signal`, `broker`, curseur) :
400 problem+json. `total_estimate` est le compte exact des lignes filtrées. Aucune liste ne sert de secret.

**Rendu des charges** (fait côté Rust, testé par snapshot, même règle pour le testament) : l'API renvoie
`payload_len`, `excerpt_len`, `excerpt_truncated`, `excerpt_hex` (hexadécimal) et `excerpt_text` : texte si
l'extrait est de l'UTF-8 valide (un caractère coupé par la borne est toléré) sans caractère de contrôle
autre que tabulation, LF et CR, ou si le Payload Format Indicator vaut 1 ; caractères de contrôle et de
mise en forme bidirectionnelle ou invisibles échappés en `\xNN` / `\u{NNNN}` ; NULL sinon. L'UI les
affiche comme texte React, jamais comme HTML, et propose Texte / Hexa.

**Compteur de module** : `MODULES` `("mqtt", ...)` = connexions MQTT en clair plus sessions TLS MQTT
(P5.15b), pour qu'une capture qui n'a que du 8883 n'estompe pas l'onglet ; sous plage,
`ModuleRows::Mqtt` = connexions qui chevauchent la plage plus sessions TLS MQTT ponctuelles.

## Signalements (définitions)

Calculés à la lecture, sur les connexions en clair (TCP et WebSocket), sans liste externe ni accès réseau.
« Public » = catégorie `Public` de `netsift_geo::AddressCategory` (ni privée RFC 1918 / ULA, ni CGNAT,
ni loopback, link-local, multicast, broadcast).

| Signalement | Définition | Explication affichée |
|---|---|---|
| `anonymous` | Connexion dont le CONNECT n'a ni nom, ni mot de passe, ni méthode d'authentification 5.0, et dont le CONNACK est accepté | Le broker accepte des clients sans identifiants ; un contrôle par certificat ou par réseau reste possible mais n'est pas visible ici |
| `public-broker` | Broker (côté serveur d'une connexion MQTT en clair) d'adresse publique | Messages et identifiants traversent Internet en clair |
| `exposed-broker` | Broker d'adresse non publique avec au moins une connexion acceptée depuis une adresse client publique | Un broker local est joignable depuis Internet (redirection de port, exposition) |
| `wildcard` | Abonnement dont le filtre est `#`, `+/#`, `$SYS/#` ou `$share/<groupe>/#` | Un client lit tous les messages du broker (supervision, collecte ou reconnaissance) |
| `auth-failures` | Au moins 5 connexions refusées (codes 4, 5, 0x86, 0x87, 0x8A, 0x8C) d'une même adresse client vers un même broker | Essais d'identifiants répétés |
| `cleartext-credentials` | Connexion en clair qui porte un mot de passe | Lien vers Credentials filtré sur `mqtt` |

## Filtre temporel (ADR-030)

La vue est dans `timeFilterViews.ts` dès sa création ; ses routes passent par `ApiRange`.

| Route | Règle |
|---|---|
| `/mqtt/connections` | *chevauche(`first_ts`, `last_ts`)* ; compteurs (PUBLISH, octets) **de la connexion entière** |
| `/mqtt/clients`, `/mqtt/brokers` | regroupés sur les connexions qui *chevauchent* ; compteurs des connexions entières |
| `/mqtt/topics`, `/mqtt/topics/node` | sous plage, nœuds recalculés depuis les lignes de `mqtt_topic_flows` qui *chevauchent(`first_ts`, `last_ts`)* (enfants d'un préfixe par parcours de l'index `(topic)` sur ce préfixe) ; compteurs de ces lignes entières ; sans plage, `mqtt_topics` |
| `/mqtt/messages` | *ponctuel(`ts`)* |
| `/mqtt/connections/{flow}/packets` | *ponctuel(`ts`)* (la transcription d'une connexion suit la plage, avec la mention « paquets de la plage ») |
| `/mqtt/stats` | connexions, clients, brokers, logins, signalements : connexions qui *chevauchent* ; PUBLISH et octets : agrégats de `mqtt_topic_flows` qui *chevauchent* (session entière) ; TLS : *ponctuel(`ts`)* |
| `/mqtt/signals` | connexions qui *chevauchent* |
| `/mqtt/tls` | *ponctuel(`ts`)*, comme `/tls/sessions` |
| `/mqtt/connections/{flow}` | non filtrée : détail par identifiant |

Colonnes de valeurs repliées sous plage (PUBLISH, octets, messages d'un topic, connexions d'un client) :
`WholeSessionHeader` / `wholeSessionHeader()` ; sous un compteur de carte, `WholeSessionLine`.

## Mise en page (proposition)

Onglet « MQTT » dans le groupe « Plus » de la barre latérale (icône lucide `RadioTower`), route `/mqtt`.
Le sous-onglet actif et les filtres sont dans l'URL (`?tab=connections|clients|brokers|topics|messages|tls`
et paramètres de filtre), retour arrière compris.

Ordre des blocs (une colonne sous 768 px) :

1. **En-tête** : titre « MQTT », sous-titre (nom de session), compteur de connexions.
2. **Bandeau de chiffres** (`StatCard`, 2 colonnes sous `sm`, 3 jusqu'à `xl`, 6 au-delà) : Connexions
   (indice « TCP / WebSocket »), Clients, Brokers (indice « n publics », ambre s'il y en a), Messages
   publiés (indice : octets de charge), Topics, MQTT chiffré (sessions TLS ; P5.15b, absent avant).
3. **Carte « Signalements »** (absente sans signalement) : une ligne par type présent : libellé, phrase
   d'explication (tableau ci-dessus), compteur, bouton « Voir » qui ouvre le sous-onglet concerné avec le
   filtre en pastille (`signal=`), lien « Voir dans Credentials » pour les identifiants en clair. Pas de
   couleur seule : le libellé dit le constat.
4. **Sous-onglets** (`SegmentedControl` avec compteurs ; liste déroulante sous 640 px) : Connexions,
   Clients, Brokers, Topics, Messages, Chiffré (P5.15b). Chaque sous-onglet est une `Card` avec sa bande
   `filters`.

### Connexions (sous-onglet par défaut)

- Filtres : `SearchInput` ; liste « Résultat » (Toutes, Acceptées, Refusées, Sans réponse) ; liste
  « Authentification » (Toutes, Anonyme, Nom seul, Mot de passe, Étendue) ; liste « Version » ; liste
  « Transport » (P5.15b) ; pastilles `FilterChip` des filtres venus d'ailleurs (broker, identifiant
  client, signalement).
- `ExpandableList` paginée (200 lignes) : début (`Timestamp`), client -> broker (`Endpoint`, port
  grisé), identifiant client (mono, `MiddleTruncate` + infobulle), version (badge), authentification
  (badge : « Anonyme » ambre, « Identifiants », « Étendue »), résultat (badge « Acceptée » / « Refusée :
  libellé du code »), badge « WebSocket », PUBLISH envoyés et reçus, durée. Sous `md`, cartes empilées
  (titre = identifiant client, puis client -> broker, puis compteurs sur une ligne). Sous plage, colonnes
  de compteurs avec `WholeSessionHeader`.
- Détail déplié, en deux colonnes à partir de `lg`, une sous `lg` :
  - **CONNECT** (liste libellé / valeur) : version et nom de protocole (`bridge` le cas échéant),
    identifiant client (copie), Clean Session / Clean Start, Keep Alive, Session Expiry, nom
    d'utilisateur, mot de passe (`SecretValue`, masqué par défaut, avec « Voir dans Credentials »),
    méthode d'authentification, testament (topic, QoS, retain, extrait en Texte / Hexa), limites annoncées
    (Receive Maximum, Maximum Packet Size, Topic Alias Maximum), User Properties ;
  - **CONNACK** : code et libellé, Session Present, identifiant attribué, Server Keep Alive, capacités 5.0
    (Maximum QoS, Retain Available, abonnements jokers / partagés), Reason String ; « CONNACK non vu »
    sinon ;
  - **Fin** : DISCONNECT (qui, code, raison), ou fin TCP / réinitialisation / encore ouverte en fin de
    capture ; WebSocket : chemin, hôte, sous-protocole, code de fermeture ; logiciel du broker annoncé ;
    PINGREQ comptés et dernier ;
  - **Abonnements** : filtre (mono), QoS demandée, options 5.0, résultat (QoS accordée ou refus),
    groupe partagé, désabonnement daté ;
  - **Transcription** : bloc à chasse fixe (fond `subtle`, `whitespace-pre-wrap`, coupure des mots
    longs, sans défilement horizontal ni défilement propre : la liste défile), une ligne par paquet :
    décalage depuis le début de la connexion (`+12,345 s`, heure complète en infobulle), sens en mot
    (« Client », « Broker »), type en gras, puis selon le type : topic (couleur d'accent), QoS, retain,
    dup, identifiant de paquet, taille, accusé et délai (« PUBACK 3 ms », « sans accusé » en ambre,
    code d'erreur en rouge), alias résolu (« alias 4 »). Une ligne PUBLISH se déplie sur son extrait
    (Texte / Hexa) et ses propriétés. Pagination « Charger la suite » par 500 paquets. Mentions « 10 000
    paquets stockés, suite comptée seulement », « octets manquants », « paquet malformé : arrêt du
    décodage ».

### Clients

- Filtres : `SearchInput` (identifiant, adresse, utilisateur).
- `DataTable` (mode `cards` sous `md`) : identifiant client (mono, « identifiant vide » ou « inconnu »
  en italique, identifiant attribué en infobulle), adresses (`Endpoint`, « +n »), utilisateurs, brokers,
  connexions (acceptées / refusées), versions, publiés, reçus, topics publiés, abonnements, première et
  dernière activité ; badges des signalements qui le concernent. Clic sur une ligne : sous-onglet
  Connexions filtré sur ce client (pastille).

### Brokers

- `DataTable` (mode `cards` sous `md`) : broker (`Endpoint` adresse et port, drapeau), transport
  (TCP, ou WebSocket et chemin), badge « Public » / « Exposé », logiciel annoncé, versions vues,
  connexions, clients, anonymes acceptées, refus, messages, topics, première et dernière activité. Clic :
  sous-onglet Connexions filtré sur ce broker.

### Topics

- Filtres : `SearchInput` (recherche d'un topic : liste plate des topics complets trouvés, clic = ouvre
  le nœud).
- Navigation par niveaux plutôt qu'un arbre graphique : fil d'Ariane (« Racine / usine / ligne1 »,
  retour à la ligne permis, chaque niveau cliquable), puis `DataTable` des enfants du niveau courant :
  nom (mono, `MiddleTruncate`, chevron s'il a des enfants, mention « topic » s'il est aussi publié
  tel quel), topics sous le nœud, messages publiés, livrés, octets, dernière activité. Clic sur un nœud
  avec enfants : descend d'un niveau ; clic sur une feuille : ouvre le détail. Tri par messages ou par
  nom (action de carte).
- Détail d'un nœud (à droite à partir de `xl`, panneau de 400 px ; sous `xl`, sous la liste) : chemin
  complet (copie), compteurs, répartition QoS et retenus, éditeurs (identifiant client et `Endpoint`),
  abonnements qui couvrent ce chemin (filtre et client), 5 derniers messages (heure, éditeur, extrait
  Texte / Hexa), bouton « Voir les messages » (sous-onglet Messages filtré sur le topic, ou le préfixe
  pour un nœud intermédiaire).
- Topics système (`$SYS/...`) affichés comme les autres, sous leur propre racine `$SYS`.

### Messages

- Filtres : `SearchInput` (topic, identifiant client), contrôle segmenté du sens (Tous, Publiés par un
  client, Livrés par le broker), liste QoS, bascule « Retenus », pastilles (topic, préfixe, client,
  broker, connexion).
- `ExpandableList` paginée (200 lignes) : heure, sens, identifiant client, topic (mono, `MiddleTruncate`),
  QoS, badges `retain` / `dup`, taille de charge, accusé. Cartes sous `md`.
- Détail : extrait de charge en Texte / Hexa (`SegmentedControl` ; Hexa par défaut si `excerpt_text`
  est NULL) dans un bloc à chasse fixe, « extrait des 512 premiers octets sur n » ; vue hexa en lignes de
  16 octets (8 sous `sm`) : décalage, octets, caractères imprimables (`.` sinon) ; Content Type, Payload
  Format Indicator, Message Expiry, Response Topic, Correlation Data (hexa), Subscription Identifiers,
  User Properties, alias utilisé ; accusé (type, code, délai) ; « Voir la connexion » (sous-onglet
  Connexions, ligne dépliée).

### Chiffré (P5.15b)

- Phrase d'en-tête : « Sessions TLS vers le port 8883 ou annonçant MQTT par ALPN ; le contenu n'est pas
  déchiffré. »
- `ExpandableList` (cartes sous `md`) : début, client -> serveur (`Endpoint`), SNI (mono, tronqué),
  version TLS (badge), ALPN, JA4 (mono, tronqué, copie), certificat (CN et badges expiré / auto-signé),
  raison (« Port 8883 » / « ALPN »). Détail : composant de détail existant de l'onglet TLS
  (`views/tls/SessionDetail.tsx`, route `/tls/sessions/{flow}`), sans le dupliquer.

### États et largeurs

- États : chargement (squelettes de la taille finale), erreur (Réessayer), session en import ou en échec
  (`SessionGate`), étape `mqtt` pas encore faite (arbre des topics « en attente », le reste disponible),
  aucune donnée (« Aucune connexion MQTT »), sous-onglet vide (« Aucun abonnement », « Aucun message
  stocké »...), plage vide (état commun « Rien dans la plage » avec « Effacer la plage »).
- 375 px : chiffres sur 2 colonnes, sous-onglets en liste déroulante, toutes les listes en cartes,
  détail d'une connexion en une colonne, hexa sur 8 octets, fil d'Ariane replié à « … / parent / nœud »
  avec le chemin complet en infobulle.
- 768 px : tableaux en mode tableau avec colonnes secondaires masquées (versions, première activité,
  topics publiés), détail en une colonne.
- 1280 px : détail de connexion en deux colonnes, Topics en deux volets.
- 1920 px : toutes les colonnes.
- Aucun graphique : les volumes sont des colonnes chiffrées ; pas de graphe client -> broker (illisible
  au-delà de quelques dizaines de nœuds ; la vue Network le couvre).

## Place prévue pour P5.16 (MQTT-SN) et P5.17 (IBM MQ)

- **MQTT-SN** (P5.16, UDP) : sous-onglet supplémentaire « MQTT-SN » de cet onglet (passerelles
  SEARCHGW / GWINFO / ADVERTISE, clients, topics enregistrés, messages), tables `mqttsn_*` dans sa propre
  plage (1700-1799 proposée), stats et signalements dans des routes `/mqtt/sn/...`. Le bandeau de chiffres
  et le compteur de module ajoutent MQTT-SN à ce moment ; l'arbre des topics peut intégrer les topics
  MQTT-SN résolus (décision de P5.16). Rien n'est préparé dans le code de P5.15 au-delà du `tab` d'URL
  extensible.
- **IBM MQ** (P5.17) : modèle différent (gestionnaires de files, canaux, files, pas de topics MQTT) :
  onglet séparé (« IBM MQ », plage 1800-1899 proposée), avec un renvoi croisé dans l'en-tête
  de l'onglet MQTT si les deux sont présents. Décision 8.

## Écarts assumés

- Pas de déchiffrement TLS ; MQTT sur `wss` non reconnu ; WebSocket compressé non décodé.
- Pas de décodage applicatif des charges (JSON non indenté, Sparkplug B `spBv1.0/...` en protobuf, CBOR) :
  texte ou hexa seulement.
- Charge utile limitée à un extrait de 512 octets ; au-delà de 10 000 paquets par connexion, seuls les
  compteurs et agrégats de topics continuent.
- MQTT détecté hors 1883 seulement par un CONNECT en premier paquet ; une connexion prise en cours hors
  1883 n'est pas reconnue.
- Un jeton passé en nom d'utilisateur sans mot de passe (pratique de certaines plateformes IoT) est
  affiché comme un nom d'utilisateur (non masqué), faute de pouvoir le distinguer d'un nom.
- Les brokers ne sont pas ajoutés comme rôle dans l'onglet Servers ni dans Open Ports (suivi possible).
- Les compteurs d'une connexion sous plage sont ceux de la connexion entière (pas de répartition
  temporelle stockée), comme les autres éléments repliés.

## Critères d'acceptation

- Fixtures `netsift_fixtures::mqtt` (encodeur de paquets 3.1, 3.1.1, 5.0) :
  1. 3.1.1 avec nom et mot de passe acceptés, SUBSCRIBE `capteurs/#` QoS 1, PUBLISH QoS 0, 1 et 2 avec
     accusés, message retenu, PINGs, DISCONNECT ;
  2. 5.0 avec propriétés : Topic Alias posé puis utilisé seul, User Properties, Content Type JSON, Payload
     Format Indicator, Session Expiry, CONNACK avec identifiant attribué et Reason String, abonnement
     partagé avec options, DISCONNECT du broker avec raison ;
  3. 3.1 (`MQIsdp`) anonyme accepté vers un broker d'adresse publique ;
  4. six CONNECT refusés (code 4 puis 0x86) d'un même client ;
  5. MQTT sur un port non standard (détecté), binaire quelconque sur 1883 et contenu commençant par
     `0x10` au nom invalide sur un autre port (non détectés) ;
  6. découpage : paquets coupés à chaque octet, plusieurs paquets par segment, longueur restante sur
     4 octets, PUBLISH de 1 Mio (extrait et taille justes), trou de réassemblage puis resynchronisation ;
  7. connexion prise en cours sur 1883 (sans CONNECT) ;
  8. abonnement `#` et `$SYS/#` avec `$SYS/broker/version` retenu (logiciel du broker) ;
  9. P5.15b : Upgrade HTTP avec `Sec-WebSocket-Protocol: mqtt`, trames masquées, paquet coupé entre deux
     trames, deux paquets dans une trame, ping / pong intercalés, close ; ClientHello vers 8883 avec SNI et
     ClientHello avec ALPN `mqtt` vers 443 ;
  10. hostiles : entier variable de 5 octets, longueurs internes au-delà de la longueur restante, topic
      UTF-8 invalide, type 0, propriétés dupliquées ou inconnues, QoS 3.
- Tests du parseur (chaque type, chaque version, propriétés, bornes, malformés) et du décodeur WebSocket.
- Tests de l'analyseur (snapshots `insta` des enregistrements) : alias résolus, accusés fusionnés,
  identifiants (secret absent de `Debug`), signalements, bornes, resynchronisation.
- Test d'équivalence fichier unique / chunks avec 1, 4 et 7 shards sur toutes les tables MQTT, étape
  `mqtt` comprise.
- Tests du store (étape `mqtt` : niveaux vides, profondeur, repli au-delà de la borne) et de l'API
  (compteurs égaux entre liste, `stats` et module, filtres, validation 400, plage ponctuelle et
  chevauchement, plage couvrant la session identique à sans plage, pages keyset sans doublon ni trou,
  détail avec secret, 404, aucune liste avec secret, rendu des charges `<script>` et caractères bidi
  échappés).
- Fuzz : nouvelle cible `mqtt` (parseur et moteur de connexion en flux) ; décodeur WebSocket ajouté à la
  cible `http` (P5.15b).
- UI (Vitest) : sous-onglets et URL, dépliage d'une connexion avec mot de passe masqué puis révélé,
  transcription, navigation dans l'arbre des topics, Texte / Hexa d'un extrait (balises affichées comme
  texte), pastilles de filtre, signalements, mention « Session entière » sous plage.
- `./x.sh shots mqtt all`, `mqtt-range`, `mqtt-connection` (première connexion dépliée), `mqtt-topics`
  (un niveau ouvert avec détail), `mqtt-messages` (un message déplié en hexa) et, en P5.15b, `mqtt-tls`,
  verts à 375, 768, 1280 et 1920 px, en `en` et `fr`, aucun mot de passe en clair sur les captures.
- Moins de 300 ms par requête sur une session synthétique volumineuse (1 M de PUBLISH stockés, 100 000
  connexions, 100 000 topics), mesure notée ici ; durée de l'étape `mqtt` notée.

## Découpage

La tâche dépasse une branche de taille habituelle (parseur, moteur, analyseur, deux transports de plus,
six sous-onglets). Découpage retenu (décision 9) :

- **P5.15a `feat/mqtt`** : parseur MQTT, moteur de connexion, analyseur TCP (1883 et détection
  heuristique), identifiants, libellé `mqtt`, migration `1600_mqtt.sql`, étape `mqtt`, API (sans
  `/mqtt/tls`), vue avec bandeau, signalements et sous-onglets Connexions, Clients, Brokers, Topics,
  Messages ; fixtures 1 à 8 et 10, cible de fuzz `mqtt`, démonstration (`add_mqtt` dans `demo.rs`),
  shots. Taille comparable à SIP.
- **P5.15b `feat/mqtt-ws-tls`** (après P5.15a, en parallèle de P5.16 et P5.17) : décodeur WebSocket,
  phase WebSocket de l'analyseur `http` qui alimente le moteur MQTT, colonnes `ws_*` déjà prévues par
  P5.15a, filtre « Transport » ; MQTT chiffré (`1601_mqtt_tls.sql`, `/mqtt/tls`, sous-onglet Chiffré,
  chiffre du bandeau, compteur de module) ; fixtures 9, cible `http` étendue, shots `mqtt-tls`.

Un ADR est proposé avec P5.15b : un analyseur (`http`) qui délègue un tunnel à un moteur d'un autre
protocole dans le même shard (alternative écartée : l'analyseur `mqtt` relit lui-même l'Upgrade HTTP,
ce qui dupliquerait le parseur d'en-têtes HTTP).

## Décisions

Réponses retenues par l'utilisateur le 2026-11-23 (les recommandations de la proposition) :

1. **Extrait de charge stocké** : 512 premiers octets par PUBLISH (et par testament).
2. **Mot de passe dans le détail de connexion** : affiché aussi là, masqué par défaut (`SecretValue`), servi
   seulement par la route de détail, comme FTP et Telnet, en plus de Credentials.
3. **Transcription fusionnée** : accusés rattachés à leur PUBLISH / SUBSCRIBE / UNSUBSCRIBE, PINGREQ /
   PINGRESP seulement comptés.
4. **Plafond de 10 000 paquets stockés par connexion** ; compteurs et agrégats de topics complets au-delà.
5. **Brokers publics** : catégorie d'adresse seulement, sans liste intégrée de brokers connus.
6. **Seuil des échecs répétés** : 5 connexions refusées d'une même adresse vers un même broker.
7. **WebSocket compressé** (`permessage-deflate`) : métadonnées seulement (P5.15b).
8. **MQTT-SN** en sous-onglet de MQTT (P5.16), **IBM MQ** en onglet séparé (P5.17).
9. **Découpage** en P5.15a puis P5.15b.
10. **Libellé `mqtt`** pour TCP 1883 dans la classification ; 8883 reste `tls`.
11. **Charges** : texte et hexadécimal seulement, sans décodage applicatif (JSON indenté, Sparkplug B).
