# Captures découpées en chunks

Objectif : l'utilisateur importe **un dossier** ; NetSift détecte le ou les jeux de chunks,
les ordonne, vérifie la continuité et les analyse comme **une seule capture continue**
(un flux TCP ou une transaction DNS à cheval sur deux fichiers est vu une seule fois).

## Sources à supporter

| Outil | Option | Nommage produit |
|---|---|---|
| dumpcap / Wireshark / tshark | `-b filesize:N`, `-b duration:N`, `-b files:N` (ring buffer) | `prefix_NNNNN_YYYYmmddHHMMSS.pcapng` (défaut) |
| dumpcap ≥ 4.x | `-b nametimenum:2` | `prefix_YYYYmmddHHMMSS_NNNNN.pcapng` |
| editcap | `-c N` / `-i N` | `prefix_NNNNN_YYYYmmddHHMMSS.ext` |
| tcpdump | `-C N` (taille) | `name`, `name1`, `name2`, ... (ou zéro-paddé avec `-W`) |
| tcpdump | `-G N` (rotation temporelle) | nom libre avec motif `strftime`, ex. `cap-%Y%m%d-%H%M%S.pcap` |
| tout outil | compression (gzip, zstd, LZ4 frame) | même nom suffixé `.gz`, `.zst` ou `.lz4` |

Extensions acceptées : `.pcap`, `.pcapng`, `.cap`, `.dmp`, sans extension (tcpdump `-C`),
chacune éventuellement suffixée `.gz`, `.zst` ou `.lz4` (insensible à la casse). Le format **et la
compression** sont déterminés par le **magic number**, jamais par l'extension : un `.pcap` compressé
en zstd est lu, un `.pcap.zst` non compressé aussi. Le suffixe de compression ne sert qu'au nommage
(motifs ci-dessous, copie compressée d'un fichier).

Compression (`netsift_capture::reader`, ADR-029) : décompression en flux, mémoire bornée, progression
sur les octets compressés lus. gzip multi-membres ; zstd (trames concaténées, trames ignorables,
somme de contrôle vérifiée, fenêtre de 32 Mio au plus : `zstd --long` et `--ultra -21/-22` refusés
avec la raison) ; LZ4 au format frame de l'outil `lz4` (blocs indépendants ou chaînés, sommes de
contrôle vérifiées ; ancien format `lz4 -l` et dictionnaires non pris en charge). Fichier compressé
coupé : `truncated_tail` comme un `.gz` tronqué ; flux corrompu : erreur de lecture du chunk. Limite :
le décodeur zstd ne rend la dernière fenêtre d'une trame qu'à sa fin, et LZ4 un bloc entier (4 Mio par
défaut avec l'outil `lz4`), donc un fichier coupé perd au plus cette quantité avant la coupure ; un
petit fichier coupé avant son premier bloc complet est signalé illisible (`unreadable_chunk`).

## Algorithme d'import d'un dossier

1. **Inventaire** (non récursif par défaut, option récursive) : pour chaque fichier, lire l'en-tête
   et le premier paquet (magic, format, linktype(s), snaplen, précision, `first_ts`). Ignorer les
   fichiers non reconnus en les listant dans le rapport. Fichiers vides : signalés, ignorés.
2. **Regroupement** en jeux de chunks par motif de nom, dans cet ordre de priorité :
   - `^(?P<prefix>.+)_(?P<num>\d{5,})_(?P<ts>\d{14})\.(?P<ext>[^.]+)(\.(gz|zst|lz4))?$`
   - `^(?P<prefix>.+)_(?P<ts>\d{14})_(?P<num>\d{5,})\.(?P<ext>[^.]+)(\.(gz|zst|lz4))?$`
   - tcpdump `-C` : même nom de base + suffixe numérique final (`cap.pcap`, `cap.pcap1`, ...), avant
     un éventuel suffixe de compression (`cap.pcap1.zst`, tcpdump `-z zstd`)
   - sinon : un groupe par préfixe commun ; à défaut, tout le dossier = un groupe.
   Plusieurs groupes détectés -> l'UI propose de choisir (un groupe = une session) ou de tout fusionner.
3. **Ordonnancement** dans un groupe : par numéro de séquence s'il existe, sinon par `first_ts`,
   puis par nom. Le tri par numéro doit être **numérique** (pas lexicographique).
4. **Contrôles de continuité** (non bloquants, enregistrés dans `anomalies`, affichés dans l'UI) :
   - numéros de séquence manquants (fichier supprimé par le ring buffer `-b files:`) ;
   - trou temporel entre `last_ts(i)` et `first_ts(i+1)` > seuil (défaut 5 s ou 2 x l'intervalle médian) ;
   - chevauchement temporel entre chunks consécutifs ;
   - doublon (même taille + même empreinte des 64 premiers Kio + même `first_ts`) -> ignoré ;
   - copie compressée à côté de l'original (`cap.pcap` et `cap.pcap.gz`, `.zst` ou `.lz4` : même nom
     sans suffixe, même premier paquet) -> doublon, le fichier non compressé est gardé (à défaut, la
     première copie compressée) ;
   - linktype ou snaplen différents d'un chunk à l'autre (accepté : chaque paquet garde son linktype) ;
   - dernier paquet tronqué (fichier en cours d'écriture au moment de la copie) -> ignoré proprement ;
   - horodatages qui reculent à l'intérieur d'un chunk -> signalés, paquets conservés.
5. **Lecture** :
   - chunks disjoints dans le temps (cas normal) : lecture séquentielle concaténée ;
   - chunks qui se chevauchent (ex. plusieurs interfaces capturées dans des fichiers séparés) :
     **fusion k-voies** par horodatage avec un tas borné (un lecteur ouvert par chunk actif) ;
   - pcapng : gérer plusieurs IDB (une interface = un linktype + une résolution de timestamp),
     blocs SHB multiples (pcapng concaténés), EPB/SPB/PB, ignorer proprement les blocs inconnus ;
   - pcap : microsecondes et nanosecondes (magic `a1b23c4d`), deux endianness.
6. **Continuité d'état** : la table de flux, le réassemblage TCP, les transactions DNS/HTTP, etc.
   ne sont **pas** réinitialisés entre deux chunks. Seul le temps paquet fait expirer les flux :
   un trou temporel plus long que le timeout ferme naturellement les flux concernés.
7. **Progression** : basée sur les octets lus / octets totaux de tous les chunks retenus ;
   l'UI affiche le chunk en cours, le débit et l'ETA ; annulation possible à tout moment
   (la session reste consultable avec ce qui a été analysé, marquée « incomplète »).

## Ce que l'UI montre (vue Captures + en-tête de session)

- Liste des chunks : n°, nom, taille, début, fin, durée, paquets, état (ok / tronqué / doublon / ignoré).
- Frise temporelle de couverture : un segment par chunk, trous et chevauchements mis en évidence.
- Bandeau d'anomalies résumé (« 2 fichiers manquants dans la séquence, 1 trou de 43 s »), détail dépliable.
- Horodatages qui reculent : chaque anomalie donne le recul (`précédent - courant`, « recule de 1,2 ms »), le résumé
  et le journal d'import le plus grand. Lecture : µs ou ms = pcapng multi-interface ou horodatage par la carte
  réseau, sans gravité ; secondes ou plus = correction de l'horloge (NTP, changement manuel) pendant la capture.

## Tests obligatoires (pcaps synthétiques via `netsift-fixtures`)

Le crate de fixtures sait découper un scénario en chunks par taille **ou** par durée, avec les
conventions de nommage dumpcap (les deux ordres), editcap et tcpdump `-C`. Cas à couvrir :

- flux TCP HTTP coupé au milieu d'une requête entre deux chunks -> une seule transaction ;
- requête DNS dans le chunk N, réponse dans le chunk N+1 -> une transaction appariée ;
- fichiers fournis dans le désordre, numérotation > 99 999, tri numérique ;
- chunk manquant, trou temporel, chunk dupliqué, dernier paquet tronqué, fichier vide ;
- mélange pcap / pcapng / `.gz` / `.zst` / `.lz4` dans un même jeu, et même résultat que le fichier
  non compressé ;
- deux jeux de préfixes différents dans le même dossier -> deux groupes proposés ;
- chevauchement (deux interfaces) -> fusion k-voies, ordre global croissant vérifié ;
- résultat identique (snapshot `insta` des tables) entre « fichier unique » et « même trafic découpé ».

Ce dernier test est le critère d'acceptation principal de la fonctionnalité.

## Plus tard (phase 5)

- Ajout de nouveaux chunks à une session existante (append si `first_ts` > dernier ts analysé).
  Le compteur de trames globales doit alors reprendre au nombre de paquets déjà importés : l'index
  de trame sert d'identifiant de flux (ADR-022), et repartir de 0 ferait entrer les nouveaux flux en
  collision avec les lignes existantes, fusionnées sans erreur par les upserts.
- Surveillance d'un dossier en cours d'écriture par dumpcap (analyse au fil de l'eau).
- `.zst` / `.lz4`.
