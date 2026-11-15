# Save PCAP (export pcapng)

Tâche ROADMAP P4.3. Décision d'architecture : ADR-021.

## But

Récupérer les paquets bruts d'une session, d'une plage horaire ou d'un flux dans un fichier pcapng
ouvrable par Wireshark ou tcpdump, sans relancer d'outil externe et dans l'ordre exact du recollage
de l'import (chunks fusionnés, doublons écartés).

## Données

- Sources : les chunks de la session (`chunks` : chemin, taille, mtime, empreinte des 64 premiers
  Kio, `first_ts`/`last_ts` = plus petit et plus grand horodatage lus). Les captures ne sont jamais
  copiées : l'export les relit.
- Flux : la ligne `flows` (protocole IP, extrémités et ports, premier et dernier horodatage).
  L'identifiant ne sert qu'à trouver la ligne, jamais à reconnaître un paquet.
- Écriture : `netsift_capture::writer::PcapNgWriter` (pur Rust, d'après la spécification pcapng) :
  un SHB, un IDB par couple (linktype, snaplen) rencontré, `if_tsresol = 9` (nanosecondes), un EPB
  par paquet avec la longueur d'origine.
- Moteur : `netsift_engine::export` (`plan_export` puis `ExportPlan::run`).

### Sélections

| Sélection | Paquets | Chunks relus |
|---|---|---|
| Session | tous | tous les chunks lus par l'import (`ok`, `truncated`) |
| Plage `[from, to]` | `from <= ts <= to`, bornes incluses | ceux dont `[first_ts, last_ts]` coupe la plage |
| Flux | les deux sens du 5-tuple, entre premier et dernier horodatage du flux (sans borne basse si la session est lue hors ordre) | ceux qui coupent `[first_ts - 30 s, last_ts]` (`[-inf, last_ts]` hors ordre) |

- Ordre et doublons : lecteur `ChunkSetSource` de l'import (fusion k-voies par horodatage, égalités
  départagées par chunk puis position), chunks doublons et ignorés jamais lus. La lecture s'arrête
  au premier paquet postérieur à la fin demandée, sauf si l'import n'a pas lu la session dans
  l'ordre des horodatages.
- Horodatages qui reculent dans un fichier : chaque fichier est rendu dans son ordre. Si la session
  porte une anomalie `out_of_order`, `timestamp_backwards` ou `merge_fanout_limit`, si sa liste
  d'anomalies a été tronquée (`limit_reached`) ou si ses statistiques de fin d'import manquent
  (import arrêté brutalement), la lecture ne s'arrête jamais avant la fin des chunks retenus, et un
  flux n'a pas de borne basse : son `first_ts` est l'heure de son premier paquet *lu*, pas la plus
  petite. Le flux est alors choisi par sa fenêtre de chunks et son 5-tuple, ce qui peut y inclure un
  flux antérieur de même 5-tuple.
- Erreurs de lecture (fichier inchangé mais corrompu, comme à l'import) : comptées et signalées dans
  le job, l'UI et la CLI (« des paquets peuvent manquer »).
- Un chunk dont la fin est inconnue (import interrompu avant sa lecture) est relu s'il commence avant
  la fin demandée.
- Flux et fragments IP : le premier fragment (offset 0) porte les ports et est reconnu comme un
  paquet entier ; les fragments suivants du même datagramme (source, destination, identification)
  sont inclus si le premier l'a été. La table de flux datant un datagramme réassemblé par son dernier
  fragment, les fragments sont acceptés jusqu'à 30 s (délai de défragmentation) avant le début du
  flux.
- Limites connues (flux) : un fragment arrivé avant son premier fragment n'est pas inclus ; les
  erreurs ICMP qui concernent le flux appartiennent à un flux ICMP ; deux flux successifs de même
  5-tuple dont les fenêtres se recouvrent (port réutilisé aussitôt, horodatages identiques) ne se
  distinguent pas : exporter l'un donne les paquets des deux.
- Snaplen d'un IDB : celui du chunk pour les paquets de sa première interface (seul snaplen que
  l'import enregistre), 0 (inconnu) sinon. Horodatage négatif écrit 0.

### Contrôle des sources

Avant la lecture, chaque chunk à relire est sondé comme à l'inventaire : fichier absent ou illisible,
taille, date de modification ou empreinte différentes -> refus. Le contrôle est refait après la
lecture, avant de publier le fichier. Aucun fichier partiel ne reste.

### API

| Méthode | Chemin | Réponse |
|---|---|---|
| POST | `/sessions/{id}/exports/pcap` `{ scope: "session" }`, `{ scope: "range", from_us, to_us }` ou `{ scope: "flow", flow_id }` | 202 `ExportJob` |
| GET | `/sessions/{id}/exports` | `ExportJob[]`, plus récent d'abord |
| GET | `/exports/{job}` | `ExportJob` (état `running`, `done`, `failed`, `cancelled`, progression en octets sources lus) |
| POST | `/exports/{job}/cancel` | `ExportJob` |
| GET | `/exports/{job}/file` | fichier en pièce jointe, `application/octet-stream`, streamé |
| GET | `/sessions/{id}/connections/{conversation}/flows` | `Page<FlowInfo>` (flux d'une conversation, index `flows_conversation`, migration 0401) |

- Erreurs synchrones (problem+json) : 404 session ou flux inconnu, 400 plage inversée ou flux mal
  formé, 409 `export-source-missing` / `export-source-modified` (détail : nom du fichier seulement),
  409 `too-many-exports` (2 exports simultanés au plus), 403 `read-only` (serveur `--read-only`).
- Une erreur pendant l'écriture (source modifiée en cours de lecture, disque plein) passe le job en
  `failed` avec le même document (`type`, `title`, `status`, `detail`).
- Fichier : `<données>/exports/netsift-<session>-<session|range|flow-N>-<job>.pcapng`, nom choisi
  par le serveur (aucun champ du client n'y entre), écrit en `.part` puis renommé ; jamais écrasé.
  Les `.part` orphelins sont supprimés au démarrage du serveur.
- Les fichiers restent dans `exports/` (les jobs, eux, vivent en mémoire et disparaissent au
  redémarrage).

### CLI

`netsift export pcap --data-dir D --session ID [--flow N | --from-ns A --to-ns B] -o FICHIER`
(même code moteur ; le fichier de sortie n'est jamais écrasé ; session `importing` ou `failed` refusée ; erreurs de lecture signalées).

## Mise en page

- Overview, en-tête : bouton « Save PCAP » (session prête ou incomplète). Dialogue : choix
  « Toute la session » / « Plage horaire » ; la plage est saisie en heure locale au format ISO
  (`2026-11-08 14:03:12`, fraction facultative), préremplie avec la période capturée ; une fin sans
  fraction inclut toute sa seconde. Puis l'état du job dans le même dialogue.
- Connections, tableau des conversations : première colonne étroite, bouton icône « Flux de A vers B »
  par ligne (visible sans défilement horizontal à 1280 px), qui ouvre la liste des flux de
  la conversation (protocole, ports, protocole applicatif, début, durée, octets, paquets) avec un
  bouton « Save PCAP » par flux et l'état de son dernier export.
- État d'un export : en cours (pourcentage et octets sources lus, Annuler), réussi (paquets, taille,
  nom du fichier ; « Ouvrir le dossier » en desktop par le plugin opener limité à `exports/`,
  « Télécharger » en mode web), échec (message traduit et détail), annulé.

## Critères d'acceptation

- Aller-retour export puis relecture par `netsift-capture` : mêmes paquets, octets, horodatages ns
  et ordre, pour un fichier unique, ses chunks séquentiels, et des chunks qui se chevauchent (fusion
  k-voies) avec un doublon (`crates/netsift-engine/tests/export.rs`).
- Fichier aux horodatages non monotones : export de flux (autant de paquets que `packets_total`)
  et de plage sans perte ; erreur de lecture comptée.
- Flux : les deux sens, aucun paquet d'un autre flux des mêmes hôtes, fragments inclus ; plage aux
  bornes incluses ; linktypes mixtes dans un fichier valide ; chunk absent ou modifié refusé sans
  fichier restant, y compris modifié pendant l'export ; annulation sans fichier restant.
- Routes : statuts, nom non contrôlable par le client, téléchargement en pièce jointe.
- Tests Vitest du dialogue et de la liste des flux ; `./x.sh shots` verts en `en` et `fr` pour
  `overview`, `overview-export` (dialogue ouvert sur la plage), `connections` et `connections-flows`
  (liste des flux ouverte). Le serveur des captures est en lecture seule : les boutons d'export y
  sont désactivés.
