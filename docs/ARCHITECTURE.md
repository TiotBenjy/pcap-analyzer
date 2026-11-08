# Architecture

## Vue d'ensemble

```
 dossier de chunks / fichier unique
            |
   [capture]  détection du jeu de chunks, ordre, contrôle de continuité,
            |  lecture pcap/pcapng(.gz), fusion k-voies si chevauchement
            v
   [decode]   couche liaison -> IP (défragmentation) -> TCP/UDP
            |  (Ethernet, VLAN, Linux SLL/SLL2, raw IP, loopback, radiotap + 802.11)
            v
   [flows]    table de flux sharded (hash 5-tuple -> N workers), réassemblage TCP borné
            |
            v
   [analyze]  analyseurs (DNS, HTTP, TLS, SMB/NTLM, SNMP, credentials, ...) -> Records
            |
            v
   [store]    writer SQLite unique, transactions par lots, agrégats time-series
            |
            v
   [api]      axum : sessions, import (progression SSE), requêtes paginées, blobs
            |
     +------+--------+
     v               v
  Tauri (desktop)   navigateur (mode dev conteneur, http://localhost:5173)
     \_____ même frontend React (ui/) _____/
```

## Organisation du dépôt

```
Cargo.toml                 workspace (resolver 3, lints partagés)
rust-toolchain.toml        Rust 1.99.1
crates/
  netsift-capture/         lecture pcap/pcapng/gz, détection & ordonnancement des chunks
  netsift-dissect/         parseurs purs, sans I/O, fuzzables (L2..L7)
  netsift-flow/            défragmentation IP, table de flux, réassemblage TCP
  netsift-analyze/         trait Analyzer + analyseurs par protocole + classification
  netsift-store/           schéma SQLite, migrations, writer par lots, requêtes
  netsift-geo/             GeoIP (mmdb DB-IP Lite), classification d'adresses
  netsift-engine/          orchestration du pipeline (threads, progression, annulation)
  netsift-api/             routes axum + DTO (ts-rs -> ui/src/api/types/)
  netsift-cli/             binaire `netsift` : ingest, query, serve, export
  netsift-fixtures/        générateur de pcaps synthétiques + découpeur en chunks (dev only)
apps/desktop/              crate Tauri (tauri.conf.json, icônes, capabilities)
ui/                        frontend React/Vite
fuzz/                      cibles cargo-fuzz (nightly, hors workspace)
docker/                    image de dev/build
scripts/                   wt.sh (worktrees), release.sh, scripts exécutés dans le conteneur
docs/                      cette documentation
```

Dépendances autorisées entre crates (pas de cycle, pas de raccourci) :
`dissect` <- `flow`, `analyze`; `flow` <- `analyze` <- `engine` (qui atteint `flow` et `dissect` via les
réexports d'`analyze`); `capture` <- `engine`; `store` <- `engine`, `api`; `geo` <- `analyze`, `api`;
`engine` + `store` <- `api` <- `cli`, `desktop`; `engine` + `store` <- `cli` (`netsift ingest`); `fixtures` <- `cli`
uniquement derrière la feature `demo` (`netsift demo-session`, jamais dans les builds de release).
`dissect` ne dépend d'aucune autre crate interne.

## Modèle d'exécution du pipeline

- 1 thread lecteur (`capture`) : produit des `RawPacket { ts_ns, chunk_id, offset, linktype, data: Bytes }`
  dans un canal borné (backpressure).
- 1 thread décodeur L2/L3 qui calcule la clé de flux et distribue par hash vers N shards
  (N = cœurs - 2, min 1). Un flux est toujours traité par le même shard : l'ordre intra-flux est garanti.
- N workers de flux : défragmentation, réassemblage TCP, appel des analyseurs.
- 1 thread writer SQLite : reçoit des `Record` par canal borné, insère par lots
  (transaction toutes les ~50 000 lignes ou 250 ms), met à jour la progression.
- Annulation : `CancellationToken` partagé ; progression : octets lus / octets totaux de tous les chunks.
- Le temps « courant » est celui des paquets, jamais l'horloge murale (timeouts de flux, expiration).

## Trait d'analyseur (à figer en fin de phase 1 avant la parallélisation)

```rust
pub trait Analyzer: Send {
    fn id(&self) -> AnalyzerId;                          // "dns", "http", ...
    fn on_packet(&mut self, ctx: &PacketCtx, pkt: &Decoded<'_>, out: &mut dyn RecordSink) {}
    fn on_stream(&mut self, ctx: &StreamCtx, dir: Direction, data: &[u8], out: &mut dyn RecordSink) {}
    fn on_flow_end(&mut self, ctx: &FlowCtx, out: &mut dyn RecordSink) {}
    fn finish(&mut self, out: &mut dyn RecordSink) {}
}
```

- Un analyseur est instancié **par shard** ; il ne partage pas d'état mutable.
- Les agrégations globales (compteurs, top N) sont faites en SQL à la lecture, pas en mémoire.
- `Record` est un enum : chaque analyseur ajoute ses variantes et sa migration SQL.
- Les sous-analyseurs de credentials sont émis par chaque protocole (`Record::Credential`),
  l'onglet Credentials ne fait qu'agréger.

## Stockage

Répertoire de données de l'application (`dirs::data_local_dir()/NetSift`, local et non itinérant sous Windows,
ou `.data/` en mode dev) :

```
sessions/<session_id>/
  session.db          SQLite, WAL, page_size 8192, synchronous=NORMAL pendant l'import
  blobs/ab/abcdef...  objets extraits (images, documents, certificats DER), SHA-256, dédupliqués
  thumbs/ab/...       miniatures PNG générées côté Rust (crate `image`, décodeurs purs Rust)
catalog.db            liste des sessions (nom, chemins sources, état, tailles)
exports/              fichiers exportés (seul dossier que l'UI desktop peut ouvrir)
geoip/                base GeoIP facultative, prioritaire sur celle du bundle
```

Les captures sources ne sont **jamais copiées** : la session référence les chemins des chunks
(+ taille, mtime, empreinte des 64 premiers Kio pour détecter une modification).
L'export « Save PCAP » (flux ou plage temporelle) relit uniquement les chunks dont la plage
temporelle intersecte la demande.

Tables principales (chaque analyseur ajoute les siennes via sa migration) :

| Table | Contenu |
|---|---|
| `meta` | version du schéma, options d'import, statistiques globales |
| `chunks` | chemin, n° de séquence, format, linktypes, premier/dernier ts, paquets, octets, anomalies |
| `anomalies` | trous temporels, numéros manquants, chevauchements, paquets tronqués, doublons |
| `timeseries` | `(bucket_s, proto) -> bytes, packets` (bucket 1 s ; l'API rééchantillonne) |
| `hosts` | IP, MAC, noms (DNS/NBNS/DHCP), pays, catégorie (privé/public/multicast...) |
| `flows` | 5-tuple, premier/dernier ts, octets/paquets par sens, protocole applicatif, état TCP |
| `dns_*`, `http_*`, `tls_*`, `smb_*`, `credentials`, `objects`, `servers`, ... | par analyseur |

Règles : index sur toutes les colonnes filtrables/triables par l'UI ; FTS5 pour la recherche
texte (noms DNS, URL, en-têtes) ; pagination par **keyset** (pas d'OFFSET sur grosses tables) ;
toute requête d'une vue doit répondre en < 300 ms sur une session de 10 M paquets.

## API HTTP (axum)

- Liaison `127.0.0.1:<port aléatoire>` + en-tête `Authorization: Bearer <jeton aléatoire>`
  (en desktop, Tauri transmet URL et jeton au frontend par une commande `get_api_endpoint`).
- Mode dev conteneur : `netsift serve --bind 0.0.0.0:7878 --token-file ...` ; le port n'est
  publié que sur `127.0.0.1` de l'hôte ; le proxy Vite ajoute le jeton.
- Préfixe `/api/v1`. Réponses JSON, erreurs `application/problem+json`.
- Listes : `?limit=&cursor=&sort=&q=&filters...` -> `{ items, next_cursor, total_estimate }`.
- Graphiques : endpoints dédiés qui renvoient des données **déjà agrégées et bornées**
  (top N + « autres », séries rééchantillonnées ≤ 2 000 points).
- Import : `POST /sessions/import { path }` -> id ; progression via SSE `GET /sessions/{id}/events`.
- Blobs : `GET /objects/{sha256}` avec `Content-Disposition` et `Content-Security-Policy: sandbox`.
- En mode dev web, la sélection de dossier passe par `GET /fs/browse?path=` limité aux racines
  autorisées (`/captures` monté en lecture seule). En desktop : dialogue natif Tauri.

## Desktop (Tauri 2)

- `apps/desktop` démarre dans `setup` : répertoire de données (créé au premier lancement, avec `exports/`),
  `recover_interrupted`, base GeoIP, API dans le runtime tokio de Tauri, **puis** la fenêtre
  (`create: false`) sur `ui/dist`. Si une étape échoue, un dialogue natif l'explique, car une release
  Windows n'a pas de console (ADR-012).
- Instance unique : un second lancement ramène la fenêtre existante au premier plan et quitte.
- Fermeture (fenêtre ou Cmd+Q sous macOS) : si un import tourne, un dialogue natif demande confirmation.
  À la sortie, l'API annule les imports et attend leur writer pendant au plus `STOP_LIMIT` (environ 15 s) ;
  les sessions annulées passent `incomplete`.
- Plugins : `dialog` (choix de dossier ou de fichier, `nativePicker()` côté UI), `opener` (limité au
  dossier `<données>/exports`). Capabilities minimales, sans `core:default`.
- GeoIP : `<données>/geoip/dbip-country-lite.mmdb` si présent, sinon la base du bundle
  (`resources/geoip/`). L'état est visible dans « Paramètres > À propos » (`GET /server-info`).
- CSP stricte : `default-src 'self'; connect-src http://127.0.0.1:*; img-src 'self' http://127.0.0.1:* data:`,
  plus `style-src 'self' 'unsafe-inline'` pour le SVG d'ECharts et des directives fermées (détail : ADR-006).
- Aucune autre fenêtre, aucun accès réseau sortant.
- Bundles publiés par `release.yml` sur tag `vX.Y.Z` (ADR-011, procédure dans `docs/GIT_WORKFLOW.md`) :
  Linux `.AppImage`, `.deb`, `.rpm` (Ubuntu 22.04 pour la compatibilité glibc), Windows NSIS + MSI
  (`windows-latest`), macOS `.dmg` universel Apple Silicon + Intel (`macos-15`, macOS 11 minimum),
  plus `SHA256SUMS.txt`. Non signés (signature ad hoc sur macOS, sans notarisation). En local,
  `./x.sh desktop` construit AppImage + .deb dans le conteneur.
- Version : celle de `[workspace.package]` dans `Cargo.toml`, lue par Tauri (pas de `version` dans
  `tauri.conf.json`) ; `scripts/check-version.sh` la compare à l'UI, à `Cargo.lock` et au tag.

## GeoIP et classification

- Base pays **DB-IP IP to Country Lite** (format mmdb, licence CC BY 4.0, attribution dans « À propos »).
  Téléchargée par `./x.sh geoip` en dev (`./x.sh desktop` la copie dans le bundle) et par `release.yml`
  pour les bundles (`scripts/ci/geoip.sh`). L'application fonctionne sans (pays inconnu).
- Classification d'adresses : privée (RFC 1918 / ULA), publique, broadcast, multicast, link-local, loopback,
  CGNAT. Utilisée pour les filtres et légendes (LAN / Public / Broadcast / Multicast / Link-local / Loopback).

## Performance (cibles à mesurer en phase 4)

- Ingestion ≥ 80 Mo/s sur 4 cœurs pour du trafic mixte ; 5 Go de chunks en < 2 min.
- Mémoire résidente < 1,5 Go quelle que soit la taille de la session (tout est borné).
- Bornes par défaut (configurables) : 16 Mio par flux pour le réassemblage TCP, 64 Mio max pour
  un objet extrait, timeout de flux TCP 300 s / UDP 60 s en temps paquet, 2 M flux actifs max (LRU).
