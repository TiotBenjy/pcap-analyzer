# Feuille de route

Chaque tâche indique sa **branche** (= nom du worktree), ses dépendances et peut être confiée
à un agent `implementer`. Les tâches d'une même « vague » sont indépendantes et se lancent
en parallèle (skill `parallel`). Seul l'orchestrateur coche les cases, sur `main`, après fusion.

Légende : `[ ]` à faire, `[~]` en cours (branche ouverte), `[x]` fusionné dans `main`.

---

## Phase 0 — Amorçage (séquentiel, un seul agent)

Objectif : un squelette qui compile, se teste, se lance en local et se construit en CI.

- [ ] **P0.1** `chore/toolchain` — Construire l'image (`./x.sh image`), vérifier `./x.sh cargo --version`,
      `./x.sh npm --version`, `./x.sh shell`. Corriger `docker/Dockerfile` / `x.sh` si besoin.
- [ ] **P0.2** `chore/workspace` — Workspace Cargo (resolver 3, édition 2024, `[workspace.lints]` :
      `unsafe_code = "forbid"` hors desktop, `clippy::pedantic` en warn ciblé, `unwrap_used`/`expect_used`/
      `indexing_slicing`/`panic` = deny dans `netsift-dissect`), toutes les crates de `ARCHITECTURE.md`
      créées vides avec un test fumée, `exclude = [".worktrees", "fuzz"]`. `./x.sh check` vert.
- [ ] **P0.3** `chore/ui-shell` — `ui/` : Vite + React + TS strict + Tailwind 4 + ESLint + Vitest + Playwright
      (version épinglée identique à `PLAYWRIGHT_VERSION` du Dockerfile). **Utiliser les versions de
      `docs/STACK_VERSIONS.md`** (combinaison testée : install + tsc + build OK). Tailwind 4 via
      `@tailwindcss/vite` + `@theme` (pas de `tailwind.config.js`). Code-splitting des vues et des graphes
      dès le départ (bundle echarts+sigma > 500 Kio sinon). AppShell + Sidebar avec toutes
      les entrées (onglets futurs inclus, désactivés), routes vides, thèmes clair/sombre, i18n en/fr,
      composants communs de base (`Card`, `Chart`, `DataTable`, `EmptyState`, `FilterBar`, `Toggle`, `Badge`).
- [ ] **P0.4** `chore/dev-loop` — `netsift serve` minimal (axum, `/api/v1/health`), `./x.sh dev`
      (backend + Vite avec proxy et jeton), `./x.sh shots` avec les assertions de `UI_GUIDELINES.md`
      sur la page d'accueil. L'utilisateur peut ouvrir http://localhost:5173.
- [ ] **P0.5** `chore/desktop` — `apps/desktop` Tauri 2 qui démarre l'API embarquée et affiche l'UI ;
      `./x.sh desktop` produit AppImage + .deb dans `dist/` ; icônes provisoires sobres.
- [ ] **P0.6** `ci/github-actions` — Rendre `.github/workflows/ci.yml` et `release.yml` cohérents avec la
      structure réelle (chemins Tauri, cache). Vérification : pousser la branche, l'utilisateur confirme
      le statut vert dans GitHub (pas de `gh`).

Sortie de phase : `./x.sh check`, `./x.sh dev`, `./x.sh shots`, `./x.sh desktop` fonctionnent.

---

## Phase 1 — Moteur d'ingestion

### Vague 1.A (parallèle)

- [ ] **P1.1** `feat/capture-reader` — `netsift-capture` : pcap (µs/ns, 2 endianness), pcapng (SHB multiples,
      IDB multiples, EPB/SPB/PB, blocs inconnus), `.gz`, détection par magic, lecture en streaming,
      tolérance au dernier paquet tronqué. Dép. : P0.2.
- [ ] **P1.2** `feat/chunk-sets` — Inventaire de dossier, regroupement, tri numérique, contrôles de continuité,
      fusion k-voies, rapport d'anomalies (`docs/CHUNKED_CAPTURES.md`). Dép. : P0.2 (interface du lecteur
      définie d'un commun accord : trait `PacketSource`, mock en attendant P1.1).
- [ ] **P1.3** `feat/dissect-l2-l4` — `netsift-dissect` : Ethernet, VLAN/QinQ, Linux SLL/SLL2, raw IPv4/IPv6,
      loopback/null, **radiotap + 802.11** (trames data -> LLC/SNAP -> IP ; trames mgmt décodées en en-tête),
      IPv4/IPv6/ICMP/TCP/UDP via `etherparse`. Dép. : P0.2.
- [ ] **P1.4** `feat/store-core` — `netsift-store` : catalogue, ouverture de session, migrations versionnées,
      writer par lots sur thread dédié, tables `meta`, `chunks`, `anomalies`, `timeseries`, `hosts`, `flows`.
      Dép. : P0.2.
- [ ] **P1.5** `feat/fixtures` — `netsift-fixtures` : constructeur de scénarios (DNS, HTTP avec image, TLS
      ClientHello/ServerHello/certificat auto-signé, NBNS, SMB browser announce, SNMP community, FTP login),
      écrivain pcap/pcapng/gz, découpeur en chunks par taille et par durée avec les 4 conventions de nommage.
      Dép. : P0.2.

### Vague 1.B (après 1.A)

- [ ] **P1.6** `feat/flow-table` — `netsift-flow` : défragmentation IP bornée, table de flux, réassemblage TCP
      (hors ordre, retransmissions, chevauchements, bornes mémoire), expiration en temps paquet.
- [ ] **P1.7** `feat/engine-pipeline` — `netsift-engine` : threads lecteur/décodeur/shards/writer, trait
      `Analyzer` **figé** (voir ARCHITECTURE), classification applicative pour `timeseries`, progression,
      annulation. CLI `netsift ingest <dossier|fichier> --out <dir>`. Test d'acceptation « fichier unique
      vs chunks = mêmes tables ».

Sortie de phase : ingestion d'un dossier de chunks synthétiques de 1 Go en CLI avec rapport.

---

## Phase 2 — API, application et premières vues

### Vague 2.A (parallèle)

- [ ] **P2.1** `feat/api-sessions` — Routes sessions (liste, import, SSE progression, suppression), `fs/browse`,
      génération des types ts-rs, client API typé côté UI.
- [ ] **P2.2** `feat/geoip` — `netsift-geo` : lecture mmdb, cache LRU, classification d'adresses ;
      `./x.sh geoip` ; attribution DB-IP dans « À propos ».
- [ ] **P2.3** `feat/ui-captures` — Vue Captures : liste des sessions, import (dialogue natif desktop /
      navigateur de dossiers en dev), progression, frise des chunks et anomalies. Spec : `specs/captures.md`.

### Vague 2.B

- [ ] **P2.4** `feat/ui-overview` — Vue Overview (`specs/overview.md`) : série temporelle par protocole,
      cartes de modules avec compteurs, résumé de session.
- [ ] **P2.5** `feat/desktop-integration` — Dialogue de dossier natif, jeton API, CSP, répertoire de données,
      fermeture propre pendant un import.

Sortie de phase : importer un dossier depuis l'app desktop et voir l'Overview.

---

## Phase 3 — Analyseurs et onglets (une branche = analyseur + API + vue + tests)

### Vague 3.A (parallèle, indépendantes)

- [ ] **P3.1** `feat/dns` — DNS + mDNS + NBNS (+ LLMNR) : transactions, codes réponse, types. `specs/dns.md`.
- [ ] **P3.2** `feat/http` — HTTP/1.x : transactions, en-têtes, corps bornés, décompression gzip/deflate/br,
      chunked ; vues HTTP et HTTP Headers. `specs/http.md`, `specs/http-headers.md`.
- [ ] **P3.3** `feat/tls` — TLS : ClientHello/ServerHello, versions, suites, SNI, ALPN, JA3/JA4 (client),
      certificats X.509 (export DER/PEM). `specs/tls.md`.
- [ ] **P3.4** `feat/connections-ports` — Agrégats de flux, ports ouverts (SYN-ACK / réponses UDP), table
      IANA des services embarquée. `specs/connections.md`, `specs/open-ports.md`.
- [ ] **P3.5** `feat/smb-netbios` — Annonces NetBIOS browser (OS, types), SMB1/2 négociation, NTLMSSP
      (v1/v2 -> lignes hashcat 5500/5600). `specs/smb.md`.

### Vague 3.B (dépend de 3.A)

- [ ] **P3.6** `feat/pictures` — Extraction d'objets HTTP (images), dédup SHA-256, miniatures Rust. Dép. P3.2.
      `specs/pictures.md`.
- [ ] **P3.7** `feat/credentials` — Agrégation + émetteurs : HTTP Basic/formulaires, FTP, POP3, IMAP,
      SMTP AUTH, SNMP v1/v2c, LDAP simple bind, NTLM (depuis P3.5). Export hashcat. `specs/credentials.md`.
- [ ] **P3.8** `feat/servers` — Rôles DNS / DHCP / LDAP (+ NTP, Kerberos, SMB) avec preuves. `specs/servers.md`.
- [ ] **P3.9** `feat/network-map` — Graphe des communications (sigma.js), filtres protocoles, agrégation
      par pays. `specs/network.md`.

---

## Phase 4 — Durcissement et version 0.1

- [ ] **P4.1** `test/fuzzing` — cibles cargo-fuzz : lecteurs pcap/pcapng, dissect L2-L4, DNS, HTTP, TLS,
      NTLMSSP, SNMP ; corpus depuis les fixtures ; 0 crash sur 30 min par cible.
- [ ] **P4.2** `perf/large-sessions` — Bench 5 Go (fixtures `--big`), profilage, index SQL, cibles d'ARCHITECTURE.
- [ ] **P4.3** `feat/export-pcap` — « Save PCAP » : export d'un flux, d'une plage temporelle ou de la session
      fusionnée (pcapng).
- [ ] **P4.4** `feat/i18n-fr` — Traduction française complète, formats de nombres/dates localisés.
- [ ] **P4.5** `chore/release-0.1` — Icônes définitives, à propos/licences tierces, tag `v0.1.0`.

---

## Phase 5 — Onglets suivants (specs à rédiger à partir de captures de référence)

Documents, FTP, Telnet, SSDP, SIP, ARP, Ethernet, WiFi (beacons, probes, clients, EAPOL -> hc22000),
Hosts (fiche par hôte agrégeant tout). Puis : ajout de chunks à une session, surveillance de dossier
en direct, `.zst`/`.lz4`, filtre temporel global (brush de l'Overview appliqué à toutes les vues).
