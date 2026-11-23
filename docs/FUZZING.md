# Fuzzing

Les captures sont des entrées hostiles : chaque parseur et chaque analyseur est fuzzé avec
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer, AddressSanitizer,
`debug-assertions` actives, donc débordements arithmétiques compris). Le crate `fuzz/` est hors du
workspace (nightly, son propre `Cargo.lock`) ; il ne change rien à `./x.sh check`.

## Lancer

Tout passe par le conteneur. La nightly et cargo-fuzz, épinglés dans `scripts/ct/fuzz.sh`
(`NIGHTLY`, `CARGO_FUZZ_VERSION`), sont installés au premier appel dans le volume de cache
(`/cache/tools`), sans toucher à la toolchain stable de l'image.

```
./x.sh fuzz                      # liste les cibles
./x.sh fuzz corpus               # régénère les graines (fuzz/seeds/) depuis netsift-fixtures
./x.sh fuzz build                # compile toutes les cibles
./x.sh fuzz dns 600              # une cible, 10 min
./x.sh fuzz all 1800             # campagne : toutes les cibles en parallèle, 30 min chacune
./x.sh fuzz tmin dns fuzz/artifacts/dns/crash-...   # minimise une entrée qui plante
```

- `all [durée] [jobs]` lance un processus libFuzzer par cible, au plus `jobs` à la fois (par défaut
  cœurs - 2), écrit un journal par cible et un bilan (`summary.txt` : exécutions, couverture,
  statut) dans `.artifacts/fuzz/`, et échoue si une cible plante.
- Corpus vivant : `fuzz/corpus/<cible>/` (enrichi à chaque campagne), graines :
  `fuzz/seeds/<cible>/`, entrées qui plantent : `fuzz/artifacts/<cible>/`. Aucun de ces dossiers
  n'est commité (`fuzz/.gitignore`).
- Options libFuzzer fixées : `-timeout=25` (une entrée plus lente est un échec),
  `-rss_limit_mb=2048` ; variables `FUZZ_TIMEOUT`, `FUZZ_RSS_LIMIT_MB` pour les changer.
- Un dictionnaire `fuzz/dict/<cible>.dict` est passé automatiquement s'il existe (protocoles
  texte : `http`, `http_auth`, `lineproto`).
- CI : le job facultatif `fuzz` de `ci.yml` (sur `main` et à la demande) régénère les graines et
  fuzze chaque cible 60 s (`scripts/ci/fuzz.sh`, même script hors conteneur). C'est assumé : une
  entrée qui plante pendant ces 60 s rend le run de `main` **rouge**, comme un test cassé ; les
  entrées et les journaux sont publiés en artefact `fuzz`, à minimiser et corriger (ci-dessous).
- Gate : `./x.sh check` et le job Rust de la CI vérifient aussi `fuzz/` sur la stable (format,
  `cargo check --locked --all-targets`, tests de `fuzz/src/lib.rs`), sans fuzzer : un changement d'API
  des crates ne casse pas les cibles en silence. Surcoût mesuré : environ 1 s sans changement, 5 s
  après une modification, 40 s à froid (target neuf, avec sccache).
- `fuzz/Cargo.lock` est commité et vérifié (`--locked`) ; `scripts/release.sh` le met à jour avec la
  version des crates `netsift-*`.

## Cibles

Chaque cible vise l'API la plus basse et pure possible ; les analyseurs sont fuzzés par leur
interface publique (`Analyzer`), comme le moteur les appelle. Les parseurs privés à leur module
sont atteints par `netsift_analyze::fuzz` (feature `fuzzing`, `#[doc(hidden)]`, jamais activée
par l'application) : l'API publique n'est pas élargie.

| Cible | Entrée | Couvre |
|---|---|---|
| `capture` | fichier de capture | lecteurs pcap / pcapng et décompression gzip / zstd / LZ4 frame (`netsift_capture::reader`) |
| `dissect` | linktype + trame | Ethernet, VLAN, SLL/SLL2, raw IP, loopback, radiotap + 802.11, IPv4/IPv6 et extensions, TCP/UDP/ICMP |
| `flow_table` | linktype + trames horodatées | défragmentation IP, table de flux (expiration, LRU), réassemblage TCP, bornes réduites |
| `dns` | message | DNS / mDNS / LLMNR et NBNS (`netsift_dissect::dns`) |
| `udp_services` | message | DHCP, NTP, Kerberos (UDP et préfixe TCP), SSDP (`ssdp::parser`), SIP et SDP (`sip`, `sdp` : datagramme et découpage TCP) |
| `http` | conversation, port 80 | analyseur HTTP : têtes, corps (longueur, chunked, fermeture), gzip / deflate / brotli, objets, identifiants |
| `http_auth` | cible + en-têtes + corps | `http::auth` : Basic, NTLM / Negotiate, formulaires et chaînes de requête (`url_decode`) |
| `tls` | mode + octets | pur : couche record, ClientHello / ServerHello, JA3 / JA4, X.509 ; ou analyseur TLS sur une conversation |
| `ntlmssp` | message | NTLMSSP et lignes hashcat 5500 / 5600 |
| `smb` | octets | SMB1 / SMB2 sur NBSS, datagrammes NetBIOS du navigateur (UDP 138) |
| `snmp` | datagramme | communautés SNMP v1 / v2c (`snmp-parser`) |
| `ldap` | conversation, port 389 | `BerStream` + `ldap-parser` (simple bind) via l'analyseur credentials |
| `lineproto` | port + conversation | `LineFlow` : FTP, SMTP AUTH, POP3, IMAP via l'analyseur credentials ; sur le port 21, analyseur `ftp` et parseurs `netsift_dissect::ftp` |
| `telnet` | sélecteur + conversation | décodeur `IAC` pur et sous-négociations (`netsift_dissect::telnet`), ou analyseur `telnet` (transcription, échos, identifiants), ports 23 / 2323 |
| `mmdb` | fichier `.mmdb` ou `.mmdb.gz` | `netsift_geo` (décodage borné, décodeur `maxminddb`, recherches) |
| `thumbs` | fichier image | `netsift_engine::thumbs::render` (PNG, JPEG, GIF, WebP, BMP, ICO, limites de décodage) |
| `analyzers` | protocole + ports + conversation | tous les analyseurs derrière une table de flux, trames IPv4 forgées (handshake, numéros de séquence cohérents, pertes), puis traduction en lignes du store |
| `pipeline` | fichier de capture | lecteur, table de flux, tous les analyseurs, traduction en lignes du store (tout sauf SQLite) |

Formats d'entrée (`fuzz/src/lib.rs`, partagés avec le générateur de graines) :

- **conversation** (`segments`) : par segment, un octet de drapeaux (bit 0 : envoyé par le
  serveur, bit 1 : un octet de perte suit), une longueur `u16` petit-boutiste, l'octet de perte
  éventuel, puis les données. Fournie directement à `on_stream` (`StreamCtx::gap_before`), ou
  transformée en trames TCP dont les pertes sautent de l'espace de séquence (`analyzers`).
- **conversation avec en-tête** (`analyzers`) : sélecteur (bit 7 : UDP, sinon TCP ; index dans
  `TCP_PORTS` / `UDP_PORTS`), port client sur 2 octets, options (handshake, fermeture), puis segments.
- **trames** (`flow_table`) : par trame, un pas de temps (`0..=239` : +10 ms par unité,
  `240..=254` : petit retour en arrière, `255` : +400 s, au-delà des délais d'expiration), une
  longueur `u16`, puis la trame.

## Graines

`./x.sh fuzz corpus` (`fuzz/examples/gen_corpus.rs`) rejoue les scénarios de `netsift-fixtures`
(démo, DNS, HTTP, TLS, NBNS, SMB, SNMP, FTP, vitrines credentials / servers / TLS / Telnet, mélange HTTP,
galerie d'images, fragmentation) dans une table de flux et découpe ce qu'elle rapporte en entrées de
chaque cible : fichiers pcap / pcapng / gzip / zstd / LZ4, trames, charges UDP, conversations TCP par port,
messages NTLMSSP, en-têtes HTTP d'authentification, certificats, bases mmdb (écrites par
`netsift_geo::test_util`), images de chaque format. Rien de binaire n'est commité ; le générateur
est déterministe.

## Quand une cible plante

1. Minimiser : `./x.sh fuzz tmin <cible> fuzz/artifacts/<cible>/crash-...` (écrit `....min`).
2. Corriger dans le parseur concerné (commit `fix(<scope>): ...` séparé).
3. Ajouter un test unitaire de régression avec l'entrée minimisée (octets en clair dans le test).
4. Relancer la cible, puis la campagne.

## Campagnes

Le bilan de chaque campagne est dans `.artifacts/fuzz/summary.txt` (`runs` : exécutions, `cov` :
compteurs de couverture atteints, `ft` : features libFuzzer, `corpus` : entrées retenues). Reporter
ici les campagnes longues.

### 2026-11-15 — P4.1, 30 min par cible

`./x.sh fuzz all 1800` : 17 cibles en parallèle (machine 22 cœurs), nightly-2026-11-10,
cargo-fuzz 0.13.2, ASan + `debug-assertions`, corpus vivant hérité d'une campagne de 5 min.
**Aucun crash, aucun timeout, aucun dépassement mémoire** (pic RSS : 505 Mo, cible `pipeline`).

| Cible | Exécutions | cov | ft | Corpus |
|---|---:|---:|---:|---:|
| `analyzers` | 649 795 | 13 358 | 40 265 | 3 902 |
| `capture` | 508 501 | 1 571 | 5 248 | 536 |
| `dissect` | 14 337 229 | 1 406 | 1 995 | 391 |
| `dns` | 4 257 523 | 967 | 3 959 | 834 |
| `flow_table` | 1 085 000 | 2 122 | 10 322 | 938 |
| `http` | 1 885 951 | 5 775 | 22 735 | 2 897 |
| `http_auth` | 3 116 240 | 1 496 | 8 690 | 1 869 |
| `ldap` | 5 977 963 | 1 471 | 6 770 | 1 056 |
| `lineproto` | 2 029 091 | 1 258 | 7 758 | 1 951 |
| `mmdb` | 5 197 739 | 3 581 | 9 837 | 2 287 |
| `ntlmssp` | 27 358 014 | 304 | 775 | 153 |
| `pipeline` | 354 819 | 14 385 | 50 006 | 2 906 |
| `smb` | 22 580 847 | 555 | 1 837 | 391 |
| `snmp` | 29 431 949 | 840 | 1 718 | 347 |
| `thumbs` | 618 707 | 7 243 | 22 157 | 2 076 |
| `tls` | 3 428 345 | 5 125 | 15 335 | 1 575 |
| `udp_services` | 36 288 243 | 621 | 1 809 | 689 |

Les cibles d'analyseurs (`analyzers`, `pipeline`) tournent à 200 à 360 exécutions par seconde :
30 min y restent une campagne courte, à prolonger quand la machine est libre.
