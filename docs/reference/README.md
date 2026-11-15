# Captures de référence

Captures d'écran d'une plateforme existante d'analyse de pcap, fournies par l'utilisateur.
Elles décrivent **les fonctionnalités et l'organisation des onglets** attendues.

Ne pas reproduire leur style : ombres sur les camemberts, emoji (drapeaux, icônes de nœuds,
titres de cartes), nuage de mots 3D, libellés de graphes qui se chevauchent, légendes tronquées,
grands espaces vides. Les règles visuelles du projet sont dans `docs/UI_GUIDELINES.md`,
et chaque spec de `docs/specs/` indique ce qui est repris et ce qui est amélioré.

| Fichier | Onglet |
|---|---|
| `overview.png` | Data Overview |
| `credentials.png` | Credentials |
| `dns-1.png`, `dns-2.png` | DNS |
| `http-headers.png` | HTTP Headers |
| `connections-1.png`, `connections-2.png` | Connections |
| `open-ports.png` | Open Ports |
| `tls-1.png`, `tls-2.png` | SSL/TLS |
| `pictures.png` | Pictures |
| `http.png` | HTTP |
| `smb.png` | SMB |
| `servers.png` | Servers |
| `network.png` | Network |

Phase 5 : les captures de Documents, FTP, Telnet, SSDP, SIP, ARP, Ethernet et WiFi montrent des données
de captures (SSID, BSSID, mots de passe). À la demande de l'utilisateur, elles ne sont **pas publiées** : elles
restent dans `docs/reference/private/` (ignoré par git, présent seulement dans le checkout racine de
l'utilisateur ; un worktree le lit par le chemin absolu du checkout racine). Ne jamais les commiter ni
recopier leurs données (SSID, adresses MAC, identifiants) dans les specs, tests ou captures d'écran.

| Fichier (`private/`) | Onglet |
|---|---|
| `documents.png` | Documents |
| `ftp.png` | FTP |
| `telnet.png` | Telnet |
| `sip.png` | SIP |
| `ssdp.png` | SSDP |
| `arp.png` | ARP |
| `ethernet.png` | Ethernet |
| `wifi-1-handshakes.png` à `wifi-5-probe-requests.png` | WiFi (handshakes, points d'accès, broadcast, client à client, probe requests) |

Hosts n'a pas de capture de référence.
