# Spécifications des vues

Une spec par onglet. Gabarit commun :

- **Référence** : capture(s) dans `docs/reference/`.
- **But** : la question à laquelle l'onglet répond.
- **Données** : ce que l'analyseur extrait, tables SQL, endpoints API.
- **Mise en page** : blocs dans l'ordre, comportement par largeur.
- **Améliorations par rapport à la référence**.
- **Critères d'acceptation** : testables (fixtures + `./x.sh shots`).

Règles transverses (sauf mention contraire) :

- En-tête de page : titre, sous-titre d'une ligne, compteur total, actions (export CSV/JSON des
  lignes filtrées).
- Les filtres d'une vue sont reflétés dans l'URL (partage d'état, retour arrière).
- Toute IP affichée utilise le composant `Endpoint` (IP mono, port grisé, drapeau, nom résolu en infobulle,
  clic -> fiche hôte quand l'onglet Hosts existera ; d'ici là, copie).
- Toute liste longue est paginée côté serveur (keyset) et virtualisée côté UI.
- Le bouton flottant « To Details » de la référence est remplacé par une navigation interne
  (ancres de section dans l'en-tête de page).

| Fichier | Onglet | Phase |
|---|---|---|
| `captures.md` | Browse Captures / import | 2 |
| `overview.md` | Data Overview | 2 |
| `dns.md` | DNS | 3 |
| `http.md` | HTTP | 3 |
| `http-headers.md` | HTTP Headers | 3 |
| `tls.md` | SSL/TLS | 3 |
| `connections.md` | Connections | 3 |
| `open-ports.md` | Open Ports | 3 |
| `smb.md` | SMB | 3 |
| `pictures.md` | Pictures | 3 |
| `credentials.md` | Credentials | 3 |
| `servers.md` | Servers | 3 |
| `network.md` | Network | 3 |
