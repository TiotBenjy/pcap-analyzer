# Browse Captures (sessions et import)

Référence : entrée « Browse Captures » de la sidebar (pas de capture fournie) et fil d'Ariane de `overview.png`.

## But

Lister les sessions analysées, en importer de nouvelles (fichier unique ou dossier de chunks),
suivre l'import et vérifier la continuité des chunks.

## Données / API

- `GET /api/v1/sessions` : id, nom, sources, date d'import, état (`importing`, `ready`, `incomplete`, `failed`),
  octets, paquets, durée capturée, nombre de chunks, nombre d'anomalies.
- `POST /api/v1/sessions/import/scan { path }` : inventaire et groupes détectés (sans analyser).
- `POST /api/v1/sessions/import { path, group_ids, name, options }` -> `{ session_id }`.
- `GET /api/v1/sessions/{id}/events` (SSE) : `progress { bytes_done, bytes_total, chunk_index, chunk_name,
  packets, rate_bps, eta_s }`, `warning`, `done`, `failed`.
- `DELETE /api/v1/sessions/{id}` (supprime la base et les blobs, jamais les captures sources).
- `GET /api/v1/sessions/{id}/chunks`, `GET /api/v1/sessions/{id}/anomalies`.

## Mise en page

1. En-tête : « Captures », bouton principal « Importer un dossier », secondaire « Importer un fichier ».
2. Tableau des sessions : nom, période capturée, durée, taille, paquets, chunks, état (badge), anomalies (compteur),
   actions (ouvrir, renommer, supprimer avec confirmation). Ligne cliquable -> Overview de la session.
3. Assistant d'import (panneau latéral ou modale large) :
   - étape 1 : choix du dossier (dialogue natif en desktop ; explorateur limité à `/captures` en mode dev) ;
   - étape 2 : résultat du scan — groupes détectés, pour chacun : motif reconnu (dumpcap, tcpdump -C, ...),
     nombre de fichiers, taille, plage temporelle, anomalies prévues ; choix des groupes ; nom de session ;
   - étape 3 : progression — barre globale, chunk en cours (n / total), débit, ETA, journal des avertissements,
     bouton Annuler. L'utilisateur peut fermer l'assistant, l'import continue (indicateur dans l'en-tête).
4. Détail de session (onglet « Sources » accessible depuis l'Overview) : frise de couverture des chunks
   (un segment par chunk, trous en hachures, chevauchements en surbrillance), tableau des chunks, anomalies.

Responsive : sous 768 px, le tableau des sessions passe en cartes ; la frise reste lisible (défilement horizontal interne).

## Critères d'acceptation

- Un dossier de chunks dumpcap synthétique (50 fichiers, un manquant, un trou) est importé ; la frise montre
  le fichier manquant et le trou ; l'anomalie est listée.
- Deux groupes de préfixes différents dans un dossier -> deux groupes proposés au scan.
- Annulation à 50 % -> session `incomplete` consultable.
- Supprimer une session ne touche pas aux fichiers sources (test).
