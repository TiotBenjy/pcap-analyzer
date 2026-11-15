// Strings of Settings > Online (`views.online`): the online checks run at startup (ADR-025).
// Features add their own dictionaries; same keys in both languages (i18n.test.ts).

export const onlineEn = {
  title: 'Online',
  description:
    'NetSift works offline. These checks are off by default. When on, NetSift sends one request at startup, with no personal data, and stays silent if it fails.',
  geoipCheck: 'Check for a new GeoIP database at startup',
  geoipCheckHint: 'Asks download.db-ip.com whether a newer database is published.',
  updateCheck: 'Check for updates at startup',
  updateCheckHint: 'Asks api.github.com for the latest release of NetSift.',
  nextStart: 'Applies from the next start.',
  readOnly: 'These settings cannot be changed on a read-only server.',
  loadError: 'Settings unavailable',
  saveError: 'The setting could not be saved: {{message}}',
};

export const onlineFr: typeof onlineEn = {
  title: 'En ligne',
  description:
    "NetSift fonctionne hors ligne. Ces vérifications sont désactivées par défaut. Activées, NetSift envoie une requête au démarrage, sans donnée personnelle, et reste silencieux en cas d'échec.",
  geoipCheck: 'Rechercher une nouvelle base GeoIP au démarrage',
  geoipCheckHint: 'Demande à download.db-ip.com si une base plus récente est publiée.',
  updateCheck: 'Rechercher les mises à jour au démarrage',
  updateCheckHint: 'Demande à api.github.com la dernière version publiée de NetSift.',
  nextStart: "S'applique à partir du prochain démarrage.",
  readOnly: 'Ces réglages ne peuvent pas être modifiés sur un serveur en lecture seule.',
  loadError: 'Réglages indisponibles',
  saveError: "Le réglage n'a pas pu être enregistré : {{message}}",
};
