// Strings of the GeoIP notice and of its status in Settings > Online (`views.geoipPrompt`, P4.9).
// Same keys in both languages (i18n.test.ts). Months are formatted by `formatMonth`.

export const geoipPromptEn = {
  missing: 'No GeoIP database: the countries of public addresses stay unknown.',
  outdated: 'GeoIP database built in {{month}}. DB-IP publishes a new one each month.',
  outdatedPublished: 'GeoIP database built in {{month}}. A newer one is available ({{published}}).',
  host: 'Downloaded by NetSift from download.db-ip.com.',
  download: 'Download',
  update: 'Update',
  installed: 'Installed database: {{month}}.',
  installedNone: 'Installed database: none.',
  checkOff: 'Not checked at this start. Applies from the next start.',
  checkNotNeeded: 'Not checked at this start: the database is current.',
  checkPending: 'Checking download.db-ip.com.',
  checkPublished: 'Last check: database of {{month}} published.',
  checkNotPublished: 'Last check: no database published for this month or the previous one.',
  checkFailed: 'Last check: no answer from download.db-ip.com.',
};

export const geoipPromptFr: typeof geoipPromptEn = {
  missing: 'Aucune base GeoIP : les pays des adresses publiques restent inconnus.',
  outdated: 'Base GeoIP générée en {{month}}. DB-IP en publie une nouvelle chaque mois.',
  outdatedPublished: 'Base GeoIP générée en {{month}}. Une plus récente est disponible ({{published}}).',
  host: 'Téléchargée par NetSift depuis download.db-ip.com.',
  download: 'Télécharger',
  update: 'Mettre à jour',
  installed: 'Base installée : {{month}}.',
  installedNone: 'Base installée : aucune.',
  checkOff: "Pas de vérification à ce démarrage. S'applique à partir du prochain démarrage.",
  checkNotNeeded: 'Pas de vérification à ce démarrage : la base est à jour.',
  checkPending: 'Vérification auprès de download.db-ip.com.',
  checkPublished: 'Dernière vérification : base de {{month}} publiée.',
  checkNotPublished: 'Dernière vérification : aucune base publiée pour ce mois ni le précédent.',
  checkFailed: 'Dernière vérification : pas de réponse de download.db-ip.com.',
};
