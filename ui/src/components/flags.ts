// Country flags from `flag-icons` (MIT), as files (never emoji: not rendered on Windows).
// Only the 4x3 set is bundled; each flag is a separate SVG file loaded on demand by the browser.
const FLAGS = import.meta.glob<string>('/node_modules/flag-icons/flags/4x3/*.svg', {
  eager: true,
  query: '?url',
  import: 'default',
});

/** URL of the flag of an ISO 3166-1 alpha-2 code, `null` when unknown. */
export function flagUrl(country: string): string | null {
  const code = country.trim().toLowerCase();
  if (!/^[a-z]{2}$/.test(code)) return null;
  return FLAGS[`/node_modules/flag-icons/flags/4x3/${code}.svg`] ?? null;
}
