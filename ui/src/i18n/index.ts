import i18n, { type FormatterModule } from 'i18next';
import { initReactI18next } from 'react-i18next';
import { en } from './en';
import { fr } from './fr';
import { reportLanguage } from '../app/desktop';
import { formatCount } from '../lib/format';
import { readPref, writePref } from '../lib/storage';

export const LANGUAGES = ['en', 'fr'] as const;
export type Language = (typeof LANGUAGES)[number];
export type LanguagePref = Language | 'system';

const STORAGE_KEY = 'netsift.lang';

/** Resolves the effective language: explicit choice, else the OS/browser locale, else English. */
export function resolveLanguage(pref: LanguagePref, navigatorLanguages: readonly string[]): Language {
  if (pref !== 'system') return pref;
  for (const tag of navigatorLanguages) {
    const base = tag.toLowerCase().split('-')[0];
    if (base === 'fr' || base === 'en') return base;
  }
  return 'en';
}

export function readLanguagePref(): LanguagePref {
  const v = readPref(STORAGE_KEY);
  return v === 'en' || v === 'fr' ? v : 'system';
}

export function setLanguagePref(pref: LanguagePref): void {
  writePref(STORAGE_KEY, pref === 'system' ? null : pref);
  void i18n.changeLanguage(resolveLanguage(pref, navigator.languages));
}

/**
 * Interpolated values that are quantities: a number passed under one of these names is written
 * with the grouping of the language (`12,345` / `12 345`). Identifiers passed as numbers (ports,
 * sequence numbers, hashcat modes, status codes, key sizes) keep their digits as they are.
 */
export const QUANTITY_KEYS: ReadonlySet<string> = new Set([
  'count',
  'edges',
  'errors',
  'gaps',
  'hosts',
  'index',
  'limit',
  'max',
  'missing',
  'n',
  'nodes',
  'overlaps',
  'packets',
  'queries',
  'shown',
  'total',
]);

/** Locale formatting of interpolated quantities (`interpolation.alwaysFormat`). */
const quantityFormatter: FormatterModule = {
  type: 'formatter',
  init: () => undefined,
  add: () => undefined,
  addCached: () => undefined,
  format: (value: unknown, _format, lng, options) => {
    const key = typeof options?.interpolationkey === 'string' ? options.interpolationkey : '';
    if (typeof value === 'number' && Number.isFinite(value) && QUANTITY_KEYS.has(key)) {
      return formatCount(value, lng ?? i18n.language);
    }
    return value as string;
  },
};

void i18n.use(initReactI18next).use(quantityFormatter).init({
  resources: { en: { translation: en }, fr: { translation: fr } },
  lng: resolveLanguage(readLanguagePref(), typeof navigator === 'undefined' ? [] : navigator.languages),
  fallbackLng: 'en',
  // React already escapes; quantities are formatted for the language (`quantityFormatter`).
  interpolation: { escapeValue: false, alwaysFormat: true },
  returnNull: false,
});

i18n.on('languageChanged', (lng) => {
  document.documentElement.lang = lng;
  void reportLanguage(lng);
});
document.documentElement.lang = i18n.language;
void reportLanguage(i18n.language);

export default i18n;
