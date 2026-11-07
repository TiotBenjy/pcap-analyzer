import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import { en } from './en';
import { fr } from './fr';
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

void i18n.use(initReactI18next).init({
  resources: { en: { translation: en }, fr: { translation: fr } },
  lng: resolveLanguage(readLanguagePref(), typeof navigator === 'undefined' ? [] : navigator.languages),
  fallbackLng: 'en',
  interpolation: { escapeValue: false }, // React already escapes
  returnNull: false,
});

i18n.on('languageChanged', (lng) => {
  document.documentElement.lang = lng;
});
document.documentElement.lang = i18n.language;

export default i18n;
