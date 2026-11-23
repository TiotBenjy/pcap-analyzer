import { describe, expect, it } from 'vitest';
import { en } from './en';
import { fr } from './fr';
import i18n, { resolveLanguage } from './index';

function flatten(obj: object, prefix = ''): Map<string, string> {
  const out = new Map<string, string>();
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (typeof v === 'string') out.set(key, v);
    else for (const [k2, v2] of flatten(v as object, key)) out.set(k2, v2);
  }
  return out;
}

// Emoji, pictographs, dingbats, arrows, box drawing, decorative bullets/stars, variation selectors.
const DECORATIVE =
  /[\p{Extended_Pictographic}\u{2190}-\u{21FF}\u{2500}-\u{27BF}\u{2B00}-\u{2BFF}\u{2022}\u{2605}\u{2606}]/u;
// Emoji presentation selector and zero-width joiner (checked separately: not allowed in a class).
const JOINERS = /\u{FE0F}|\u{200D}/u;

describe('dictionaries', () => {
  const enFlat = flatten(en);
  const frFlat = flatten(fr);

  it('fr has exactly the same keys as en', () => {
    expect([...frFlat.keys()].sort()).toEqual([...enFlat.keys()].sort());
  });

  it.each([
    ['en', enFlat],
    ['fr', frFlat],
  ] as const)('%s has no empty, decorative or exclamatory strings', (_lang, dict) => {
    for (const [key, value] of dict) {
      expect(value.trim(), key).not.toBe('');
      expect(DECORATIVE.test(value) || JOINERS.test(value), `${key}: ${value}`).toBe(false);
      expect(value.includes('!'), `${key}: ${value}`).toBe(false);
    }
  });
});

/** Placeholders of a value (`{{count}}`), sorted. */
const placeholders = (v: string) => [...v.matchAll(/\{\{\s*([\w.]+)\s*\}\}/g)].map((m) => m[1]).sort();

/**
 * Words spelled the same in French and English: a French value equal to the English one is
 * accepted when it is made only of these, of acronyms and code-like names (`DNS`, `NetNTLMv2`,
 * `SSL/TLS`), of the names below and of placeholders.
 */
const SAME_IN_FRENCH = new Set(
  [
    'actions', 'agent', 'anomalies', 'bits', 'captures', 'chunk', 'chunks', 'client', 'clients', 'communications', 'contact',
    'conversation', 'conversations', 'destination', 'destinations', 'dimensions', 'documents', 'ethertype', 'ethertypes', 'extensions',
    'format', 'images', 'import', 'message', 'messages', 'mode', 'modules', 'multicast', 'navigation', 'observations', 'occurrences', 'ports', 'position', 'public',
    'scanner', 'scanners', 'secret', 'session', 'sessions', 'source', 'sources', 'total', 'transactions', 'transport', 'type', 'unicast', 'version', 'versions', 'volume',
  ],
);

/** Product, tool and language names, written the same in every language. */
const NAMES = ['Windows for Workgroups', 'Client Hello', 'Server Hello', 'tcpdump', 'English', 'Français', 'NetSift', 'Telnet', 'Ethernet', 'Kerberos', 'Novell', 'Apple', 'Xenix', 'GeoIP', 'Call-ID'];

/** True for a value that reads the same in every language (see `SAME_IN_FRENCH`), or a URL. */
function isLanguageNeutral(value: string): boolean {
  if (/^https?:\/\//.test(value)) return true;
  let text = value.replace(/\{\{[^}]*\}\}/g, ' ');
  for (const name of NAMES) text = text.replaceAll(name, ' ');
  const words = text.match(/\p{L}[\p{L}\d]*/gu) ?? [];
  // A word without three lowercase letters in a row is an acronym or a code (`SSL`, `mDNS`, `JA3`).
  return words.every((w) => !/\p{Ll}{3,}/u.test(w) || SAME_IN_FRENCH.has(w.toLowerCase()));
}

describe('French dictionary', () => {
  const enFlat = flatten(en);
  const frFlat = flatten(fr);

  it('keeps the placeholders of every English value', () => {
    for (const [key, value] of enFlat) expect(placeholders(frFlat.get(key) ?? ''), key).toEqual(placeholders(value));
  });

  it('translates every value, except language-neutral ones and words spelled the same', () => {
    const untranslated = [...enFlat]
      .filter(([key, value]) => frFlat.get(key) === value && !isLanguageNeutral(value))
      .map(([key, value]) => `${key}: ${value}`);
    expect(untranslated).toEqual([]);
  });

  it('follows French typography', () => {
    const problems: string[] = [];
    for (const [key, value] of frFlat) {
      const fail = (why: string) => problems.push(`${key} (${why}): ${value}`);
      // High punctuation takes a no-break space before it (`Total\u00a0:`), never a plain one.
      if (/ [:;?!]/.test(value)) fail('plain space before : ; ? !');
      if (/[^\s\u00a0\u202f/][;?!](\s|$)/.test(value) || /[^\s\u00a0\u202f/\d]:(\s|$)/.test(value)) fail('no space before : ; ?');
      if (value.includes('"')) fail('straight double quotes, use « »');
      if (/«(?![\u00a0\u202f])|(?<![\u00a0\u202f])»/.test(value)) fail('« » need no-break spaces inside');
      if (value.includes('\u2019')) fail('typographic apostrophe: the dictionary uses the straight one');
      if (value.includes('...')) fail('three dots, use the ellipsis character');
    }
    expect(problems).toEqual([]);
  });
});

describe('plural forms', () => {
  const loaded = flatten(i18n.getResourceBundle('fr', 'translation') as object);

  it('gives every French plural its `many` form (1,000,000 and above)', () => {
    expect(new Intl.PluralRules('fr').select(1_000_000)).toBe('many');
    const missing = [...loaded.keys()]
      .filter((key) => key.endsWith('_other'))
      .map((key) => key.replace(/_other$/, '_many'))
      .filter((key) => !loaded.has(key));
    expect(missing).toEqual([]);
  });

  it('writes a million in French, not in English', async () => {
    await i18n.changeLanguage('fr');
    try {
      expect(i18n.t('views.import.files', { count: 1_000_000 })).toBe('1\u202f000\u202f000 fichiers');
      expect(i18n.t('views.credentials.paths.entries', { count: 2_000_000 })).toBe('2\u202f000\u202f000 entrées');
      expect(i18n.t('views.import.files', { count: 1 })).toBe('1 fichier');
    } finally {
      await i18n.changeLanguage('en');
    }
  });

  it('uses no i18next format specifier (the quantity formatter replaces the built-in one)', () => {
    for (const [key, value] of [...flatten(en), ...flatten(fr)]) expect(/\{\{[^}]*,[^}]*\}\}/.test(value), key).toBe(false);
  });
});

describe('resolveLanguage', () => {
  it('honours an explicit preference', () => {
    expect(resolveLanguage('fr', ['en-US'])).toBe('fr');
  });
  it('follows the first supported system language', () => {
    expect(resolveLanguage('system', ['de-DE', 'fr-CA', 'en'])).toBe('fr');
  });
  it('falls back to English', () => {
    expect(resolveLanguage('system', ['de-DE'])).toBe('en');
    expect(resolveLanguage('system', [])).toBe('en');
  });
});
