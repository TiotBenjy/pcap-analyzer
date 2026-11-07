import { describe, expect, it } from 'vitest';
import { en } from './en';
import { fr } from './fr';
import { resolveLanguage } from './index';

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
