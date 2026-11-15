import { describe, expect, it } from 'vitest';
import { notesExcerpt } from './download';

describe('notesExcerpt', () => {
  it('drops the Markdown of git-cliff notes and joins the entries', () => {
    const notes = [
      '## [0.2.0](https://github.com/o/r/releases/tag/v0.2.0) - 2026-11-20',
      '',
      '### Fonctionnalités',
      '',
      '- **update** : Check GitHub releases ([abc1234](https://github.com/o/r/commit/abc1234))',
      '- **dns** : Parse `NBNS` names on _x86_64_ hosts ([def5678](https://github.com/o/r/commit/def5678))',
      '',
      '| Système | Fichier |',
      '|---|---|',
      '**Comparaison** : [v0.1.0...v0.2.0](https://github.com/o/r/compare/v0.1.0...v0.2.0)',
    ].join('\n');
    expect(notesExcerpt(notes)).toBe(
      'update : Check GitHub releases; dns : Parse NBNS names on x86_64 hosts; Comparaison : v0.1.0...v0.2.0',
    );
  });

  it('handles other list markers and empty notes', () => {
    expect(notesExcerpt('* One\n+   Two  three\n')).toBe('One; Two three');
    expect(notesExcerpt('')).toBe('');
    expect(notesExcerpt('# Only a heading')).toBe('');
  });

  it('cuts long notes', () => {
    expect(notesExcerpt('word '.repeat(100), 20)).toBe('word word word word…');
    expect(notesExcerpt('short', 20)).toBe('short');
  });
});
