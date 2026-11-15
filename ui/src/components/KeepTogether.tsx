import { Fragment } from 'react';

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * `text` with every occurrence of `word` (or of each of several words) kept on one line: a host
 * name such as `download.db-ip.com` must not break at its hyphen. The rest of the text wraps as
 * usual.
 */
export function KeepTogether({ text, word }: { text: string; word: string | readonly string[] }) {
  const words = (typeof word === 'string' ? [word] : word).filter((w) => w !== '');
  if (words.length === 0) return <>{text}</>;
  // Longest first: a word that contains another one is kept whole. The capture group keeps the
  // matched words in the result of `split`, at odd indexes.
  const sorted = [...words].sort((a, b) => b.length - a.length);
  const parts = text.split(new RegExp(`(${sorted.map(escapeRe).join('|')})`));
  return (
    <>
      {parts.map((part, i) =>
        // Parts never move: the index is a stable key.
        i % 2 === 1 ? (
          <span key={i} className="whitespace-nowrap">
            {part}
          </span>
        ) : (
          <Fragment key={i}>{part}</Fragment>
        ),
      )}
    </>
  );
}
