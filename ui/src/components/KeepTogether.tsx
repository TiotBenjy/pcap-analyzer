import { Fragment } from 'react';

/**
 * `text` with every occurrence of `word` kept on one line: a host name such as
 * `download.db-ip.com` must not break at its hyphen. The rest of the text wraps as usual.
 */
export function KeepTogether({ text, word }: { text: string; word: string }) {
  const parts = text.split(word);
  return (
    <>
      {parts.map((part, i) => (
        // Parts never move: the index is a stable key.
        <Fragment key={i}>
          {i > 0 && <span className="whitespace-nowrap">{word}</span>}
          {part}
        </Fragment>
      ))}
    </>
  );
}
