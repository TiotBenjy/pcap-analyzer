import { createElement, type ReactNode } from 'react';
import { WholeSessionHeader } from './WholeSession';

/**
 * `header` of a DataTable column whose values were folded at import: the label as is, or under a
 * time range the label with the "Whole session" line below it (`WholeSessionHeader`). Pass
 * `ranged && wide` when the narrow card layout explains it in a note instead.
 */
export function wholeSessionHeader(label: string, ranged: boolean): string | (() => ReactNode) {
  if (!ranged) return label;
  return () => createElement(WholeSessionHeader, { label, ranged: true });
}
