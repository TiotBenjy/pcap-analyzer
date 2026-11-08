import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { HttpHeaderLine } from '../../api/types/HttpHeaderLine';
import { SecretValue } from '../../components/SecretValue';
import { highlightParts, isSensitiveHeader } from './format';

/** Values longer than this are folded, with "Show all". */
export const FOLD_CHARS = 240;

function Highlighted({ text, term }: { text: string; term: string }) {
  return (
    <>
      {highlightParts(text, term).map((p, i) =>
        p.match ? (
          <mark key={i} className="rounded-sm bg-accent-soft text-fg">
            {p.text}
          </mark>
        ) : (
          <span key={i}>{p.text}</span>
        ),
      )}
    </>
  );
}

function Value({ name, value, term }: { name: string; value: string; term: string }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const long = value.length > FOLD_CHARS;
  const shown = long && !open ? `${value.slice(0, FOLD_CHARS)}…` : value;
  const text = <Highlighted text={shown} term={term} />;
  return (
    <span className="flex min-w-0 flex-col items-start gap-0.5">
      {isSensitiveHeader(name) ? (
        <SecretValue value={value} label={name}>
          {text}
        </SecretValue>
      ) : (
        <span className="min-w-0 [overflow-wrap:anywhere]">{text}</span>
      )}
      {long && (
        <button
          type="button"
          aria-expanded={open}
          onClick={() => {
            setOpen((o) => !o);
          }}
          className="text-meta text-accent hover:underline"
        >
          {open ? t('views.http.showLess') : t('views.http.showAll', { count: value.length })}
        </button>
      )}
    </span>
  );
}

interface HeaderTableProps {
  headers: readonly HttpHeaderLine[];
  /** Accessible name of the table. */
  label: string;
  /** Term highlighted in names and values. */
  highlight?: string;
}

/** Header lines in order, name / value in monospace; sensitive values masked by default. */
export function HeaderTable({ headers, label, highlight = '' }: HeaderTableProps) {
  const { t } = useTranslation();
  if (headers.length === 0) return <p className="text-muted">{t('views.http.noHeaders')}</p>;
  return (
    <table aria-label={label} className="w-full table-fixed border-collapse font-mono text-meta">
      <colgroup>
        <col className="w-[34%] sm:w-[28%]" />
        <col />
      </colgroup>
      <tbody>
        {headers.map((h, i) => (
          <tr key={`${i}-${h.name}`} className="border-b border-line align-top last:border-b-0">
            <th scope="row" className="py-1 pr-3 text-left font-normal text-muted">
              <span data-testid="truncatable" title={h.name} className="block truncate">
                <Highlighted text={h.name} term={highlight} />
              </span>
            </th>
            <td className="py-1">
              <Value name={h.name} value={h.value} term={highlight} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
