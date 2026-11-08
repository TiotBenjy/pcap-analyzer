import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { HttpCount } from '../../api/types/HttpCount';
import { Card } from '../../components/Card';
import { EmptyState } from '../../components/EmptyState';
import { Skeleton } from '../../components/Skeleton';
import { formatCount } from '../../lib/format';

interface RankedListProps {
  title: string;
  /** `null` while loading. */
  items: readonly HttpCount[] | null;
  emptyText: string;
  /** Called when an entry is chosen (filters the list); entries are plain text without it. */
  onSelect?: (key: string) => void;
  /** Label of the action of an entry, for screen readers. */
  selectLabel?: (key: string) => string;
  /** Footer (distinct count, link to the full list). */
  footer?: ReactNode;
  /** Display text of a key. */
  label?: (key: string) => string;
}

/** Ranked list with proportion bars (replaces word clouds, docs/UI_GUIDELINES.md). */
export function RankedList({ title, items, emptyText, onSelect, selectLabel, footer, label }: RankedListProps) {
  const { t } = useTranslation();
  const max = Math.max(1, ...(items ?? []).map((i) => i.count));
  let body: ReactNode;
  if (items === null) {
    body = (
      <div className="flex flex-col gap-2" aria-busy="true">
        <span className="sr-only">{t('common.loading')}</span>
        {[0, 1, 2, 3].map((i) => (
          <Skeleton key={i} height={28} />
        ))}
      </div>
    );
  } else if (items.length === 0) {
    body = <EmptyState title={emptyText} />;
  } else {
    body = (
      <ol className="flex flex-col gap-1">
        {items.map((item) => {
          const text = label?.(item.key) ?? (item.key === '' ? '-' : item.key);
          const content = (
            <>
              <span className="flex min-w-0 items-baseline justify-between gap-2">
                <span data-testid="truncatable" title={text} className="min-w-0 truncate">
                  {text}
                </span>
                <span className="num shrink-0 text-meta text-muted">{formatCount(item.count)}</span>
              </span>
              <span aria-hidden className="block h-1 w-full rounded-full bg-subtle">
                <span className="block h-1 rounded-full bg-accent" style={{ width: `${(item.count / max) * 100}%` }} />
              </span>
            </>
          );
          return (
            <li key={item.key} className="min-w-0">
              {onSelect === undefined ? (
                <div className="flex flex-col gap-1 px-2 py-1">{content}</div>
              ) : (
                <button
                  type="button"
                  aria-label={selectLabel?.(item.key)}
                  onClick={() => {
                    onSelect(item.key);
                  }}
                  className="flex min-h-8 w-full flex-col gap-1 rounded-md px-2 py-1 text-left hover:bg-subtle"
                >
                  {content}
                </button>
              )}
            </li>
          );
        })}
      </ol>
    );
  }
  return (
    <Card title={title} className="flex flex-col">
      <div className="flex flex-col gap-2">
        {body}
        {footer !== undefined && items !== null && items.length > 0 && (
          <div className="border-t border-line pt-2 text-meta text-muted">{footer}</div>
        )}
      </div>
    </Card>
  );
}
