import type { ReactNode } from 'react';
import type { HttpCount } from '../../api/types/HttpCount';
import { BarList } from '../../components/BarList';
import { Card } from '../../components/Card';
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

/** Ranked list with proportion bars in a card (replaces word clouds, docs/UI_GUIDELINES.md). */
export function RankedList({ title, items, emptyText, onSelect, selectLabel, footer, label }: RankedListProps) {
  return (
    <Card title={title} className="flex flex-col">
      <div className="flex flex-col gap-2">
        <BarList
          ariaLabel={title}
          loading={items === null}
          emptyText={emptyText}
          items={(items ?? []).map((item) => ({
            key: item.key,
            label: label?.(item.key) ?? (item.key === '' ? '-' : item.key),
            value: item.count,
            valueText: formatCount(item.count),
          }))}
          {...(onSelect === undefined ? {} : { onSelect })}
          {...(selectLabel === undefined ? {} : { selectLabel: (item) => selectLabel(item.key) })}
        />
        {footer !== undefined && items !== null && items.length > 0 && (
          <div className="border-t border-line pt-2 text-meta text-muted">{footer}</div>
        )}
      </div>
    </Card>
  );
}
