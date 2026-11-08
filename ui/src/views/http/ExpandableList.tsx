import { useVirtualizer } from '@tanstack/react-virtual';
import { ChevronRight } from 'lucide-react';
import { type ReactNode, useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '../../components/Button';
import { cn } from '../../lib/cn';

/** Lists longer than this (or with more pages to load) are virtualized. */
export const VIRTUALIZE_FROM = 100;
const ESTIMATED_ROW = 44;
/** Next page is requested when the last rendered row is this close to the end. */
const PREFETCH_ROWS = 20;

interface ExpandableListProps<T> {
  items: readonly T[];
  getKey: (item: T) => number;
  /** Accessible name of the list. */
  ariaLabel: string;
  /** Column titles (wide layouts), above the scrolling rows. */
  header?: ReactNode;
  /** Summary of a row (inside its expand button). */
  renderRow: (item: T) => ReactNode;
  /** Content shown under an expanded row. */
  renderDetail: (item: T) => ReactNode;
  /** Accessible label of the expand button of a row. */
  rowLabel: (item: T) => string;
  hasMore: boolean;
  loadingMore: boolean;
  onLoadMore: () => void;
  maxHeight?: number;
}

/**
 * Rows that expand in place, loaded page by page. Virtualized (rows of any height, measured)
 * when long; the list scrolls inside its own container, never the page horizontally.
 */
export function ExpandableList<T>({
  items,
  getKey,
  ariaLabel,
  header,
  renderRow,
  renderDetail,
  rowLabel,
  hasMore,
  loadingMore,
  onLoadMore,
  maxHeight = 640,
}: ExpandableListProps<T>) {
  const { t } = useTranslation();
  const scrollRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState<ReadonlySet<number>>(new Set());
  const baseId = useId();
  const virtual = hasMore || items.length > VIRTUALIZE_FROM;
  // eslint-disable-next-line react-hooks/incompatible-library -- TanStack Virtual is not memo-safe by design
  const virtualizer = useVirtualizer({
    count: virtual ? items.length : 0,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ESTIMATED_ROW,
    overscan: 8,
    getItemKey: (index) => {
      const item = items[index];
      return item === undefined ? index : getKey(item);
    },
  });
  const virtualItems = virtual ? virtualizer.getVirtualItems() : [];
  const lastIndex = virtualItems.at(-1)?.index ?? -1;

  useEffect(() => {
    if (virtual && hasMore && !loadingMore && lastIndex >= items.length - PREFETCH_ROWS) onLoadMore();
  }, [virtual, hasMore, loadingMore, lastIndex, items.length, onLoadMore]);

  const toggle = (key: number) => {
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const row = (item: T, index: number) => {
    const key = getKey(item);
    const expanded = open.has(key);
    const detailId = `${baseId}-${key}`;
    return (
      <div
        key={key}
        role="listitem"
        data-index={index}
        ref={virtual ? virtualizer.measureElement : undefined}
        className="border-b border-line last:border-b-0"
      >
        <button
          type="button"
          aria-expanded={expanded}
          aria-controls={expanded ? detailId : undefined}
          aria-label={rowLabel(item)}
          onClick={() => {
            toggle(key);
          }}
          className={cn(
            'flex w-full min-w-0 items-start gap-2 px-3 py-2 text-left hover:bg-subtle focus-visible:bg-subtle',
            expanded && 'bg-subtle',
          )}
        >
          <ChevronRight
            aria-hidden
            size={16}
            strokeWidth={1.75}
            className={cn('mt-0.5 shrink-0 text-faint transition-transform', expanded && 'rotate-90')}
          />
          <span className="block min-w-0 flex-1">{renderRow(item)}</span>
        </button>
        {expanded && (
          <div id={detailId} className="border-t border-line bg-app/40 px-3 py-3 sm:px-4">
            {renderDetail(item)}
          </div>
        )}
      </div>
    );
  };

  const padTop = virtualItems[0]?.start ?? 0;
  const padBottom = virtual ? virtualizer.getTotalSize() - (virtualItems.at(-1)?.end ?? 0) : 0;

  return (
    <div className="flex min-w-0 flex-col">
      {header}
      <div ref={scrollRef} className="min-w-0 overflow-y-auto overscroll-contain" style={{ maxHeight }}>
        <div role="list" aria-label={ariaLabel} style={virtual ? { paddingTop: padTop, paddingBottom: padBottom } : undefined}>
          {virtual
            ? virtualItems.map((v) => {
                const item = items[v.index];
                return item === undefined ? null : row(item, v.index);
              })
            : items.map(row)}
        </div>
      </div>
      {hasMore && (
        <div className="flex justify-center border-t border-line p-2">
          <Button variant="ghost" disabled={loadingMore} onClick={onLoadMore}>
            {loadingMore ? t('common.loading') : t('views.http.loadMore')}
          </Button>
        </div>
      )}
    </div>
  );
}
