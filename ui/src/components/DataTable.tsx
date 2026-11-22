import {
  type ColumnDef,
  flexRender,
  type RowData,
  getCoreRowModel,
  getSortedRowModel,
  type SortingState,
  useReactTable,
} from '@tanstack/react-table';
import { useVirtualizer } from '@tanstack/react-virtual';
import { ArrowDown, ArrowUp } from 'lucide-react';
import { type KeyboardEvent, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { cn } from '../lib/cn';
import { MD_QUERY, useMediaQuery } from '../lib/useMediaQuery';
import { EmptyState } from './EmptyState';

declare module '@tanstack/react-table' {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars -- signature imposed by TanStack
  interface ColumnMeta<TData extends RowData, TValue> {
    /** `right` for numeric columns (header and cells). */
    align?: 'left' | 'right';
    /**
     * Place of the column in the cards drawn below 768 px (`cards`): `title` on the first line,
     * `action` at its end, `hidden` left out; a labelled line by default.
     */
    card?: 'title' | 'action' | 'hidden';
  }
}

/** Above this many rows the body is virtualized (docs/UI_GUIDELINES.md). */
export const VIRTUALIZE_THRESHOLD = 200;
const ROW_HEIGHT = 32;
/** First guess of a card height, measured once drawn. */
const CARD_HEIGHT = 96;

interface DataTableProps<T> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- TanStack column value types are heterogeneous
  columns: ColumnDef<T, any>[];
  data: readonly T[];
  getRowId: (row: T, index: number) => string;
  /** Maximum height of the scroll container, in px. */
  maxHeight?: number;
  emptyText?: string;
  onRowClick?: (row: T) => void;
  /** Accessible table name. */
  ariaLabel: string;
  /**
   * Below 768 px, draws one card per row instead of the table (docs/UI_GUIDELINES.md): `title`
   * and `action` columns on the first line, the others as labelled lines (`meta.card`).
   */
  cards?: boolean;
}

/**
 * Generic table: sticky header, resizable columns, client-side sorting, virtualization above
 * 200 rows. Horizontal overflow scrolls inside the container, never the page. With `cards`, rows
 * become stacked cards below 768 px, so that no column hides in a horizontal scroll.
 */
export function DataTable<T>({
  columns,
  data,
  getRowId,
  maxHeight = 560,
  emptyText,
  onRowClick,
  ariaLabel,
  cards = false,
}: DataTableProps<T>) {
  const { t } = useTranslation();
  const wide = useMediaQuery(MD_QUERY);
  const asCards = cards && !wide;
  const [sorting, setSorting] = useState<SortingState>([]);
  const scrollRef = useRef<HTMLDivElement>(null);

  // eslint-disable-next-line react-hooks/incompatible-library -- TanStack Table is not memo-safe by design
  const table = useReactTable({
    columns,
    data: data as T[],
    getRowId,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    columnResizeMode: 'onChange',
    enableColumnResizing: true,
  });

  const rows = table.getRowModel().rows;
  const virtual = rows.length > VIRTUALIZE_THRESHOLD;
  const virtualizer = useVirtualizer({
    count: virtual ? rows.length : 0,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => (asCards ? CARD_HEIGHT : ROW_HEIGHT),
    overscan: asCards ? 6 : 12,
  });
  // Sizes measured in one mode (cards) must not be applied to the other (rows).
  useEffect(() => {
    virtualizer.measure();
  }, [asCards, virtualizer]);

  if (data.length === 0) {
    return <EmptyState title={emptyText ?? t('common.noData')} />;
  }

  const items = virtual ? virtualizer.getVirtualItems() : [];
  const padTop = virtual ? (items[0]?.start ?? 0) : 0;
  const padBottom = virtual ? virtualizer.getTotalSize() - (items.at(-1)?.end ?? 0) : 0;
  const visible = (
    virtual ? items.map((v) => ({ row: rows[v.index], pos: v.index })) : rows.map((row, pos) => ({ row, pos }))
  ).filter((v): v is { row: (typeof rows)[number]; pos: number } => v.row !== undefined);
  const colCount = table.getVisibleLeafColumns().length;
  const clickProps = (row: T) =>
    onRowClick === undefined
      ? {}
      : {
          tabIndex: 0,
          onClick: () => {
            onRowClick(row);
          },
          onKeyDown: (e: KeyboardEvent<HTMLElement>) => {
            // Enter or Space on a nested control (copy, download) belongs to that control.
            if (e.target !== e.currentTarget) return;
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              onRowClick(row);
            }
          },
        };

  if (asCards) {
    const headers = new Map(table.getFlatHeaders().map((h) => [h.column.id, h]));
    return (
      <div ref={scrollRef} className="relative w-full min-w-0 overflow-auto" style={{ maxHeight }} data-testid="datatable">
        <ul aria-label={ariaLabel} className="divide-y divide-line">
          {padTop > 0 && <li aria-hidden style={{ height: padTop }} />}
          {visible.map(({ row, pos }) => {
            const cells = row.getVisibleCells();
            const place = (c: (typeof cells)[number]) => c.column.columnDef.meta?.card;
            const title = cells.filter((c) => place(c) === 'title');
            const actions = cells.filter((c) => place(c) === 'action');
            const lines = cells.filter((c) => place(c) === undefined);
            return (
              <li
                key={row.id}
                data-index={pos}
                ref={virtual ? virtualizer.measureElement : undefined}
                {...clickProps(row.original)}
                className={cn(
                  'flex min-w-0 flex-col gap-1.5 px-3 py-2.5',
                  onRowClick !== undefined && 'cursor-pointer hover:bg-subtle focus-visible:bg-subtle',
                )}
              >
                {(title.length > 0 || actions.length > 0) && (
                  <div className="flex min-w-0 items-center gap-2">
                    <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-2 gap-y-1 font-medium">
                      {title.map((c) => (
                        <div key={c.id} className="max-w-full min-w-0">
                          {flexRender(c.column.columnDef.cell, c.getContext())}
                        </div>
                      ))}
                    </div>
                    {actions.map((c) => (
                      <div key={c.id} className="shrink-0">
                        {flexRender(c.column.columnDef.cell, c.getContext())}
                      </div>
                    ))}
                  </div>
                )}
                {lines.length > 0 && (
                  <dl className="grid min-w-0 grid-cols-[minmax(0,8rem)_minmax(0,1fr)] gap-x-3 gap-y-1 text-meta">
                    {lines.map((c) => {
                      const header = headers.get(c.column.id);
                      return (
                        <div key={c.id} className="contents">
                          <dt className="min-w-0 truncate text-muted">
                            {header === undefined ? null : flexRender(c.column.columnDef.header, header.getContext())}
                          </dt>
                          <dd className="min-w-0 truncate">{flexRender(c.column.columnDef.cell, c.getContext())}</dd>
                        </div>
                      );
                    })}
                  </dl>
                )}
              </li>
            );
          })}
          {padBottom > 0 && <li aria-hidden style={{ height: padBottom }} />}
        </ul>
      </div>
    );
  }

  return (
    <div ref={scrollRef} className="relative w-full min-w-0 overflow-auto" style={{ maxHeight }} data-testid="datatable">
      <table
        aria-label={ariaLabel}
        aria-rowcount={rows.length + 1}
        className="w-full table-fixed border-collapse text-table"
        style={{ minWidth: table.getTotalSize() }}
      >
        <thead className="sticky top-0 z-10 bg-surface">
          {table.getHeaderGroups().map((hg) => (
            <tr key={hg.id}>
              {hg.headers.map((header) => {
                const sorted = header.column.getIsSorted();
                const right = header.column.columnDef.meta?.align === 'right';
                return (
                  <th
                    key={header.id}
                    scope="col"
                    style={{ width: header.getSize() }}
                    aria-sort={sorted === 'asc' ? 'ascending' : sorted === 'desc' ? 'descending' : 'none'}
                    className={cn(
                      'relative h-8 border-b border-line px-3 text-meta font-medium text-muted select-none',
                      right ? 'text-right' : 'text-left',
                    )}
                  >
                    {header.isPlaceholder ? null : header.column.getCanSort() ? (
                      <button
                        type="button"
                        onClick={header.column.getToggleSortingHandler()}
                        className={cn('inline-flex max-w-full items-center gap-1 hover:text-fg', right && 'flex-row-reverse')}
                      >
                        <span className="truncate">{flexRender(header.column.columnDef.header, header.getContext())}</span>
                        {sorted === 'asc' && <ArrowUp aria-hidden size={14} strokeWidth={1.75} />}
                        {sorted === 'desc' && <ArrowDown aria-hidden size={14} strokeWidth={1.75} />}
                      </button>
                    ) : (
                      <span className="truncate">{flexRender(header.column.columnDef.header, header.getContext())}</span>
                    )}
                    {header.column.getCanResize() && (
                      <div
                        aria-hidden
                        onMouseDown={header.getResizeHandler()}
                        onTouchStart={header.getResizeHandler()}
                        className={cn(
                          'absolute top-0 right-0 h-full w-1 cursor-col-resize touch-none hover:bg-accent',
                          header.column.getIsResizing() && 'bg-accent',
                        )}
                      />
                    )}
                  </th>
                );
              })}
            </tr>
          ))}
        </thead>
        <tbody>
          {padTop > 0 && (
            <tr aria-hidden>
              <td colSpan={colCount} style={{ height: padTop }} />
            </tr>
          )}
          {visible.map(({ row, pos }) => (
            <tr
              key={row.id}
              style={{ height: ROW_HEIGHT }}
              aria-rowindex={pos + 2}
              {...clickProps(row.original)}
              className={cn(
                'border-b border-line last:border-b-0',
                onRowClick !== undefined && 'cursor-pointer hover:bg-subtle focus-visible:bg-subtle',
              )}
            >
              {row.getVisibleCells().map((cell) => (
                <td
                  key={cell.id}
                  className={cn('truncate px-3', cell.column.columnDef.meta?.align === 'right' && 'text-right')}
                >
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </td>
              ))}
            </tr>
          ))}
          {padBottom > 0 && (
            <tr aria-hidden>
              <td colSpan={colCount} style={{ height: padBottom }} />
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
