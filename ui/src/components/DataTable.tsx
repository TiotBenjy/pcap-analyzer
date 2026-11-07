import {
  type ColumnDef,
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  type SortingState,
  useReactTable,
} from '@tanstack/react-table';
import { useVirtualizer } from '@tanstack/react-virtual';
import { ArrowDown, ArrowUp } from 'lucide-react';
import { type KeyboardEvent, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { cn } from '../lib/cn';
import { EmptyState } from './EmptyState';

/** Above this many rows the body is virtualized (docs/UI_GUIDELINES.md). */
export const VIRTUALIZE_THRESHOLD = 200;
const ROW_HEIGHT = 32;

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
}

/**
 * Generic table: sticky header, resizable columns, client-side sorting, virtualization above
 * 200 rows. Horizontal overflow scrolls inside the container, never the page.
 */
export function DataTable<T>({
  columns,
  data,
  getRowId,
  maxHeight = 560,
  emptyText,
  onRowClick,
  ariaLabel,
}: DataTableProps<T>) {
  const { t } = useTranslation();
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
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
  });

  if (data.length === 0) {
    return <EmptyState title={emptyText ?? t('common.noData')} />;
  }

  const items = virtual ? virtualizer.getVirtualItems() : [];
  const padTop = virtual ? (items[0]?.start ?? 0) : 0;
  const padBottom = virtual ? virtualizer.getTotalSize() - (items.at(-1)?.end ?? 0) : 0;
  const visible = virtual ? items.map((v) => rows[v.index]).filter((r) => r !== undefined) : rows;
  const colCount = table.getVisibleLeafColumns().length;

  return (
    <div ref={scrollRef} className="w-full min-w-0 overflow-auto" style={{ maxHeight }} data-testid="datatable">
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
                return (
                  <th
                    key={header.id}
                    scope="col"
                    style={{ width: header.getSize() }}
                    aria-sort={sorted === 'asc' ? 'ascending' : sorted === 'desc' ? 'descending' : 'none'}
                    className="relative h-8 border-b border-line px-3 text-left text-meta font-medium text-muted select-none"
                  >
                    {header.isPlaceholder ? null : header.column.getCanSort() ? (
                      <button
                        type="button"
                        onClick={header.column.getToggleSortingHandler()}
                        className="inline-flex max-w-full items-center gap-1 hover:text-fg"
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
          {visible.map((row, i) => (
            <tr
              key={row.id}
              style={{ height: ROW_HEIGHT }}
              aria-rowindex={(virtual ? (items[i]?.index ?? i) : i) + 2}
              {...(onRowClick === undefined
                ? {}
                : {
                    tabIndex: 0,
                    onClick: () => {
                      onRowClick(row.original);
                    },
                    onKeyDown: (e: KeyboardEvent<HTMLTableRowElement>) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        onRowClick(row.original);
                      }
                    },
                  })}
              className={cn(
                'border-b border-line last:border-b-0',
                onRowClick !== undefined && 'cursor-pointer hover:bg-subtle focus-visible:bg-subtle',
              )}
            >
              {row.getVisibleCells().map((cell) => (
                <td key={cell.id} className="truncate px-3">
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
