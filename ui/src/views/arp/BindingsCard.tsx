import type { ColumnDef } from '@tanstack/react-table';
import { useDeferredValue, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useArpBindings } from '../../api/arpQueries';
import type { ArpBindingInfo } from '../../api/types/ArpBindingInfo';
import { useViewRange } from '../../app/timeRange';
import { Badge } from '../../components/Badge';
import { Card } from '../../components/Card';
import { CopyButton } from '../../components/CopyButton';
import { DataTable } from '../../components/DataTable';
import { Endpoint } from '../../components/Endpoint';
import { ErrorState } from '../../components/ErrorState';
import { SearchInput } from '../../components/SearchInput';
import { Skeleton } from '../../components/Skeleton';
import { Timestamp } from '../../components/Timestamp';
import { Toggle } from '../../components/Toggle';
import { cn } from '../../lib/cn';
import { formatCount, formatTimestamp, labelled } from '../../lib/format';
import { LG_QUERY, MD_QUERY, useMediaQuery } from '../../lib/useMediaQuery';
import { ipSortKey } from './format';

interface BindingsCardProps {
  sessionId: string;
  /** First and last message of the session or range: reference of the activity bars. */
  period: readonly [number, number] | null;
  oneDay: boolean;
  onSelect: (binding: ArpBindingInfo) => void;
}

/** IP to MAC pairs with their activity in time (folded rows: counters of the session). */
export function BindingsCard({ sessionId, period, oneDay, onSelect }: BindingsCardProps) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const q = useDeferredValue(search);
  const [conflicts, setConflicts] = useState(false);
  const list = useArpBindings(sessionId, { q, conflicts }, true);
  const ranged = useViewRange() !== null;
  // From 768 to 1024 px the activity bars are left out so that the table fits without scrolling
  // (the cards drawn below 768 px keep them).
  const lg = useMediaQuery(LG_QUERY);
  const md = useMediaQuery(MD_QUERY);
  const wide = lg || !md;
  const columns = useBindingColumns(period, oneDay, ranged, wide);

  let body;
  if (list.isPending) body = <Skeleton height={160} />;
  else if (list.isError) body = <ErrorState message={t('views.arp.loadError')} onRetry={() => void list.refetch()} />;
  else
    body = (
      <>
        <DataTable
          columns={columns}
          data={list.data.items}
          getRowId={(b) => `${b.ip.ip} ${b.mac}`}
          ariaLabel={t('views.arp.bindings.label')}
          cards
          maxHeight={420}
          emptyText={t('views.arp.bindings.empty')}
          onRowClick={onSelect}
        />
        {list.data.truncated && (
          <p className="border-t border-line px-3 py-2 text-meta text-muted sm:px-4">
            {t('views.arp.bindings.truncated', { count: list.data.items.length })}
          </p>
        )}
      </>
    );

  return (
    <Card
      title={t('views.arp.bindings.title')}
      flush
      filters={
        <div className="flex min-w-0 flex-wrap items-center gap-2" data-testid="arp-binding-filters">
          <SearchInput value={search} onChange={setSearch} placeholder={t('views.arp.bindings.search')} />
          <Toggle label={t('views.arp.bindings.conflictsOnly')} checked={conflicts} onChange={setConflicts} />
        </div>
      }
    >
      {body}
    </Card>
  );
}

function useBindingColumns(
  period: readonly [number, number] | null,
  oneDay: boolean,
  ranged: boolean,
  wide: boolean,
): ColumnDef<ArpBindingInfo, unknown>[] {
  const { t } = useTranslation();
  return useMemo<ColumnDef<ArpBindingInfo, unknown>[]>(() => {
    const counter = (label: string) => (ranged ? t('timeRange.wholeSessionColumn', { label }) : label);
    const all: ColumnDef<ArpBindingInfo, unknown>[] = [
      {
        id: 'ip',
        meta: { card: 'title' },
        accessorFn: (b) => ipSortKey(b.ip.ip),
        header: t('views.arp.bindings.col.ip'),
        size: wide ? 200 : 130,
        cell: ({ row }) => <Endpoint endpoint={row.original.ip} show={wide ? 'both' : 'address'} />,
      },
      {
        id: 'conflict',
        meta: { card: 'action' },
        accessorFn: (b) => (b.conflict ? 1 : 0),
        header: t('views.arp.bindings.conflict'),
        size: 88,
        cell: ({ row }) => (row.original.conflict ? <Badge tone="warning">{t('views.arp.bindings.conflict')}</Badge> : null),
      },
      {
        id: 'mac',
        accessorFn: (b) => b.mac,
        header: t('views.arp.bindings.col.mac'),
        size: 196,
        cell: ({ row }) => (
          <span className="inline-flex max-w-full min-w-0 items-center">
            <span data-testid="truncatable" title={row.original.mac} className="truncate font-mono">
              {row.original.mac}
            </span>
            <CopyButton value={row.original.mac} name={t('views.arp.mac')} />
          </span>
        ),
      },
      {
        id: 'first',
        accessorFn: (b) => b.first_ts_us,
        header: t('views.arp.bindings.col.first'),
        size: oneDay ? 96 : 168,
        cell: ({ row }) => <Timestamp us={row.original.first_ts_us} withDate={!oneDay} />,
      },
      {
        id: 'last',
        accessorFn: (b) => b.last_ts_us,
        header: t('views.arp.bindings.col.last'),
        size: oneDay ? 96 : 168,
        cell: ({ row }) => <Timestamp us={row.original.last_ts_us} withDate={!oneDay} />,
      },
      {
        id: 'activity',
        enableSorting: false,
        header: t('views.arp.bindings.col.activity'),
        size: 120,
        cell: ({ row }) => <ActivityBar binding={row.original} period={period} />,
      },
      {
        id: 'messages',
        meta: { align: 'right' },
        accessorFn: (b) => b.messages,
        header: counter(t('views.arp.bindings.col.messages')),
        size: ranged ? 190 : 104,
        cell: ({ row }) => {
          const b = row.original;
          const detail = [
            labelled(t('views.arp.bindings.col.requests'), formatCount(b.requests)),
            labelled(t('views.arp.bindings.col.replies'), formatCount(b.replies)),
            labelled(t('views.arp.bindings.col.gratuitous'), formatCount(b.gratuitous)),
          ].join(', ');
          return (
            <span className="num" title={detail}>
              {formatCount(b.messages)}
            </span>
          );
        },
      },
    ];
    return wide ? all : all.filter((c) => c.id !== 'activity');
  }, [t, period, oneDay, ranged, wide]);
}

/** Where the activity of a binding lies in the period of the messages shown. */
function ActivityBar({ binding: b, period }: { binding: ArpBindingInfo; period: readonly [number, number] | null }) {
  const { t } = useTranslation();
  if (period === null) return null;
  const [start, end] = period;
  const span = Math.max(1, end - start);
  const clamp = (v: number) => Math.min(1, Math.max(0, (v - start) / span));
  const left = clamp(b.first_ts_us);
  const right = clamp(b.last_ts_us);
  const title = t('views.arp.bindings.activityTitle', {
    from: formatTimestamp(b.first_ts_us),
    to: formatTimestamp(b.last_ts_us),
  });
  return (
    <span role="img" aria-label={title} title={title} className="relative block h-2 w-full min-w-12 overflow-hidden rounded-full bg-subtle">
      <span
        className={cn('absolute inset-y-0 rounded-full', b.conflict ? 'bg-warning' : 'bg-accent')}
        style={{ left: `min(${left * 100}%, calc(100% - 4px))`, width: `max(4px, ${(right - left) * 100}%)` }}
      />
    </span>
  );
}
