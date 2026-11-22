import type { ColumnDef } from '@tanstack/react-table';
import { X } from 'lucide-react';
import { type ReactNode, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ARP_KINDS, type ArpKind, type ArpMessageFilters } from '../../api/arp';
import { useArpMessages } from '../../api/arpQueries';
import type { ArpMessageInfo } from '../../api/types/ArpMessageInfo';
import type { ArpStats } from '../../api/types/ArpStats';
import { Badge, type BadgeTone } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { DataTable } from '../../components/DataTable';
import { EmptyState } from '../../components/EmptyState';
import { Endpoint } from '../../components/Endpoint';
import { ErrorState } from '../../components/ErrorState';
import { FilterBar } from '../../components/FilterBar';
import { Skeleton } from '../../components/Skeleton';
import { Timestamp } from '../../components/Timestamp';
import { LG_QUERY, MD_QUERY, useMediaQuery } from '../../lib/useMediaQuery';

/** Address filter of the message list: an IP (sender or target), optionally with a sender MAC. */
export interface AddressFilter {
  ip?: string;
  mac?: string;
}

const UNSOLICITED = 'unsolicited';
const KIND_TONES: Record<ArpKind, BadgeTone> = {
  request: 'neutral',
  reply: 'neutral',
  gratuitous: 'accent',
  probe: 'neutral',
  other: 'neutral',
};

function isKind(value: string): value is ArpKind {
  return (ARP_KINDS as readonly string[]).includes(value);
}

interface MessagesCardProps {
  sessionId: string;
  stats: ArpStats;
  oneDay: boolean;
  address: AddressFilter | null;
  onAddress: (address: AddressFilter | null) => void;
  unsolicited: boolean;
  onUnsolicited: (on: boolean) => void;
}

/** ARP messages in time order, filtered by type, address and unsolicited replies. */
export function MessagesCard({ sessionId, stats, oneDay, address, onAddress, unsolicited, onUnsolicited }: MessagesCardProps) {
  const { t } = useTranslation();
  const [kinds, setKinds] = useState<ReadonlySet<ArpKind>>(() => new Set(ARP_KINDS));
  const filters = useMemo<ArpMessageFilters>(
    () => ({
      // Every type selected: no type filter (the server reads it as "all").
      kinds: kinds.size === ARP_KINDS.length ? [] : ARP_KINDS.filter((k) => kinds.has(k)),
      ip: address?.ip,
      mac: address?.mac,
      unsolicited,
    }),
    [kinds, address, unsolicited],
  );
  const none = kinds.size === 0;
  const list = useArpMessages(sessionId, filters, !none);
  // From 768 to 1024 px the target MAC (zero in requests) is left out of the table; the cards drawn
  // below 768 px keep it.
  const lg = useMediaQuery(LG_QUERY);
  const md = useMediaQuery(MD_QUERY);
  const wide = lg || !md;
  const columns = useMessageColumns(oneDay, wide);
  const filtered = kinds.size !== ARP_KINDS.length || address !== null || unsolicited;

  let body: ReactNode;
  if (none) body = <EmptyState title={t('views.arp.messages.empty')} />;
  else if (list.isPending) body = <Skeleton height={160} />;
  else if (list.isError) body = <ErrorState message={t('views.arp.loadError')} onRetry={() => void list.refetch()} />;
  else
    body = (
      <>
        <DataTable
          columns={columns}
          data={list.data.items}
          getRowId={(m) => m.id}
          ariaLabel={t('views.arp.messages.label')}
          cards
          emptyText={t('views.arp.messages.empty')}
        />
        {list.data.truncated && (
          <p className="border-t border-line px-3 py-2 text-meta text-muted sm:px-4">
            {t('views.arp.messages.truncated', { count: list.data.items.length })}
          </p>
        )}
      </>
    );

  const addressText = address === null ? '' : [address.ip, address.mac].filter((v) => v !== undefined).join(' ');
  return (
    <Card
      title={t('views.arp.messages.title')}
      flush
      filters={
        <div className="flex min-w-0 flex-wrap items-center gap-2" data-testid="arp-message-filters">
          <FilterBar
            filters={[
              // `other` (RARP, InARP...) only when there is some, or when it was switched off.
              ...ARP_KINDS.filter((k) => k !== 'other' || stats.kinds.other > 0 || !kinds.has(k)).map((k) => ({
                id: k,
                label: t(`views.arp.filters.${k}`),
                count: stats.kinds[k],
                active: kinds.has(k),
              })),
              { id: UNSOLICITED, label: t('views.arp.filters.unsolicited'), count: stats.unsolicited, active: unsolicited },
            ]}
            onToggle={(id, active) => {
              if (id === UNSOLICITED) {
                onUnsolicited(active);
                return;
              }
              if (!isKind(id)) return;
              setKinds((cur) => {
                const next = new Set(cur);
                if (active) next.add(id);
                else next.delete(id);
                return next;
              });
            }}
          />
          {address !== null && (
            <span className="inline-flex h-8 max-w-full min-w-0 items-center rounded-md border border-accent bg-accent-soft pl-2.5 text-body">
              <span data-testid="truncatable" title={addressText} className="min-w-0 truncate font-mono text-table">
                {t('views.arp.filters.address', { address: addressText })}
              </span>
              <button
                type="button"
                aria-label={t('views.arp.filters.clearAddress')}
                title={t('views.arp.filters.clearAddress')}
                onClick={() => {
                  onAddress(null);
                }}
                className="inline-flex size-8 shrink-0 items-center justify-center rounded-md text-muted hover:text-fg"
              >
                <X aria-hidden size={16} strokeWidth={1.75} />
              </button>
            </span>
          )}
          {filtered && (
            <Button
              variant="ghost"
              onClick={() => {
                setKinds(new Set(ARP_KINDS));
                onAddress(null);
                onUnsolicited(false);
              }}
            >
              {t('views.arp.filters.clear')}
            </Button>
          )}
        </div>
      }
    >
      {body}
    </Card>
  );
}

function Mac({ value }: { value: string | null }) {
  if (value === null) return null;
  const unknown = value === '00:00:00:00:00:00';
  return (
    <span data-testid="truncatable" title={value} className={unknown ? 'block truncate font-mono text-faint' : 'block truncate font-mono'}>
      {value}
    </span>
  );
}

/** Column widths from 768 to 1024 px (about 700 px in all: a MAC address and both badges fit). */
const NARROW_SIZES: Readonly<Record<string, number>> = { kind: 184, sender: 124, senderMac: 164, target: 124 };

function useMessageColumns(oneDay: boolean, wide: boolean): ColumnDef<ArpMessageInfo, unknown>[] {
  const { t } = useTranslation();
  return useMemo<ColumnDef<ArpMessageInfo, unknown>[]>(() => {
    const all: ColumnDef<ArpMessageInfo, unknown>[] = [
      {
        id: 'time',
        meta: { card: 'title' },
        accessorFn: (m) => m.ts_us,
        header: t('views.arp.messages.col.time'),
        size: oneDay ? 96 : 176,
        cell: ({ row }) => <Timestamp us={row.original.ts_us} withDate={!oneDay} />,
      },
      {
        id: 'kind',
        meta: { card: 'title' },
        accessorFn: (m) => m.kind,
        header: t('views.arp.messages.col.kind'),
        size: 200,
        cell: ({ row }) => {
          const m = row.original;
          const kind = isKind(m.kind) ? m.kind : 'other';
          return (
            <span className="inline-flex max-w-full min-w-0 items-center gap-1.5 overflow-hidden">
              <Badge tone={KIND_TONES[kind]}>{t(`views.arp.kind.${kind}`)}</Badge>
              {m.unsolicited && <Badge tone="warning">{t('views.arp.messages.unsolicited')}</Badge>}
            </span>
          );
        },
      },
      {
        id: 'sender',
        accessorFn: (m) => m.sender?.ip ?? '',
        header: t('views.arp.messages.col.sender'),
        size: 170,
        cell: ({ row }) => (row.original.sender === null ? null : <Endpoint endpoint={row.original.sender} show="address" />),
      },
      {
        id: 'senderMac',
        accessorFn: (m) => m.sender_mac ?? '',
        header: t('views.arp.messages.col.senderMac'),
        size: 170,
        cell: ({ row }) => <Mac value={row.original.sender_mac} />,
      },
      {
        id: 'target',
        accessorFn: (m) => m.target?.ip ?? '',
        header: t('views.arp.messages.col.target'),
        size: 170,
        cell: ({ row }) => (row.original.target === null ? null : <Endpoint endpoint={row.original.target} show="address" />),
      },
      {
        id: 'targetMac',
        accessorFn: (m) => m.target_mac ?? '',
        header: t('views.arp.messages.col.targetMac'),
        size: 170,
        cell: ({ row }) => <Mac value={row.original.target_mac} />,
      },
    ];
    return all
      .filter((c) => wide || c.id !== 'targetMac')
      .map((c) => {
        const narrow = c.id === undefined ? undefined : NARROW_SIZES[c.id];
        return wide || narrow === undefined ? c : { ...c, size: narrow };
      });
  }, [t, oneDay, wide]);
}
