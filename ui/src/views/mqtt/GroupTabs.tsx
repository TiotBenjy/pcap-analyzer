import type { ColumnDef } from '@tanstack/react-table';
import { type ReactNode, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useMqttBrokers, useMqttClients } from '../../api/mqttQueries';
import type { MqttBrokerInfo } from '../../api/types/MqttBrokerInfo';
import type { MqttClientInfo } from '../../api/types/MqttClientInfo';
import type { Page } from '../../api/types/Page';
import { Badge } from '../../components/Badge';
import { Card } from '../../components/Card';
import { DataTable } from '../../components/DataTable';
import { Endpoint } from '../../components/Endpoint';
import { ErrorState } from '../../components/ErrorState';
import { SearchInput } from '../../components/SearchInput';
import { Skeleton } from '../../components/Skeleton';
import { Timestamp } from '../../components/Timestamp';
import { wholeSessionHeader } from '../../components/wholeSessionHeader';
import { formatCount } from '../../lib/format';
import { useDebounced } from '../../lib/useDebounced';
import { LoadMore } from '../connections/LoadMore';
import { ClientId } from './ConnectionsTab';

interface ListQuery<T> {
  data: { pages: Page<T>[] } | undefined;
  isError: boolean;
  hasNextPage: boolean;
  isFetchingNextPage: boolean;
  fetchNextPage: () => Promise<unknown>;
  refetch: () => Promise<unknown>;
}

/** Body of a keyset table: loading, error, rows and the "load more" footer. */
function PagedTable<T>({ query, children }: { query: ListQuery<T>; children: (items: T[]) => ReactNode }) {
  const { t } = useTranslation();
  if (query.isError)
    return (
      <ErrorState
        message={t('views.mqtt.loadError')}
        onRetry={() => {
          void query.refetch();
        }}
      />
    );
  if (query.data === undefined)
    return (
      <div className="p-3 sm:p-4">
        <Skeleton height={160} />
      </div>
    );
  const items = query.data.pages.flatMap((p) => p.items);
  return (
    <>
      {children(items)}
      <LoadMore
        shown={items.length}
        total={query.data.pages[0]?.total_estimate ?? null}
        hasMore={query.hasNextPage}
        loading={query.isFetchingNextPage}
        onMore={() => {
          void query.fetchNextPage();
        }}
      />
    </>
  );
}

interface TabProps {
  sessionId: string;
  enabled: boolean;
  oneDay: boolean;
  ranged: boolean;
}

/** Clients: connections grouped by client identifier (or address without identifier). */
export function ClientsTab({ sessionId, enabled, oneDay, ranged, onSelect }: TabProps & { onSelect: (c: MqttClientInfo) => void }) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const q = useDebounced(search.trim());
  const query = useMqttClients(sessionId, q === '' ? {} : { q }, enabled);
  const columns = useMemo<ColumnDef<MqttClientInfo>[]>(() => {
    const counter = (label: string) => wholeSessionHeader(label, ranged);
    return [
      {
        id: 'client',
        meta: { card: 'title' },
        accessorFn: (c) => c.client_id ?? c.key,
        header: t('views.mqtt.clients.col.client'),
        size: 200,
        cell: ({ row }) => (
          <span className="flex min-w-0 items-center gap-1.5">
            <ClientId id={row.original.client_id} />
            {row.original.wildcard && <Badge tone="warning">{t('views.mqtt.signals.kind.wildcard')}</Badge>}
          </span>
        ),
      },
      {
        id: 'addresses',
        accessorFn: (c) => c.addresses[0]?.ip ?? '',
        header: t('views.mqtt.clients.col.addresses'),
        size: 190,
        cell: ({ row }) => {
          const c = row.original;
          const first = c.addresses[0];
          return (
            <span className="flex min-w-0 items-center gap-1.5">
              {first !== undefined && <Endpoint endpoint={first} show="address" />}
              {c.address_count > 1 && <span className="num text-muted">{t('views.mqtt.clients.more', { count: c.address_count - 1 })}</span>}
            </span>
          );
        },
      },
      {
        id: 'users',
        accessorFn: (c) => c.usernames.join(', '),
        header: t('views.mqtt.clients.col.users'),
        size: 140,
        cell: ({ row }) => {
          const users = row.original.usernames.join(', ');
          return (
            <span data-testid="truncatable" title={users} className="block min-w-0 truncate font-mono">
              {users}
            </span>
          );
        },
      },
      {
        id: 'connections',
        meta: { align: 'right' },
        accessorFn: (c) => c.connections,
        header: counter(t('views.mqtt.clients.col.connections')),
        size: 130,
        cell: ({ row }) => (
          <span className="num">
            {formatCount(row.original.connections)}
            {row.original.rejected > 0 && (
              <span className="text-danger">{` (${t('views.mqtt.clients.rejected', { count: row.original.rejected })})`}</span>
            )}
          </span>
        ),
      },
      {
        id: 'versions',
        accessorFn: (c) => c.versions.join(' '),
        header: t('views.mqtt.clients.col.versions'),
        size: 110,
        cell: ({ row }) => <span className="font-mono text-muted">{row.original.versions.join(', ')}</span>,
      },
      {
        id: 'published',
        meta: { align: 'right' },
        accessorFn: (c) => c.publish_c2s,
        header: counter(t('views.mqtt.clients.col.published')),
        size: 110,
        cell: ({ row }) => <span className="num">{formatCount(row.original.publish_c2s)}</span>,
      },
      {
        id: 'received',
        meta: { align: 'right' },
        accessorFn: (c) => c.publish_s2c,
        header: counter(t('views.mqtt.clients.col.received')),
        size: 110,
        cell: ({ row }) => <span className="num">{formatCount(row.original.publish_s2c)}</span>,
      },
      {
        id: 'topics',
        meta: { align: 'right' },
        accessorFn: (c) => c.topics_published,
        header: counter(t('views.mqtt.clients.col.topics')),
        size: 90,
        cell: ({ row }) => <span className="num">{formatCount(row.original.topics_published)}</span>,
      },
      {
        id: 'last',
        accessorFn: (c) => c.last_ts_us,
        header: counter(t('views.mqtt.clients.col.lastSeen')),
        size: oneDay ? 130 : 170,
        cell: ({ row }) => <Timestamp us={row.original.last_ts_us} withDate={!oneDay} />,
      },
    ];
  }, [t, oneDay, ranged]);
  return (
    <Card
      title={t('views.mqtt.clients.title')}
      flush
      {...(query.data?.pages[0]?.total_estimate == null
        ? {}
        : { actions: <span className="num text-meta text-muted">{formatCount(query.data.pages[0].total_estimate)}</span> })}
      filters={
        <div role="search" className="flex min-w-0 flex-wrap items-center gap-2">
          <SearchInput value={search} onChange={setSearch} placeholder={t('views.mqtt.clients.search')} />
        </div>
      }
    >
      <PagedTable query={query}>
        {(items) => (
          <DataTable
            columns={columns}
            data={items}
            getRowId={(c) => c.key}
            ariaLabel={t('views.mqtt.clients.label')}
            cards
            maxHeight={560}
            emptyText={t('views.mqtt.clients.noMatch')}
            onRowClick={onSelect}
          />
        )}
      </PagedTable>
    </Card>
  );
}

/** Brokers: connections grouped by broker endpoint. */
export function BrokersTab({ sessionId, enabled, oneDay, ranged, onSelect }: TabProps & { onSelect: (b: MqttBrokerInfo) => void }) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const q = useDebounced(search.trim());
  const query = useMqttBrokers(sessionId, q === '' ? {} : { q }, enabled);
  const columns = useMemo<ColumnDef<MqttBrokerInfo>[]>(() => {
    const counter = (label: string) => wholeSessionHeader(label, ranged);
    return [
      {
        id: 'broker',
        meta: { card: 'title' },
        accessorFn: (b) => b.broker.ip,
        header: t('views.mqtt.brokers.col.broker'),
        size: 210,
        cell: ({ row }) => <Endpoint endpoint={row.original.broker} port={row.original.port} show="address" />,
      },
      {
        id: 'status',
        accessorFn: (b) => (b.public ? 2 : b.exposed ? 1 : 0),
        header: t('views.mqtt.brokers.col.status'),
        size: 100,
        cell: ({ row }) =>
          row.original.public ? (
            <Badge tone="warning">{t('views.mqtt.brokers.public')}</Badge>
          ) : row.original.exposed ? (
            <Badge tone="warning">{t('views.mqtt.brokers.exposed')}</Badge>
          ) : (
            <span className="text-muted">{t('views.mqtt.brokers.local')}</span>
          ),
      },
      {
        id: 'software',
        accessorFn: (b) => b.software ?? '',
        header: t('views.mqtt.brokers.col.software'),
        size: 180,
        cell: ({ row }) => {
          const s = row.original.software ?? '';
          return (
            <span data-testid="truncatable" title={s} className="block min-w-0 truncate">
              {s}
            </span>
          );
        },
      },
      {
        id: 'versions',
        accessorFn: (b) => b.versions.join(' '),
        header: t('views.mqtt.brokers.col.versions'),
        size: 110,
        cell: ({ row }) => <span className="font-mono text-muted">{row.original.versions.join(', ')}</span>,
      },
      {
        id: 'connections',
        meta: { align: 'right' },
        accessorFn: (b) => b.connections,
        header: counter(t('views.mqtt.brokers.col.connections')),
        size: 110,
        cell: ({ row }) => <span className="num">{formatCount(row.original.connections)}</span>,
      },
      {
        id: 'clients',
        meta: { align: 'right' },
        accessorFn: (b) => b.clients,
        header: counter(t('views.mqtt.brokers.col.clients')),
        size: 90,
        cell: ({ row }) => <span className="num">{formatCount(row.original.clients)}</span>,
      },
      {
        id: 'anonymous',
        meta: { align: 'right' },
        accessorFn: (b) => b.anonymous_accepted,
        header: counter(t('views.mqtt.brokers.col.anonymous')),
        size: 110,
        cell: ({ row }) => (
          <span className={row.original.anonymous_accepted > 0 ? 'num text-warning' : 'num'}>{formatCount(row.original.anonymous_accepted)}</span>
        ),
      },
      {
        id: 'rejected',
        meta: { align: 'right' },
        accessorFn: (b) => b.rejected,
        header: counter(t('views.mqtt.brokers.col.rejected')),
        size: 100,
        cell: ({ row }) => <span className="num">{formatCount(row.original.rejected)}</span>,
      },
      {
        id: 'messages',
        meta: { align: 'right' },
        accessorFn: (b) => b.messages,
        header: counter(t('views.mqtt.brokers.col.messages')),
        size: 110,
        cell: ({ row }) => <span className="num">{formatCount(row.original.messages)}</span>,
      },
      {
        id: 'last',
        accessorFn: (b) => b.last_ts_us,
        header: counter(t('views.mqtt.brokers.col.lastSeen')),
        size: oneDay ? 130 : 170,
        cell: ({ row }) => <Timestamp us={row.original.last_ts_us} withDate={!oneDay} />,
      },
    ];
  }, [t, oneDay, ranged]);
  return (
    <Card
      title={t('views.mqtt.brokers.title')}
      flush
      {...(query.data?.pages[0]?.total_estimate == null
        ? {}
        : { actions: <span className="num text-meta text-muted">{formatCount(query.data.pages[0].total_estimate)}</span> })}
      filters={
        <div role="search" className="flex min-w-0 flex-wrap items-center gap-2">
          <SearchInput value={search} onChange={setSearch} placeholder={t('views.mqtt.brokers.search')} />
        </div>
      }
    >
      <PagedTable query={query}>
        {(items) => (
          <DataTable
            columns={columns}
            data={items}
            getRowId={(b) => `${b.broker.ip} ${b.port} ${b.transport}`}
            ariaLabel={t('views.mqtt.brokers.label')}
            cards
            maxHeight={560}
            emptyText={t('views.mqtt.brokers.noMatch')}
            onRowClick={onSelect}
          />
        )}
      </PagedTable>
    </Card>
  );
}
