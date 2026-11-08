import { getRouteApi, useNavigate } from '@tanstack/react-router';
import { ArrowLeftRight } from 'lucide-react';
import { type ReactNode, useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { type HttpListParams, type HttpSort, METHOD_GROUPS } from '../../api/http';
import { useHttpStats, useHttpTransactions } from '../../api/httpQueries';
import type { HttpTransactionSummary } from '../../api/types/HttpTransactionSummary';
import type { ChartEvents } from '../../charts/EChartsRenderer';
import { Badge } from '../../components/Badge';
import { Card } from '../../components/Card';
import { Chart } from '../../components/Chart';
import { Endpoint } from '../../components/Endpoint';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';
import { FilterBar } from '../../components/FilterBar';
import { PageHeader } from '../../components/PageHeader';
import { SegmentedControl } from '../../components/SegmentedControl';
import { Skeleton } from '../../components/Skeleton';
import { formatBytes, formatCount, formatTimestamp } from '../../lib/format';
import { barColor, barsHeight, barsOption, type ChartFormat, PART_HEIGHT, statusOption } from './charts';
import { ExpandableList } from './ExpandableList';
import { displayTarget } from './format';
import { RankedList } from './RankedList';
import { useSessionGate } from './gate';
import { FilterChip, MethodBadge, MethodsChart, ServerCell, StatusBadge, TargetText } from './shared';
import { methodFilters, methodParam, useDebounced, useViewableSession } from './state';
import { TransactionDetail } from './TransactionDetail';

const route = getRouteApi('/sessions/$sessionId');

/** Column layout of the transaction rows (wide screens), shared by the header and the rows. */
export const ROW_GRID =
  'md:grid md:grid-cols-[64px_minmax(9.5rem,1fr)_minmax(0,1.7fr)_64px_minmax(0,1.6fr)_44px_64px] md:items-center md:gap-3 ' +
  'xl:grid-cols-[72px_minmax(10rem,1fr)_minmax(0,1.8fr)_72px_minmax(0,1.6fr)_48px_72px_minmax(0,0.9fr)]';

/** HTTP transactions: methods, statuses and content types, tops, filters and the list. */
export default function HttpView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const { session, viewable, oneDay } = useViewableSession(sessionId);
  const stats = useHttpStats(sessionId, viewable);
  const navigate = useNavigate();

  const [disabled, setDisabled] = useState<ReadonlySet<string>>(new Set());
  const [search, setSearch] = useState('');
  const q = useDebounced(search.trim());
  const [host, setHost] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [sort, setSort] = useState<HttpSort>('time');

  const params = useMemo<HttpListParams>(() => {
    const p: HttpListParams = { sort, order: sort === 'status' ? 'asc' : 'desc' };
    const methods = methodParam(disabled);
    if (methods !== undefined) p.methods = methods;
    if (status !== null) p.statuses = [status];
    if (host !== null) p.host = host;
    if (q !== '') p.q = q;
    return p;
  }, [disabled, status, host, q, sort]);
  const list = useHttpTransactions(sessionId, params, viewable);

  const gate = useSessionGate(session);
  const s = stats.data;
  const fmt = useMemo<ChartFormat>(
    () => ({ count: formatCount, label: (k) => (k === '' ? '-' : k === 'other' ? t('common.other') : k) }),
    [t],
  );

  let content: ReactNode;
  if (gate !== null) content = gate;
  else if (s !== undefined && s.transactions === 0)
    content = (
      <Card>
        <EmptyState icon={ArrowLeftRight} title={t('views.http.noTransactions')} description={t('views.http.noTransactionsText')} />
      </Card>
    );
  else
    content = (
      <>
        <div className="grid gap-4 [grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr))]">
          <MethodsChart
            counts={s?.methods}
            loading={stats.isPending}
            error={stats.isError}
            onRetry={() => {
              void stats.refetch();
            }}
          />
          <StatusChart stats={s} loading={stats.isPending} error={stats.isError} onSelect={setStatus} fmt={fmt} />
          <ContentTypesChart stats={s} loading={stats.isPending} error={stats.isError} fmt={fmt} />
        </div>
        <div className="grid items-start gap-4 [grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr))]">
          <RankedList
            title={t('views.http.topHosts')}
            items={s?.hosts ?? (stats.isError ? [] : null)}
            emptyText={t('views.http.noHosts')}
            onSelect={setHost}
            selectLabel={(k) => t('views.http.filterHost', { host: k })}
            footer={s === undefined ? undefined : t('views.http.distinctHosts', { count: s.host_count })}
          />
          <RankedList
            title={t('views.http.topUserAgents')}
            items={s?.user_agents ?? (stats.isError ? [] : null)}
            emptyText={t('views.http.noUserAgents')}
            onSelect={(k) => {
              setSearch(k);
            }}
            selectLabel={(k) => t('views.http.searchFor', { text: k })}
            footer={s === undefined ? undefined : t('views.http.distinctUserAgents', { count: s.user_agent_count })}
          />
          <RankedList
            title={t('views.http.rareHeaders')}
            items={s?.rare_headers ?? (stats.isError ? [] : null)}
            emptyText={t('views.http.noHeaders')}
            onSelect={(name) => {
              void navigate({ href: `/sessions/${encodeURIComponent(sessionId)}/http-headers?name=${encodeURIComponent(name)}` });
            }}
            selectLabel={(k) => t('views.http.showHeader', { name: k })}
            footer={s === undefined ? undefined : t('views.http.headerLines', { count: s.header_count })}
          />
        </div>
        <Card
          title={t('views.http.transactions')}
          flush
          actions={
            <SegmentedControl
              hideLabel
              label={t('views.http.sortLabel')}
              value={sort}
              options={[
                { value: 'time', label: t('views.http.sort.time') },
                { value: 'size', label: t('views.http.sort.size') },
                { value: 'status', label: t('views.http.sort.status') },
              ]}
              onChange={setSort}
            />
          }
        >
          <div className="flex flex-col gap-2 border-b border-line p-3 sm:p-4">
            <FilterBar
              filters={methodFilters(s?.methods, disabled, t('views.http.otherMethods'))}
              onToggle={(id, active) => {
                setDisabled((prev) => {
                  const next = new Set(prev);
                  if (active) next.delete(id);
                  else next.add(id);
                  return next;
                });
              }}
              onSetAll={(active) => {
                setDisabled(active ? new Set() : new Set(METHOD_GROUPS));
              }}
              search={search}
              onSearch={setSearch}
              searchPlaceholder={t('views.http.searchPlaceholder')}
            />
            {(host !== null || status !== null) && (
              <div className="flex flex-wrap gap-2">
                {host !== null && (
                  <FilterChip
                    label={t('views.http.hostChip', { host })}
                    removeLabel={t('views.http.removeFilter', { label: host })}
                    onRemove={() => {
                      setHost(null);
                    }}
                  />
                )}
                {status !== null && (
                  <FilterChip
                    label={t('views.http.statusChip', { status })}
                    removeLabel={t('views.http.removeFilter', { label: status })}
                    onRemove={() => {
                      setStatus(null);
                    }}
                  />
                )}
              </div>
            )}
          </div>
          <TransactionList sessionId={sessionId} query={list} oneDay={oneDay} />
        </Card>
      </>
    );

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('nav.items.http')}
        subtitle={session.data?.name ?? t('views.http.subtitle')}
        {...(s === undefined ? {} : { count: <Badge>{formatCount(s.transactions)}</Badge> })}
      />
      {content}
    </div>
  );
}

interface ChartCardProps {
  stats: ReturnType<typeof useHttpStats>['data'];
  loading: boolean;
  error: boolean;
  fmt: ChartFormat;
}

function StatusChart({ stats, loading, error, fmt, onSelect }: ChartCardProps & { onSelect: (status: string) => void }) {
  const { t } = useTranslation();
  const statuses = useMemo(() => stats?.statuses ?? [], [stats]);
  const option = useMemo(() => statusOption(statuses, fmt), [statuses, fmt]);
  const events = useMemo<ChartEvents>(
    () => ({
      click: (p) => {
        const name = (p as { name?: unknown }).name;
        if (typeof name === 'string') onSelect(name);
      },
    }),
    [onSelect],
  );
  return (
    <Card title={t('views.http.statuses')}>
      <Chart
        option={option}
        height={PART_HEIGHT}
        ariaLabel={t('views.http.statusesLabel')}
        loading={loading}
        error={error ? t('views.http.loadError') : null}
        empty={!loading && !error && statuses.length === 0}
        emptyText={t('views.http.noResponses')}
        onEvents={events}
      />
    </Card>
  );
}

function ContentTypesChart({ stats, loading, error, fmt }: ChartCardProps) {
  const { t } = useTranslation();
  const items = useMemo(() => {
    const top = stats?.content_types ?? [];
    const other = stats?.content_types_other ?? 0;
    return other > 0 ? [...top, { key: 'other', count: other }] : top;
  }, [stats]);
  const option = useMemo(() => barsOption(items, barColor, fmt), [items, fmt]);
  return (
    <Card title={t('views.http.contentTypes')}>
      <Chart
        option={option}
        height={barsHeight(items.length)}
        ariaLabel={t('views.http.contentTypesLabel')}
        loading={loading}
        error={error ? t('views.http.loadError') : null}
        empty={!loading && !error && items.length === 0}
        emptyText={t('views.http.noContentTypes')}
      />
    </Card>
  );
}

function ListHeader() {
  const { t } = useTranslation();
  return (
    <div aria-hidden className="hidden border-b border-line py-2 pr-3 pl-9 text-meta font-medium text-muted md:block">
      <div className={ROW_GRID}>
        <span>{t('views.http.col.time')}</span>
        <span>{t('views.http.col.client')}</span>
        <span>{t('views.http.col.server')}</span>
        <span>{t('views.http.col.method')}</span>
        <span>{t('views.http.col.path')}</span>
        <span>{t('views.http.col.status')}</span>
        <span className="text-right">{t('views.http.col.size')}</span>
        <span className="hidden xl:block">{t('views.http.col.type')}</span>
      </div>
    </div>
  );
}

function Row({ tx, oneDay }: { tx: HttpTransactionSummary; oneDay: boolean }) {
  const { i18n } = useTranslation();
  const size = formatBytes(tx.response_size, i18n.language);
  return (
    <span className={`flex min-w-0 flex-col gap-1 ${ROW_GRID}`}>
      <span className="num hidden text-meta text-muted md:block">{formatTimestamp(tx.ts_us, !oneDay)}</span>
      <span className="hidden min-w-0 md:block">
        <Endpoint endpoint={tx.client} port={tx.client_port} showName={false} className="text-meta" />
      </span>
      <span className="hidden min-w-0 md:block">
        <ServerCell tx={tx} />
      </span>
      {/* Narrow screens: method and target, then endpoints, status and size. */}
      <span className="flex min-w-0 items-center gap-2 md:contents">
        <span className="shrink-0 md:block">
          <MethodBadge method={tx.method} />
        </span>
        <span className="min-w-0 flex-1 md:block">
          <TargetText tx={tx} />
        </span>
      </span>
      <span className="flex min-w-0 items-center gap-2 md:contents">
        <span className="min-w-0 flex-1 md:hidden">
          <ServerCell tx={tx} />
        </span>
        <span className="shrink-0 md:block">
          <StatusBadge status={tx.status} />
        </span>
        <span className="num shrink-0 text-right text-meta text-muted md:block">{size}</span>
      </span>
      <span
        data-testid="truncatable"
        title={tx.content_type ?? ''}
        className="hidden min-w-0 truncate text-meta text-muted xl:block"
      >
        {tx.content_type ?? '-'}
      </span>
    </span>
  );
}

type ListQuery = ReturnType<typeof useHttpTransactions>;

/** Transaction rows, expanded in place (request, response, bodies, connection). */
export function TransactionList({ sessionId, query, oneDay }: { sessionId: string; query: ListQuery; oneDay: boolean }) {
  const { t } = useTranslation();
  const items = useMemo(() => query.data?.pages.flatMap((p) => p.items) ?? [], [query.data]);
  const total = query.data?.pages[0]?.total_estimate ?? null;
  const loadMore = useCallback(() => {
    void query.fetchNextPage();
  }, [query]);
  if (query.isPending)
    return (
      <div className="flex flex-col gap-2 p-3 sm:p-4" aria-busy="true">
        <span className="sr-only">{t('common.loading')}</span>
        {[0, 1, 2, 3, 4].map((i) => (
          <Skeleton key={i} height={32} />
        ))}
      </div>
    );
  if (query.isError)
    return (
      <ErrorState
        message={t('views.http.loadError')}
        onRetry={() => {
          void query.refetch();
        }}
      />
    );
  if (items.length === 0) return <EmptyState title={t('views.http.noMatch')} />;
  return (
    <>
      {total !== null && (
        <p className="border-b border-line px-3 py-1.5 text-meta text-muted sm:px-4" data-testid="http-row-count">
          {t('common.rows', { count: total })}
        </p>
      )}
      <ExpandableList
        items={items}
        getKey={(tx) => tx.id}
        ariaLabel={t('views.http.listLabel')}
        header={<ListHeader />}
        renderRow={(tx) => <Row tx={tx} oneDay={oneDay} />}
        renderDetail={(tx) => <TransactionDetail sessionId={sessionId} id={tx.id} />}
        rowLabel={(tx) =>
          t('views.http.rowLabel', {
            method: tx.method ?? '-',
            target: displayTarget(tx),
            status: tx.status ?? '-',
          })
        }
        hasMore={query.hasNextPage}
        loadingMore={query.isFetchingNextPage}
        onLoadMore={loadMore}
      />
    </>
  );
}
