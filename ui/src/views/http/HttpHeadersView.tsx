import { getRouteApi, useRouterState } from '@tanstack/react-router';
import { ListTree } from 'lucide-react';
import { type ReactNode, useCallback, useId, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { type HttpHeaderListParams, METHOD_GROUPS } from '../../api/http';
import { useHttpHeaders, useHttpHeaderStats, useHttpTransaction } from '../../api/httpQueries';
import type { HttpTransactionSummary } from '../../api/types/HttpTransactionSummary';
import { Badge } from '../../components/Badge';
import { Card } from '../../components/Card';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';
import { FilterBar } from '../../components/FilterBar';
import { PageHeader } from '../../components/PageHeader';
import { Skeleton } from '../../components/Skeleton';
import { formatCount } from '../../lib/format';
import { ExpandableList } from './ExpandableList';
import { displayTarget } from './format';
import { useSessionGate } from './gate';
import { HeaderTable } from './HeaderTable';
import { RankedList } from './RankedList';
import { MethodBadge, MethodsChart, ServerCell, StatusBadge, TargetText } from './shared';
import { methodFilters, methodParam, useDebounced, useViewableSession } from './state';

const route = getRouteApi('/sessions/$sessionId');
/** Entries of the most used header names. */
const TOP_NAMES = 10;

/** `?name=` of the location (link from the HTTP view), when it is a non-empty string. */
function useInitialName(): string {
  const search = useRouterState({ select: (s) => s.location.search as Record<string, unknown> });
  const name = search.name;
  return typeof name === 'string' ? name : '';
}

/** HTTP headers of requests and responses: methods, filters, header search, expandable rows. */
export default function HttpHeadersView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const { session, viewable } = useViewableSession(sessionId);
  const stats = useHttpHeaderStats(sessionId, viewable);
  const initialName = useInitialName();

  const [disabled, setDisabled] = useState<ReadonlySet<string>>(new Set());
  const [search, setSearch] = useState('');
  const [name, setName] = useState(initialName);
  const q = useDebounced(search.trim());
  const headerName = useDebounced(name.trim());
  const params = useMemo<HttpHeaderListParams>(() => {
    const p: HttpHeaderListParams = {};
    const methods = methodParam(disabled);
    if (methods !== undefined) p.methods = methods;
    if (q !== '') p.q = q;
    if (headerName !== '') p.name = headerName;
    return p;
  }, [disabled, q, headerName]);
  const list = useHttpHeaders(sessionId, params, viewable);
  const gate = useSessionGate(session);
  const s = stats.data;
  const namesId = useId();

  let content: ReactNode;
  if (gate !== null) content = gate;
  else if (s !== undefined && s.transactions === 0)
    content = (
      <Card>
        <EmptyState icon={ListTree} title={t('views.http.noTransactions')} description={t('views.http.noTransactionsText')} />
      </Card>
    );
  else
    content = (
      <>
        <div className="grid items-start gap-4 lg:grid-cols-2">
          <MethodsChart
            counts={s?.methods}
            loading={stats.isPending}
            error={stats.isError}
            onRetry={() => {
              void stats.refetch();
            }}
          />
          <RankedList
            title={t('views.httpHeaders.topNames')}
            items={s === undefined ? (stats.isError ? [] : null) : s.names.slice(0, TOP_NAMES)}
            emptyText={t('views.http.noHeaders')}
            onSelect={setName}
            selectLabel={(k) => t('views.http.showHeader', { name: k })}
            footer={s === undefined ? undefined : t('views.http.headerLines', { count: s.header_count })}
          />
        </div>
        <Card title={t('views.httpHeaders.transactions')} flush>
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
              searchPlaceholder={t('views.httpHeaders.searchPlaceholder')}
            />
            <label className="flex min-w-0 flex-wrap items-center gap-2">
              <span className="text-muted">{t('views.httpHeaders.nameLabel')}</span>
              <input
                type="text"
                list={namesId}
                value={name}
                autoComplete="off"
                spellCheck={false}
                placeholder={t('views.httpHeaders.namePlaceholder')}
                onChange={(e) => {
                  setName(e.target.value);
                }}
                className="h-8 w-full min-w-0 rounded-md border border-line bg-surface px-2.5 text-body placeholder:text-faint sm:max-w-xs"
              />
              <datalist id={namesId}>
                {(s?.names ?? []).map((n) => (
                  <option key={n.key} value={n.key} />
                ))}
              </datalist>
            </label>
          </div>
          <HeaderList sessionId={sessionId} query={list} highlight={q} />
        </Card>
      </>
    );

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('nav.items.httpHeaders')}
        subtitle={session.data?.name ?? t('views.httpHeaders.subtitle')}
        {...(s === undefined ? {} : { count: <Badge>{formatCount(s.header_count)}</Badge> })}
      />
      {content}
    </div>
  );
}

function Row({ tx }: { tx: HttpTransactionSummary }) {
  return (
    <span className="flex min-w-0 flex-col gap-1 md:flex-row md:items-center md:gap-3">
      <span className="flex min-w-0 flex-1 items-center gap-2">
        <span className="shrink-0">
          <MethodBadge method={tx.method} />
        </span>
        <span className="min-w-0 flex-1">
          <TargetText tx={tx} />
        </span>
      </span>
      <span className="flex min-w-0 items-center gap-2 md:w-[45%] md:shrink-0">
        <span className="min-w-0 flex-1">
          <ServerCell tx={tx} />
        </span>
        <span className="shrink-0">
          <StatusBadge status={tx.status} />
        </span>
      </span>
    </span>
  );
}

/** Both header tables of a transaction, side by side from 1024 px. */
function HeadersDetail({ sessionId, id, highlight }: { sessionId: string; id: number; highlight: string }) {
  const { t } = useTranslation();
  const query = useHttpTransaction(sessionId, id, true);
  if (query.isPending) return <Skeleton height={120} />;
  if (query.isError)
    return (
      <ErrorState
        message={t('views.http.detailError')}
        onRetry={() => {
          void query.refetch();
        }}
      />
    );
  const d = query.data;
  return (
    <div className="grid min-w-0 grid-cols-1 gap-4 lg:grid-cols-2">
      <section className="flex min-w-0 flex-col gap-2">
        <h4 className="text-meta font-medium text-muted uppercase">{t('views.http.detail.request')}</h4>
        {d.request === null ? (
          <p className="text-muted">{t('views.http.detail.noRequest')}</p>
        ) : (
          <HeaderTable headers={d.request.headers} label={t('views.http.detail.requestHeaders')} highlight={highlight} />
        )}
      </section>
      <section className="flex min-w-0 flex-col gap-2">
        <h4 className="text-meta font-medium text-muted uppercase">{t('views.http.detail.response')}</h4>
        {d.response === null ? (
          <p className="text-muted">{t('views.http.detail.noResponse')}</p>
        ) : (
          <HeaderTable headers={d.response.headers} label={t('views.http.detail.responseHeaders')} highlight={highlight} />
        )}
      </section>
    </div>
  );
}

type ListQuery = ReturnType<typeof useHttpHeaders>;

function HeaderList({ sessionId, query, highlight }: { sessionId: string; query: ListQuery; highlight: string }) {
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
        ariaLabel={t('views.httpHeaders.listLabel')}
        renderRow={(tx) => <Row tx={tx} />}
        renderDetail={(tx) => <HeadersDetail sessionId={sessionId} id={tx.id} highlight={highlight} />}
        rowLabel={(tx) =>
          t('views.http.rowLabel', { method: tx.method ?? '-', target: displayTarget(tx), status: tx.status ?? '-' })
        }
        hasMore={query.hasNextPage}
        loadingMore={query.isFetchingNextPage}
        onLoadMore={loadMore}
      />
    </>
  );
}
