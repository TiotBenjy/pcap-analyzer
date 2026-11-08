import { getRouteApi } from '@tanstack/react-router';
import { DoorOpen } from 'lucide-react';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useOpenPorts, useOpenPortStats } from '../../api/connectionQueries';
import { useSession } from '../../api/sessionQueries';
import type { AddressCategory } from '../../api/types/AddressCategory';
import type { HostOpenPorts } from '../../api/types/HostOpenPorts';
import type { OpenPortInfo } from '../../api/types/OpenPortInfo';
import { CHART_HEIGHT } from '../../charts/sizes';
import { Badge } from '../../components/Badge';
import { Card } from '../../components/Card';
import { Chart } from '../../components/Chart';
import { Endpoint } from '../../components/Endpoint';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';
import { FilterBar } from '../../components/FilterBar';
import { PageHeader } from '../../components/PageHeader';
import { Skeleton } from '../../components/Skeleton';
import { formatCount, formatTimestamp } from '../../lib/format';
import { useMediaQuery } from '../../lib/useMediaQuery';
import { LoadMore } from '../connections/LoadMore';
import { isViewable } from '../connections/session';
import { SessionGate } from '../connections/SessionGate';
import { useDebounced } from '../connections/useDebounced';
import { categoriesOf } from './categories';
import { buildPortsOption } from './portsChart';
import { portLabel, serviceMismatch, serviceName } from './services';

const route = getRouteApi('/sessions/$sessionId');

const MD_QUERY = '(min-width: 768px)';

/** Open ports: services seen answering, most exposed ports and hosts with their ports. */
export default function OpenPortsView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const session = useSession(sessionId);
  const viewable = isViewable(session.data);
  const [showPrivate, setShowPrivate] = useState(true);
  const [showPublic, setShowPublic] = useState(true);
  const [showNames, setShowNames] = useState(true);
  const [search, setSearch] = useState('');
  const q = useDebounced(search);
  const categories = useMemo(() => categoriesOf(showPrivate, showPublic), [showPrivate, showPublic]);
  const filters = useMemo(() => ({ ...(categories === undefined ? {} : { categories }), q }), [categories, q]);
  const hosts = useOpenPorts(sessionId, filters, viewable);
  const total = hosts.data?.pages[0]?.total_estimate ?? null;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('nav.items.openPorts')}
        subtitle={session.data?.name ?? t('views.openPorts.subtitle')}
        {...(total === null ? {} : { count: <Badge>{formatCount(total)}</Badge> })}
      />
      <SessionGate session={session}>
        <FilterBar
          filters={[
            { id: 'private', label: t('views.openPorts.filters.private'), active: showPrivate },
            { id: 'public', label: t('views.openPorts.filters.public'), active: showPublic },
            { id: 'names', label: t('views.openPorts.filters.names'), active: showNames },
          ]}
          onToggle={(id, active) => {
            if (id === 'private') setShowPrivate(active);
            else if (id === 'public') setShowPublic(active);
            else setShowNames(active);
          }}
          search={search}
          onSearch={setSearch}
          searchPlaceholder={t('views.openPorts.filters.search')}
        />
        <PortsChartCard sessionId={sessionId} categories={categories} enabled={viewable} />
        <Card title={t('views.openPorts.table.title')} flush>
          {hosts.isError ? (
            <ErrorState
              message={t('views.openPorts.table.loadError')}
              onRetry={() => {
                void hosts.refetch();
              }}
            />
          ) : hosts.data === undefined ? (
            <div className="p-3 sm:p-4">
              <Skeleton height={160} />
            </div>
          ) : (
            <>
              <HostList
                hosts={hosts.data.pages.flatMap((p) => p.items)}
                showNames={showNames}
                filtered={search.trim() !== '' || categories !== undefined}
              />
              <LoadMore
                shown={hosts.data.pages.reduce((n, p) => n + p.items.length, 0)}
                total={total}
                hasMore={hosts.hasNextPage}
                loading={hosts.isFetchingNextPage}
                onMore={() => {
                  void hosts.fetchNextPage();
                }}
              />
            </>
          )}
        </Card>
      </SessionGate>
    </div>
  );
}

function PortsChartCard({
  sessionId,
  categories,
  enabled,
}: {
  sessionId: string;
  categories: readonly AddressCategory[] | undefined;
  enabled: boolean;
}) {
  const { t } = useTranslation();
  const stats = useOpenPortStats(sessionId, categories, enabled);
  const data = stats.data;
  const option = useMemo(
    () => (data === undefined ? {} : buildPortsOption(data, { hosts: (n) => t('views.openPorts.chart.hosts', { count: n }) })),
    [data, t],
  );
  const others = data === undefined ? 0 : Math.max(0, Number(data.distinct_ports) - data.top.length);
  return (
    <Card title={t('views.openPorts.chart.title')}>
      <Chart
        option={option}
        height={CHART_HEIGHT.bars(data?.top.length ?? 5)}
        ariaLabel={t('views.openPorts.chart.label')}
        loading={!enabled || stats.isPending}
        error={stats.isError ? t('views.openPorts.chart.loadError') : null}
        onRetry={() => {
          void stats.refetch();
        }}
        empty={data !== undefined && data.top.length === 0}
        emptyText={t('views.openPorts.chart.empty')}
      />
      {others > 0 && <p className="mt-2 text-meta text-muted">{t('views.openPorts.chart.others', { count: others })}</p>}
    </Card>
  );
}

function PortBadge({ port }: { port: OpenPortInfo }) {
  const { t } = useTranslation();
  const name = serviceName(port);
  const mismatch = serviceMismatch(port.detected, port.service);
  const title = [
    `${port.port}/${port.transport}`,
    port.service === null ? t('views.openPorts.table.noIana') : t('views.openPorts.table.iana', { name: port.service }),
    ...(port.detected === null ? [] : [t('views.openPorts.table.detected', { name: port.detected })]),
    ...(mismatch ? [t('views.openPorts.table.mismatch')] : []),
    t('views.openPorts.table.clients', { count: port.clients }),
    t(`views.openPorts.table.evidence.${port.evidence}`),
    t('views.openPorts.table.seen', { first: formatTimestamp(port.first_ts_us), last: formatTimestamp(port.last_ts_us) }),
  ].join('\n');
  return (
    <Badge tone={mismatch ? 'warning' : 'neutral'} title={title} className="font-mono">
      {name === null ? portLabel(port) : `${portLabel(port)} ${name}`}
    </Badge>
  );
}

function Ports({ host }: { host: HostOpenPorts }) {
  return (
    <div className="flex min-w-0 flex-wrap gap-1">
      {host.ports.map((p) => (
        <PortBadge key={`${p.transport}/${p.port}`} port={p} />
      ))}
    </div>
  );
}

function Banners({ host }: { host: HostOpenPorts }) {
  const { t } = useTranslation();
  const banners = host.ports.filter((p) => p.banner !== null);
  const [first, ...rest] = banners;
  if (first === undefined) return <span className="text-muted">{t('views.openPorts.table.noBanner')}</span>;
  const line = (p: OpenPortInfo) => (
    <span data-testid="truncatable" title={`${portLabel(p)}: ${p.banner ?? ''}`} className="block truncate font-mono text-meta">
      {p.banner}
    </span>
  );
  if (rest.length === 0) return line(first);
  return (
    <details className="min-w-0">
      <summary className="flex min-w-0 cursor-pointer items-center gap-2">
        <span className="min-w-0 flex-1">{line(first)}</span>
        <span className="shrink-0 text-meta text-muted">{t('views.openPorts.table.moreBanners', { count: rest.length })}</span>
      </summary>
      <div className="mt-1 flex flex-col gap-0.5">{rest.map((p) => <div key={`${p.transport}/${p.port}`}>{line(p)}</div>)}</div>
    </details>
  );
}

function HostList({ hosts, showNames, filtered }: { hosts: HostOpenPorts[]; showNames: boolean; filtered: boolean }) {
  const { t } = useTranslation();
  const wide = useMediaQuery(MD_QUERY);
  if (hosts.length === 0) {
    return (
      <EmptyState
        icon={DoorOpen}
        title={filtered ? t('views.openPorts.table.noMatch') : t('views.openPorts.table.empty')}
      />
    );
  }
  if (!wide) {
    return (
      <ul aria-label={t('views.openPorts.table.label')} className="divide-y divide-line">
        {hosts.map((h) => (
          <li key={h.host.ip} className="flex min-w-0 flex-col gap-2 px-3 py-2.5">
            <div className="flex min-w-0 items-center justify-between gap-2">
              <Endpoint endpoint={h.host} showName={showNames} />
              <span className="num shrink-0 text-meta text-muted">
                {t('views.openPorts.table.clients', { count: h.clients })}
              </span>
            </div>
            <Ports host={h} />
            <Banners host={h} />
          </li>
        ))}
      </ul>
    );
  }
  return (
    <div className="min-w-0 overflow-x-auto">
      <table aria-label={t('views.openPorts.table.label')} className="w-full table-fixed border-collapse text-table">
        <thead>
          <tr className="border-b border-line text-left text-meta text-muted">
            <th scope="col" className="w-[28%] px-3 py-2 font-medium sm:px-4">{t('views.openPorts.table.host')}</th>
            <th scope="col" className="px-3 py-2 font-medium">{t('views.openPorts.table.ports')}</th>
            <th scope="col" className="w-24 px-3 py-2 text-right font-medium">{t('views.openPorts.table.clients')}</th>
            <th scope="col" className="w-[26%] px-3 py-2 font-medium sm:pr-4">{t('views.openPorts.table.banner')}</th>
          </tr>
        </thead>
        <tbody>
          {hosts.map((h) => (
            <tr key={h.host.ip} className="border-b border-line align-top last:border-b-0">
              <td className="px-3 py-2 sm:px-4">
                <Endpoint endpoint={h.host} showName={showNames} />
              </td>
              <td className="px-3 py-2">
                <Ports host={h} />
              </td>
              <td className="num px-3 py-2 text-right">{formatCount(h.clients)}</td>
              <td className="min-w-0 px-3 py-2 sm:pr-4">
                <Banners host={h} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
