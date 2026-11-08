import { getRouteApi, Link } from '@tanstack/react-router';
import { CircleAlert, Hourglass } from 'lucide-react';
import { type ReactNode, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { DNS_PROTOCOLS, type DnsFilter } from '../../api/dns';
import { useDnsStats } from '../../api/dnsQueries';
import { useSession } from '../../api/sessionQueries';
import type { DnsProtocol } from '../../api/types/DnsProtocol';
import type { DnsStats } from '../../api/types/DnsStats';
import { Badge } from '../../components/Badge';
import { Card } from '../../components/Card';
import { Chart } from '../../components/Chart';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';
import { FilterBar, type FilterOption } from '../../components/FilterBar';
import { PageHeader } from '../../components/PageHeader';
import { formatCount } from '../../lib/format';
import { CountryList } from './CountryList';
import { barsHeight, barsOption, type ChartEntry, DONUT_CENTER_Y, donutOption, withOther } from './dnsCharts';
import { formatLatency, protocolColor, protocolLabel, rcodeLabel } from './dnsFormat';
import { PairsList } from './PairsList';
import { ServerMap } from './ServerMap';

const route = getRouteApi('/sessions/$sessionId');

/** Delay before the search text is sent to the server. */
const SEARCH_DELAY_MS = 250;
const ERRORS = 'errors';
const DONUT_HEIGHT = 240;

/** DNS, mDNS, NBNS and LLMNR: charts, server map, filters, client/server pairs (`docs/specs/dns.md`). */
export default function DnsView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const session = useSession(sessionId);
  const state = session.data?.state;
  const viewable = state === 'ready' || state === 'incomplete';
  const stats = useDnsStats(sessionId, viewable);

  const [hidden, setHidden] = useState<ReadonlySet<DnsProtocol>>(new Set());
  const [errorsOnly, setErrorsOnly] = useState(false);
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  useEffect(() => {
    const timer = setTimeout(() => {
      setQuery(search.trim());
    }, SEARCH_DELAY_MS);
    return () => {
      clearTimeout(timer);
    };
  }, [search]);

  const filter = useMemo<DnsFilter>(
    () => ({
      protocols: DNS_PROTOCOLS.filter((p) => !hidden.has(p)),
      errors: errorsOnly,
      q: query,
    }),
    [hidden, errorsOnly, query],
  );

  let content: ReactNode;
  if (session.isError) {
    content = (
      <Card>
        <ErrorState
          message={t('views.dns.loadError')}
          onRetry={() => {
            void session.refetch();
          }}
        />
      </Card>
    );
  } else if (state === 'importing') {
    content = (
      <Card>
        <EmptyState
          icon={Hourglass}
          title={t('views.dns.importingTitle')}
          description={t('views.dns.importingText')}
          action={<CapturesLink />}
        />
      </Card>
    );
  } else if (state === 'failed') {
    content = (
      <Card>
        <EmptyState
          icon={CircleAlert}
          title={t('views.dns.failedTitle')}
          description={session.data?.state_detail ?? t('views.dns.failedText')}
          action={<CapturesLink />}
        />
      </Card>
    );
  } else {
    const s = stats.data;
    const count = (p: DnsProtocol) => s?.protocols.find((c) => c.protocol === p)?.count ?? 0;
    const filters: FilterOption[] = [
      ...DNS_PROTOCOLS.map((p) => ({
        id: p,
        label: protocolLabel(t, p),
        active: !hidden.has(p),
        ...(s === undefined ? {} : { count: count(p) }),
      })),
      { id: ERRORS, label: t('views.dns.filters.errors'), active: errorsOnly, ...(s === undefined ? {} : { count: s.errors }) },
    ];
    content = (
      <>
        <ChartsRow stats={stats.data ?? null} loading={stats.isPending && viewable} error={stats.isError} onRetry={() => void stats.refetch()} />
        <ServerMap sessionId={sessionId} enabled={viewable} />
        <Card title={t('views.dns.table.title')} flush>
          <div className="border-b border-line p-3 sm:px-4">
            <FilterBar
              filters={filters}
              onToggle={(id, active) => {
                if (id === ERRORS) {
                  setErrorsOnly(active);
                  return;
                }
                setHidden((prev) => {
                  const next = new Set(prev);
                  if (active) next.delete(id as DnsProtocol);
                  else next.add(id as DnsProtocol);
                  return next;
                });
              }}
              onSetAll={(active) => {
                setHidden(active ? new Set() : new Set(DNS_PROTOCOLS));
              }}
              search={search}
              onSearch={setSearch}
              searchPlaceholder={t('views.dns.filters.search')}
            />
          </div>
          <PairsList sessionId={sessionId} filter={filter} enabled={viewable} hasTraffic={s === undefined ? null : s.total > 0} />
        </Card>
      </>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('nav.items.dns')}
        subtitle={session.data?.name ?? t('views.dns.subtitle')}
        {...(stats.data === undefined ? {} : { count: <Badge>{formatCount(stats.data.total)}</Badge> })}
      />
      {content}
    </div>
  );
}

function CapturesLink() {
  const { t } = useTranslation();
  return (
    <Link to="/captures" className="text-accent hover:underline">
      {t('views.overview.followImport')}
    </Link>
  );
}

interface ChartsRowProps {
  stats: DnsStats | null;
  loading: boolean;
  error: boolean;
  onRetry: () => void;
}

/** Protocols, results, query types and server countries. */
function ChartsRow({ stats, loading, error, onRetry }: ChartsRowProps) {
  const { t } = useTranslation();
  const errorText = error ? t('views.dns.loadError') : null;
  const empty = stats !== null && stats.total === 0;

  const options = useMemo(() => {
    const protocols: ChartEntry[] = (stats?.protocols ?? []).map((p) => ({
      key: p.protocol,
      label: protocolLabel(t, p.protocol),
      value: p.count,
      color: protocolColor(p.protocol),
    }));
    const rcodes = withOther(
      (stats?.rcodes ?? []).map((r) => ({ key: r.key ?? '__none', label: rcodeLabel(t, r.key), value: r.count })),
      stats?.rcode_other ?? 0,
      t('common.other'),
    );
    const qtypes = withOther(
      (stats?.qtypes ?? []).map((q) => ({ key: q.key ?? '', label: q.key ?? '', value: q.count })),
      stats?.qtype_other ?? 0,
      t('common.other'),
    );
    return {
      protocols: donutOption(protocols, formatCount),
      rcodes: barsOption(rcodes, formatCount),
      rcodeCount: rcodes.length,
      qtypes: barsOption(qtypes, formatCount),
      qtypeCount: qtypes.length,
    };
  }, [stats, t]);
  const latency =
    stats !== null && stats.latency_p50_us !== null && stats.latency_p95_us !== null
      ? t('views.dns.charts.latency', {
          p50: formatLatency(stats.latency_p50_us),
          p95: formatLatency(stats.latency_p95_us),
        })
      : null;

  const common = { loading, error: errorText, onRetry, empty, emptyText: t('views.dns.table.empty') };
  return (
    <div
      className="grid gap-4 [grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr))]"
      data-testid="dns-charts"
    >
      <Card title={t('views.dns.charts.protocols')}>
        <div className="relative">
          <Chart
            {...common}
            option={options.protocols}
            height={DONUT_HEIGHT}
            ariaLabel={t('views.dns.charts.protocolsLabel')}
          />
          {stats !== null && !empty && !loading && !error && (
            <span
              aria-hidden
              data-testid="donut-total"
              className="num pointer-events-none absolute left-1/2 -translate-x-1/2 -translate-y-1/2 text-card font-semibold"
              style={{ top: `${DONUT_CENTER_Y}%` }}
            >
              {formatCount(stats.total)}
            </span>
          )}
        </div>
      </Card>
      <Card title={t('views.dns.charts.results')}>
        <Chart
          {...common}
          option={options.rcodes}
          height={barsHeight(options.rcodeCount)}
          ariaLabel={t('views.dns.charts.resultsLabel')}
        />
        {latency !== null && (
          <p className="mt-2 text-meta text-muted">{latency}</p>
        )}
      </Card>
      <Card title={t('views.dns.charts.qtypes')}>
        <Chart
          {...common}
          option={options.qtypes}
          height={barsHeight(options.qtypeCount)}
          ariaLabel={t('views.dns.charts.qtypesLabel')}
          empty={empty || (stats !== null && options.qtypeCount === 0)}
        />
      </Card>
      <Card title={t('views.dns.charts.countries')}>
        <CountryList stats={stats} loading={loading} error={errorText} onRetry={onRetry} />
      </Card>
    </div>
  );
}
