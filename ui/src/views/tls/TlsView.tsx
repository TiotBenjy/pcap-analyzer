import { getRouteApi } from '@tanstack/react-router';
import type { ColumnDef } from '@tanstack/react-table';
import { CircleAlert, FileKey, Hourglass, Lock, ShieldAlert, ShieldOff, TriangleAlert } from 'lucide-react';
import { type ReactNode, useDeferredValue, useId, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useSession } from '../../api/sessionQueries';
import type { TlsSessionFilters } from '../../api/tls';
import { useTlsSessions, useTlsStats } from '../../api/tlsQueries';
import type { TlsSessionItem } from '../../api/types/TlsSessionItem';
import type { TlsStats } from '../../api/types/TlsStats';
import type { ChartEvents } from '../../charts/EChartsRenderer';
import { CHART_HEIGHT } from '../../charts/sizes';
import { Badge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { Chart } from '../../components/Chart';
import { DataTable } from '../../components/DataTable';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';
import { FilterBar } from '../../components/FilterBar';
import { PageHeader } from '../../components/PageHeader';
import { SegmentedControl } from '../../components/SegmentedControl';
import { Skeleton } from '../../components/Skeleton';
import { StatCard } from '../../components/StatCard';
import { OTHER_COLOR } from '../../charts/palette';
import { formatCount, formatTimestamp, sameLocalDay } from '../../lib/format';
import { useMediaQuery } from '../../lib/useMediaQuery';
import { useTheme } from '../../theme/theme';
import { CertificatesPanel } from './CertificatesPanel';
import { IssueBadges, MonoValue, SuiteName } from './parts';
import { SessionDetail } from './SessionDetail';
import {
  buildMatrixOption,
  buildSuitesOption,
  buildVersionsOption,
  matrixHeight,
  matrixVersions,
  suiteOfRow,
  type TlsChartFormat,
  versionOfPie,
} from './tlsCharts';
import { isWeakness, suiteLabel, versionLabel, versionTone } from './tlsFormat';

const route = getRouteApi('/sessions/$sessionId');

/** Value of the "all versions" segment. */
const ANY = 'any';
/** From this width every column of the sessions table fits; below, secondary ones are hidden. */
const WIDE_TABLE_QUERY = '(min-width: 1800px)';

type Tab = 'sessions' | 'certificates';

/** SSL/TLS view (docs/specs/tls.md): charts, filters, sessions table and certificates. */
export default function TlsView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const session = useSession(sessionId);
  const state = session.data?.state;
  const viewable = state === 'ready' || state === 'incomplete';
  const stats = useTlsStats(sessionId, viewable);
  const [tab, setTab] = useState<Tab>('sessions');

  let content: ReactNode;
  if (session.isError || stats.isError) {
    content = (
      <Card>
        <ErrorState
          message={t('views.tls.loadError')}
          onRetry={() => {
            void session.refetch();
            void stats.refetch();
          }}
        />
      </Card>
    );
  } else if (state === 'importing') {
    content = (
      <Card>
        <EmptyState icon={Hourglass} title={t('views.tls.importingTitle')} description={t('views.tls.importingText')} />
      </Card>
    );
  } else if (state === 'failed') {
    content = (
      <Card>
        <EmptyState
          icon={CircleAlert}
          title={t('views.tls.failedTitle')}
          description={session.data?.state_detail ?? t('views.tls.failedText')}
        />
      </Card>
    );
  } else if (stats.data === undefined) {
    content = (
      <div className="flex flex-col gap-4" aria-busy="true">
        <span className="sr-only">{t('common.loading')}</span>
        <Skeleton height={88} />
        <Skeleton height={CHART_HEIGHT.donut} />
      </div>
    );
  } else if (stats.data.sessions === 0) {
    content = (
      <Card>
        <EmptyState icon={Lock} title={t('views.tls.empty')} />
      </Card>
    );
  } else {
    const oneDay =
      session.data?.first_ts_us != null &&
      session.data.last_ts_us != null &&
      sameLocalDay(session.data.first_ts_us, session.data.last_ts_us);
    content = (
      <>
        <StatBand stats={stats.data} />
        <SegmentedControl
          hideLabel
          label={t('views.tls.tabs.label')}
          value={tab}
          options={[
            { value: 'sessions', label: t('views.tls.tabs.sessions') },
            { value: 'certificates', label: t('views.tls.tabs.certificates', { count: stats.data.certificates }) },
          ]}
          onChange={setTab}
        />
        {tab === 'sessions' ? (
          <SessionsPanel sessionId={sessionId} stats={stats.data} oneDay={oneDay} />
        ) : (
          <CertificatesPanel sessionId={sessionId} enabled={viewable} total={stats.data.certificates} />
        )}
      </>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('nav.items.tls')}
        subtitle={session.data?.name ?? t('views.tls.subtitle')}
        {...(stats.data === undefined ? {} : { count: <Badge>{formatCount(stats.data.sessions)}</Badge> })}
      />
      {content}
    </div>
  );
}

function StatBand({ stats }: { stats: TlsStats }) {
  const { t } = useTranslation();
  return (
    <section
      aria-label={t('views.tls.stat.sessions')}
      data-testid="tls-summary"
      className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5"
    >
      <StatCard icon={Lock} label={t('views.tls.stat.sessions')} value={formatCount(stats.sessions)} />
      <StatCard icon={TriangleAlert} label={t('views.tls.stat.weak')} value={formatCount(stats.weak_sessions)} />
      <StatCard icon={ShieldAlert} label={t('views.tls.stat.certIssues')} value={formatCount(stats.cert_issue_sessions)} />
      <StatCard
        icon={ShieldOff}
        label={t('views.tls.stat.encrypted')}
        value={formatCount(stats.encrypted_cert_sessions)}
        hint={t('views.tls.stat.encryptedHint')}
      />
      <StatCard icon={FileKey} label={t('views.tls.stat.certificates')} value={formatCount(stats.certificates)} />
    </section>
  );
}

function useChartFormat(): TlsChartFormat {
  const { t, i18n } = useTranslation();
  return useMemo(() => {
    const pct = new Intl.NumberFormat(i18n.language, { style: 'percent', maximumFractionDigits: 1 });
    return {
      version: (v) => versionLabel(v) ?? t('views.tls.charts.noServerHello'),
      share: (count, total) => t('views.tls.charts.share', { count, pct: pct.format(total === 0 ? 0 : count / total) }),
      other: t('common.other'),
      sessions: (count) => t('views.tls.charts.sessions', { count }),
      weak: (w) => (isWeakness(w) ? t(`views.tls.weak.${w}`) : t('views.tls.weak.other')),
      count: (n) => formatCount(n),
    };
  }, [t, i18n.language]);
}

interface PanelProps {
  sessionId: string;
  stats: TlsStats;
  oneDay: boolean;
}

function SessionsPanel({ sessionId, stats, oneDay }: PanelProps) {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const q = useDeferredValue(search);
  const [version, setVersion] = useState<number | undefined>(undefined);
  const [suite, setSuite] = useState<number | undefined>(undefined);
  const [weak, setWeak] = useState(false);
  const [certIssues, setCertIssues] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const filters: TlsSessionFilters = { version, suite, q, weak, certIssues };
  const list = useTlsSessions(sessionId, filters, true);
  const fmt = useChartFormat();
  const suiteId = useId();
  const { theme } = useTheme();
  const wideTable = useMediaQuery(WIDE_TABLE_QUERY);
  // Theme text color of the bar value labels (read again when the theme changes).
  const labelColor = useMemo(() => {
    void theme;
    return getComputedStyle(document.documentElement).getPropertyValue('--ns-muted').trim() || OTHER_COLOR;
  }, [theme]);

  const versionsOption = useMemo(() => buildVersionsOption(stats, fmt), [stats, fmt]);
  const suitesOption = useMemo(() => buildSuitesOption(stats, fmt, labelColor), [stats, fmt, labelColor]);
  const matrixOption = useMemo(() => buildMatrixOption(stats, fmt, theme === 'dark'), [stats, fmt, theme]);
  const columnsOfMatrix = useMemo(() => matrixVersions(stats), [stats]);

  const pieEvents = useMemo<ChartEvents>(
    () => ({
      click: (params) => {
        const v = versionOfPie(params);
        if (v !== undefined) setVersion((cur) => (cur === v ? undefined : v));
      },
    }),
    [],
  );
  const barEvents = useMemo<ChartEvents>(
    () => ({
      click: (params) => {
        const index = (params as { dataIndex?: number }).dataIndex;
        if (index === undefined) return;
        const s = suiteOfRow(stats, index);
        if (s !== undefined) setSuite((cur) => (cur === s ? undefined : s));
      },
    }),
    [stats],
  );
  const matrixEvents = useMemo<ChartEvents>(
    () => ({
      click: (params) => {
        const value = (params as { value?: unknown }).value;
        if (!Array.isArray(value)) return;
        const [x, y] = value as [number, number];
        const v = columnsOfMatrix[x];
        const s = suiteOfRow(stats, y);
        setVersion(v ?? undefined);
        setSuite(s);
      },
    }),
    [stats, columnsOfMatrix],
  );

  const columns = useSessionColumns(oneDay, wideTable);
  const filtered = version !== undefined || suite !== undefined || q !== '' || weak || certIssues;
  const selectedItem = list.data?.items.find((s) => s.id === selected);
  const suiteCount = stats.suites.length;

  let table: ReactNode;
  if (list.isPending) table = <Skeleton height={160} />;
  else if (list.isError)
    table = (
      <ErrorState
        message={t('views.tls.loadError')}
        onRetry={() => {
          void list.refetch();
        }}
      />
    );
  else
    table = (
      <>
        <DataTable
          columns={columns}
          data={list.data.items}
          getRowId={(s) => s.id}
          ariaLabel={t('views.tls.table.label')}
          emptyText={t('views.tls.table.empty')}
          onRowClick={(s) => {
            setSelected((cur) => (cur === s.id ? null : s.id));
          }}
        />
        {list.data.truncated && (
          <p className="border-t border-line px-3 py-2 text-meta text-muted sm:px-4">
            {t('views.tls.table.truncated', { count: list.data.items.length })}
          </p>
        )}
      </>
    );

  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-4 [grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr))]">
        <Card title={t('views.tls.charts.versions')}>
          <Chart
            option={versionsOption}
            height={CHART_HEIGHT.donut}
            ariaLabel={t('views.tls.charts.versionsLabel')}
            onEvents={pieEvents}
          />
        </Card>
        <Card title={t('views.tls.charts.suites')}>
          <div className="flex flex-col gap-2">
            <Chart
              option={suitesOption}
              height={CHART_HEIGHT.bars(suiteCount)}
              ariaLabel={t('views.tls.charts.suitesLabel')}
              empty={suiteCount === 0}
              onEvents={barEvents}
            />
            {stats.suites.some((s) => s.weak !== null) && (
              <p className="text-meta text-muted">{t('views.tls.charts.weakNote')}</p>
            )}
          </div>
        </Card>
      </div>

      {suiteCount > 0 && (
        <Card title={t('views.tls.charts.matrix')}>
          <Chart
            option={matrixOption}
            height={matrixHeight(suiteCount)}
            ariaLabel={t('views.tls.charts.matrixLabel')}
            onEvents={matrixEvents}
          />
        </Card>
      )}

      <Card
        title={t('views.tls.table.label')}
        actions={
          <div className="flex min-w-0 flex-wrap items-center gap-2" data-testid="tls-filters">
            <FilterBar
              filters={[
                { id: 'weak', label: t('views.tls.filters.weak'), count: stats.weak_sessions, active: weak },
                {
                  id: 'certIssues',
                  label: t('views.tls.filters.certIssues'),
                  count: stats.cert_issue_sessions,
                  active: certIssues,
                },
              ]}
              onToggle={(id, active) => {
                if (id === 'weak') setWeak(active);
                else setCertIssues(active);
              }}
              search={search}
              onSearch={setSearch}
              searchPlaceholder={t('views.tls.filters.search')}
            />
            <SegmentedControl
              hideLabel
              label={t('views.tls.filters.version')}
              value={version === undefined ? ANY : String(version)}
              options={[
                { value: ANY, label: t('views.tls.filters.anyVersion') },
                ...stats.versions
                  .filter((v) => v.version !== null)
                  .map((v) => ({ value: String(v.version), label: versionLabel(v.version) ?? '' })),
              ]}
              onChange={(v) => {
                setVersion(v === ANY ? undefined : Number(v));
              }}
            />
            {/* Up to 15 long names: a native list stays usable on every width. */}
            <label htmlFor={suiteId} className="sr-only">
              {t('views.tls.filters.suite')}
            </label>
            <select
              id={suiteId}
              value={suite ?? ''}
              onChange={(e) => {
                setSuite(e.target.value === '' ? undefined : Number(e.target.value));
              }}
              className="h-8 w-full min-w-0 rounded-md border border-line bg-surface px-2 text-body sm:w-auto sm:max-w-72"
            >
              <option value="">{t('views.tls.filters.anySuite')}</option>
              {stats.suites
                .filter((s) => s.suite !== null)
                .map((s) => (
                  <option key={s.suite} value={s.suite ?? ''}>
                    {`${suiteLabel(s.name, s.suite)} (${formatCount(s.count)})`}
                  </option>
                ))}
            </select>
            {filtered && (
              <Button
                variant="ghost"
                onClick={() => {
                  setSearch('');
                  setVersion(undefined);
                  setSuite(undefined);
                  setWeak(false);
                  setCertIssues(false);
                }}
              >
                {t('views.tls.filters.clear')}
              </Button>
            )}
          </div>
        }
        flush
      >
        {table}
      </Card>

      {selectedItem !== undefined && (
        <SessionDetail
          key={selectedItem.id}
          sessionId={sessionId}
          item={selectedItem}
          onClose={() => {
            setSelected(null);
          }}
        />
      )}
    </div>
  );
}

/**
 * Columns of the sessions table. Below `WIDE_TABLE_QUERY`, client and ALPN are hidden (they are
 * in the details) and the others narrower, so that JA3, JA4 and the certificate stay in view.
 */
function useSessionColumns(oneDay: boolean, wide: boolean): ColumnDef<TlsSessionItem, unknown>[] {
  const { t } = useTranslation();
  return useMemo<ColumnDef<TlsSessionItem, unknown>[]>(() => {
    const all: ColumnDef<TlsSessionItem, unknown>[] = [
      {
        id: 'time',
        accessorFn: (s) => s.ts_us,
        header: t('views.tls.table.col.time'),
        size: oneDay ? 88 : 168,
        cell: ({ row }) => <span className="num">{formatTimestamp(row.original.ts_us, !oneDay)}</span>,
      },
      {
        id: 'client',
        accessorFn: (s) => s.client_ip,
        header: t('views.tls.table.col.client'),
        size: 152,
        cell: ({ row }) => <Endpoint ip={row.original.client_ip} port={row.original.client_port} />,
      },
      {
        id: 'server',
        accessorFn: (s) => s.server_ip,
        header: t('views.tls.table.col.server'),
        size: 152,
        cell: ({ row }) => <Endpoint ip={row.original.server_ip} port={row.original.server_port} />,
      },
      {
        id: 'sni',
        accessorFn: (s) => s.sni ?? '',
        header: t('views.tls.table.col.sni'),
        size: 160,
        cell: ({ row }) => {
          const sni = row.original.sni ?? '';
          return (
            <span data-testid="truncatable" title={sni} className="block truncate">
              {sni}
            </span>
          );
        },
      },
      {
        id: 'version',
        accessorFn: (s) => s.version ?? 0,
        header: t('views.tls.table.col.version'),
        size: 84,
        cell: ({ row }) => {
          const label = versionLabel(row.original.version);
          return label === null ? null : <Badge tone={versionTone(row.original.version)}>{label}</Badge>;
        },
      },
      {
        id: 'suite',
        accessorFn: (s) => s.cipher_name ?? '',
        header: t('views.tls.table.col.suite'),
        size: 250,
        cell: ({ row }) =>
          row.original.cipher_suite === null ? null : (
            <SuiteName name={row.original.cipher_name} id={row.original.cipher_suite} weak={row.original.cipher_weak} />
          ),
      },
      {
        id: 'alpn',
        accessorFn: (s) => s.alpn ?? '',
        header: t('views.tls.table.col.alpn'),
        size: 80,
        cell: ({ row }) => {
          const alpn = row.original.alpn ?? row.original.alpn_offered.join(', ');
          const offered = row.original.alpn === null && alpn !== '';
          return (
            <span data-testid="truncatable" title={alpn} className={offered ? 'block truncate text-faint' : 'block truncate'}>
              {alpn}
            </span>
          );
        },
      },
      {
        id: 'ja3',
        accessorFn: (s) => s.ja3_hash ?? '',
        header: t('views.tls.table.col.ja3'),
        size: 140,
        cell: ({ row }) =>
          row.original.ja3_hash === null ? null : (
            <MonoValue value={row.original.ja3_hash} name={t('views.tls.table.col.ja3')} />
          ),
      },
      {
        id: 'ja4',
        accessorFn: (s) => s.ja4 ?? '',
        header: t('views.tls.table.col.ja4'),
        size: 190,
        cell: ({ row }) =>
          row.original.ja4 === null ? null : <MonoValue value={row.original.ja4} name={t('views.tls.table.col.ja4')} />,
      },
      {
        id: 'certificate',
        accessorFn: (s) => s.leaf_subject_cn ?? '',
        header: t('views.tls.table.col.certificate'),
        size: 220,
        cell: ({ row }) => <CertificateCell item={row.original} />,
      },
    ];
    return all
      .filter((c) => wide || (c.id !== 'client' && c.id !== 'alpn'))
      .map((c) => {
        const narrow = c.id === undefined ? undefined : NARROW_SIZES[c.id];
        return wide || narrow === undefined ? c : { ...c, size: narrow };
      });
  }, [t, oneDay, wide]);
}

/** Column widths below `WIDE_TABLE_QUERY` (about 1000 px in all). */
const NARROW_SIZES: Readonly<Record<string, number>> = {
  server: 140,
  sni: 130,
  version: 80,
  suite: 170,
  ja3: 100,
  ja4: 140,
  certificate: 150,
};

function Endpoint({ ip, port }: { ip: string; port: number }) {
  const text = ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`;
  return (
    <span data-testid="truncatable" title={text} className="block truncate font-mono text-meta">
      {text}
    </span>
  );
}

function CertificateCell({ item }: { item: TlsSessionItem }) {
  const { t } = useTranslation();
  if (item.cert_status === 'encrypted') return <span className="text-muted">{t('views.tls.cert.encrypted')}</span>;
  if (item.cert_count === 0) return <span className="text-faint">{t('views.tls.cert.none')}</span>;
  const cn = item.leaf_subject_cn ?? item.leaf_sha256?.slice(0, 12) ?? '';
  return (
    <span className="flex min-w-0 items-center gap-1.5 overflow-hidden">
      <span data-testid="truncatable" title={cn} className="min-w-0 truncate">
        {cn}
      </span>
      <IssueBadges issues={item.cert_issues} />
    </span>
  );
}
