import { getRouteApi, Link } from '@tanstack/react-router';
import {
  Cable,
  CircleAlert,
  Clock,
  FileStack,
  HardDrive,
  Hourglass,
  Layers,
  Monitor,
  RotateCcw,
} from 'lucide-react';
import { type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useOverviewSummary, useTraffic } from '../../api/overviewQueries';
import { useSession } from '../../api/sessionQueries';
import type { OverviewSummary } from '../../api/types/OverviewSummary';
import type { TrafficProtocol } from '../../api/types/TrafficProtocol';
import type { ChartEvents } from '../../charts/EChartsRenderer';
import { colorFor } from '../../charts/palette';
import { CHART_HEIGHT } from '../../charts/sizes';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { Chart } from '../../components/Chart';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';
import { MultiSelect } from '../../components/MultiSelect';
import { PageHeader } from '../../components/PageHeader';
import { SegmentedControl } from '../../components/SegmentedControl';
import { StatCard } from '../../components/StatCard';
import { formatBytes, formatCount, formatDuration, formatPeriod, formatTimestamp, sameLocalDay } from '../../lib/format';
import { useMediaQuery } from '../../lib/useMediaQuery';
import { SessionStateBadge } from '../sessions/SessionStateBadge';
import { linktypeName } from './linktypes';
import { ModuleGrid } from './ModuleGrid';
import {
  buildTrafficOption,
  FULL_ZOOM,
  isZoomed,
  type LegendLayout,
  type Metric,
  type Scale,
  type TrafficFormat,
  type Zoom,
  zoomOfEvent,
} from './trafficChart';

const route = getRouteApi('/sessions/$sessionId');

/** Below this viewport width the legend is hidden and the chart is shorter (spec). */
const SM_QUERY = '(min-width: 640px)';
const SMALL_CHART_HEIGHT = 240;
/** Buckets asked for (the server allows up to 2000). */
const POINTS = 500;
const SMALL_POINTS = 200;
/** Container width from which the legend moves to the right of the chart. */
const LEGEND_SIDE_MIN_WIDTH = 1024;

/** Width of an element, followed with a ResizeObserver (0 before layout). */
function useElementWidth<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const el = ref.current;
    if (el === null) return;
    const ro = new ResizeObserver((entries) => {
      setWidth(Math.round(entries[0]?.contentRect.width ?? 0));
    });
    ro.observe(el);
    return () => {
      ro.disconnect();
    };
  }, []);
  return [ref, width];
}

/** Session overview: summary band, traffic by protocol over time, module cards. */
export default function OverviewView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const session = useSession(sessionId);
  const state = session.data?.state;
  const viewable = state === 'ready' || state === 'incomplete';
  const summary = useOverviewSummary(sessionId, viewable);

  let content: ReactNode;
  if (session.isError) {
    content = (
      <Card>
        <ErrorState
          message={t('views.overview.loadError')}
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
          title={t('views.overview.importingTitle')}
          description={t('views.overview.importingText')}
          action={<CapturesLink />}
        />
      </Card>
    );
  } else if (state === 'failed') {
    content = (
      <Card>
        <EmptyState
          icon={CircleAlert}
          title={t('views.overview.failedTitle')}
          description={session.data?.state_detail ?? t('views.overview.failedText')}
          action={<CapturesLink />}
        />
      </Card>
    );
  } else {
    content = (
      <>
        <SummaryBand
          summary={summary.data ?? null}
          error={summary.isError}
          onRetry={() => {
            void summary.refetch();
          }}
        />
        <TrafficCard sessionId={sessionId} enabled={viewable} />
        <section aria-labelledby="overview-modules" className="flex flex-col gap-2">
          <h2 id="overview-modules" className="text-card font-medium">
            {t('views.overview.modulesTitle')}
          </h2>
          <ModuleGrid sessionId={sessionId} modules={summary.data?.modules ?? null} />
        </section>
      </>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('nav.items.overview')}
        subtitle={session.data?.name ?? t('views.overview.subtitle')}
        {...(state === undefined || state === 'ready'
          ? {}
          : { count: <SessionStateBadge state={state} detail={session.data?.state_detail ?? null} /> })}
        actions={
          <Link
            to="/sessions/$sessionId/sources"
            params={{ sessionId }}
            className="inline-flex h-8 items-center gap-1.5 rounded-md border border-line bg-surface px-3 font-medium hover:bg-subtle"
          >
            <FileStack aria-hidden size={16} strokeWidth={1.75} />
            {t('views.session.sources')}
          </Link>
        }
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

function SummaryBand({
  summary,
  error,
  onRetry,
}: {
  summary: OverviewSummary | null;
  error: boolean;
  onRetry: () => void;
}) {
  const { t } = useTranslation();
  if (error) {
    return (
      <Card>
        <ErrorState message={t('views.overview.loadError')} onRetry={onRetry} />
      </Card>
    );
  }
  const s = summary;
  const hasPeriod = s !== null && s.first_ts_us !== null && s.last_ts_us !== null;
  const period = s === null ? '' : formatPeriod(s.first_ts_us, s.last_ts_us);
  const avg = s !== null && s.packets > 0 ? formatBytes(s.bytes / s.packets) : null;
  const links = s === null ? '' : s.linktypes.map(linktypeName).join(', ');
  return (
    <section
      aria-label={t('views.overview.summaryLabel')}
      data-testid="overview-summary"
      className="grid grid-cols-2 gap-3 sm:grid-cols-3 2xl:grid-cols-6"
    >
      <StatCard
        icon={Clock}
        label={t('views.overview.stat.duration')}
        value={s === null ? null : hasPeriod ? formatDuration((s.duration_us ?? 0) / 1e6) : t('views.overview.noPeriod')}
        hint={<span title={period}>{period === '' ? ' ' : period}</span>}
      />
      <StatCard
        icon={Layers}
        label={t('views.overview.stat.packets')}
        value={s === null ? null : formatCount(s.packets)}
        hint={<span title={links}>{links === '' ? ' ' : t('views.overview.linktypes', { list: links })}</span>}
      />
      <StatCard
        icon={HardDrive}
        label={t('views.overview.stat.volume')}
        value={s === null ? null : formatBytes(s.bytes)}
        {...(s === null ? {} : { title: `${formatCount(s.bytes)} B` })}
        hint={avg === null ? ' ' : t('views.overview.avgPacket', { size: avg })}
      />
      <StatCard icon={Monitor} label={t('views.overview.stat.hosts')} value={s === null ? null : formatCount(s.host_count)} />
      <StatCard icon={Cable} label={t('views.overview.stat.flows')} value={s === null ? null : formatCount(s.flow_count)} />
      <StatCard
        icon={FileStack}
        label={t('views.overview.stat.chunks')}
        value={s === null ? null : formatCount(s.chunk_count)}
        tone={s !== null && s.anomaly_count > 0 ? 'warning' : 'neutral'}
        hint={s === null ? ' ' : t('views.overview.anomalies', { count: s.anomaly_count })}
      />
    </section>
  );
}

const compact = (lang: string) => new Intl.NumberFormat(lang, { notation: 'compact', maximumFractionDigits: 1 });

function TrafficCard({ sessionId, enabled }: { sessionId: string; enabled: boolean }) {
  const { t, i18n } = useTranslation();
  const small = !useMediaQuery(SM_QUERY);
  // A few hundred buckets are enough for the chart width (and keep short bursts readable).
  const traffic = useTraffic(sessionId, { points: small ? SMALL_POINTS : POINTS }, enabled);
  const [metric, setMetric] = useState<Metric>('bytes');
  const [scale, setScale] = useState<Scale>('linear');
  const [zoom, setZoom] = useState<Zoom>(FULL_ZOOM);
  // Protocols hidden by the user; new protocols are shown by default.
  const [hidden, setHidden] = useState<ReadonlySet<TrafficProtocol>>(new Set());
  const [boxRef, boxWidth] = useElementWidth<HTMLDivElement>();

  const data = traffic.data;
  const present = useMemo(() => data?.series.map((s) => s.protocol) ?? [], [data]);
  const selected = useMemo(() => new Set(present.filter((p) => !hidden.has(p))), [present, hidden]);

  const legend: LegendLayout = small ? 'none' : boxWidth >= LEGEND_SIDE_MIN_WIDTH ? 'right' : 'bottom';
  const lang = i18n.language;

  const format = useMemo<TrafficFormat>(() => {
    const step = data === undefined ? 0 : data.step_us / 1e6;
    const first = data?.start_us ?? 0;
    const last = data === undefined ? 0 : data.start_us + data.points * data.step_us;
    const oneDay = sameLocalDay(first, last);
    const count = compact(lang);
    return {
      protocol: (p) => t(`views.overview.protocols.${p}`),
      value: (v) => (metric === 'bytes' ? formatBytes(v, lang) : formatCount(v)),
      axis: (v) => (metric === 'bytes' ? formatBytes(v, lang) : count.format(v)),
      bucket: (ms) =>
        t('views.overview.traffic.bucket', {
          time: formatTimestamp(ms * 1000, !oneDay),
          step: formatDuration(step, lang),
        }),
      total: t('views.overview.traffic.total'),
    };
  }, [t, lang, metric, data]);

  const option = useMemo(
    () => (data === undefined ? {} : buildTrafficOption({ data, selected, metric, scale, zoom, legend, format })),
    [data, selected, metric, scale, zoom, legend, format],
  );

  const onEvents = useMemo<ChartEvents>(
    () => ({
      datazoom: (params) => {
        const z = zoomOfEvent(params);
        if (z !== null) setZoom(z);
      },
    }),
    [],
  );

  const setSelected = useCallback(
    (next: Set<TrafficProtocol>) => {
      setHidden(new Set(present.filter((p) => !next.has(p))));
    },
    [present],
  );

  const options = useMemo(
    () =>
      (data?.series ?? []).map((s) => ({
        value: s.protocol,
        label: t(`views.overview.protocols.${s.protocol}`),
        color: colorFor(s.protocol),
        detail: metric === 'bytes' ? formatBytes(s.total_bytes, lang) : formatCount(s.total_packets),
      })),
    [data, t, metric, lang],
  );

  const height = small ? SMALL_CHART_HEIGHT : CHART_HEIGHT.timeseries;
  const noData = data !== undefined && data.series.length === 0;
  const noneSelected = data !== undefined && !noData && selected.size === 0;

  return (
    <Card title={t('views.overview.traffic.title')}>
      <div className="flex flex-col gap-3">
        <div className="flex min-w-0 flex-wrap items-center gap-2" data-testid="traffic-controls">
          <MultiSelect
            label={t('views.overview.traffic.protocols')}
            options={options}
            selected={selected}
            onChange={setSelected}
          />
          <SegmentedControl
            hideLabel
            label={t('views.overview.traffic.metric')}
            value={metric}
            options={[
              { value: 'bytes', label: t('views.overview.traffic.bytes') },
              { value: 'packets', label: t('views.overview.traffic.packets') },
            ]}
            onChange={setMetric}
          />
          <SegmentedControl
            hideLabel
            label={t('views.overview.traffic.scale')}
            value={scale}
            options={[
              { value: 'linear', label: t('views.overview.traffic.linear') },
              { value: 'log', label: t('views.overview.traffic.log') },
            ]}
            onChange={setScale}
          />
          <Button
            variant="ghost"
            disabled={!isZoomed(zoom)}
            onClick={() => {
              setZoom(FULL_ZOOM);
            }}
          >
            <RotateCcw aria-hidden size={16} strokeWidth={1.75} />
            {t('views.overview.traffic.resetZoom')}
          </Button>
        </div>
        <div ref={boxRef} className="min-w-0">
          <Chart
            option={option}
            height={height}
            ariaLabel={t('views.overview.traffic.chartLabel')}
            loading={!enabled || traffic.isPending}
            error={traffic.isError ? t('views.overview.traffic.loadError') : null}
            onRetry={() => {
              void traffic.refetch();
            }}
            empty={noData || noneSelected}
            emptyText={noData ? t('views.overview.traffic.empty') : t('views.overview.traffic.noneSelected')}
            onEvents={onEvents}
          />
        </div>
      </div>
    </Card>
  );
}
