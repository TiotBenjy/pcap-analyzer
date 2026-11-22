import { getRouteApi, Link } from '@tanstack/react-router';
import {
  Cable,
  CircleAlert,
  Clock,
  Download,
  FileStack,
  HardDrive,
  Hourglass,
  Layers,
  Monitor,
  CalendarRange,
  Maximize2,
  ZoomOut,
} from 'lucide-react';
import { type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTimeRange } from '../../app/timeRange';
import { useTranslation } from 'react-i18next';
import { useOverviewSummary, useTraffic } from '../../api/overviewQueries';
import { useSession } from '../../api/sessionQueries';
import type { OverviewSummary } from '../../api/types/OverviewSummary';
import type { TrafficProtocol } from '../../api/types/TrafficProtocol';
import type { ChartEvents, ChartHandle } from '../../charts/EChartsRenderer';
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
import { TimeRangeDialog } from '../../components/TimeRangeDialog';
import { sessionVersionMessage } from '../../lib/errors';
import { formatByteCount, formatBytes, formatCompact, formatCount, formatDuration, formatPeriod, formatTimestamp, sameLocalDay } from '../../lib/format';
import { type TimeRange, widen } from '../../lib/timeRange';
import { useMediaQuery } from '../../lib/useMediaQuery';
import { SavePcapDialog } from '../exports/SavePcapDialog';
import { SessionStateBadge } from '../sessions/SessionStateBadge';
import { linktypeName } from './linktypes';
import { ModuleGrid } from './ModuleGrid';
import {
  buildTrafficOption,
  FULL_ZOOM,
  type LegendLayout,
  type Metric,
  type Scale,
  type TrafficFormat,
  zoomOfEvent,
  zoomRange,
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
/** A zoom becomes the time range of the views once it has not moved for this long. */
export const ZOOM_SETTLE_MS = 400;

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
  const [saving, setSaving] = useState(false);
  const { range, setRange } = useTimeRange();
  const firstUs = summary.data?.first_ts_us ?? null;
  const lastUs = summary.data?.last_ts_us ?? null;

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
          error={summary.isError ? summary.error : null}
          onRetry={() => {
            void summary.refetch();
          }}
        />
        <TrafficCard
          sessionId={sessionId}
          enabled={viewable}
          range={range}
          setRange={setRange}
          firstUs={firstUs}
          lastUs={lastUs}
        />
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
          <>
            <Link
              to="/sessions/$sessionId/sources"
              params={{ sessionId }}
              className="inline-flex h-8 items-center gap-1.5 rounded-md border border-line bg-surface px-3 font-medium hover:bg-subtle"
            >
              <FileStack aria-hidden size={16} strokeWidth={1.75} />
              {t('views.session.sources')}
            </Link>
            {viewable && (
              <Button
                title={t('views.exportPcap.actionTitle')}
                onClick={() => {
                  setSaving(true);
                }}
              >
                <Download aria-hidden size={16} strokeWidth={1.75} />
                {t('views.exportPcap.action')}
              </Button>
            )}
          </>
        }
      />
      {content}
      <SavePcapDialog
        open={saving}
        onClose={() => {
          setSaving(false);
        }}
        sessionId={sessionId}
        firstUs={firstUs}
        lastUs={lastUs}
        activeRange={range}
      />
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
  /** Error of the summary query, `null` when none. */
  error: unknown;
  onRetry: () => void;
}) {
  const { t } = useTranslation();
  if (error !== null) {
    return (
      <Card>
        <ErrorState message={sessionVersionMessage(t, error) ?? t('views.overview.loadError')} onRetry={onRetry} />
      </Card>
    );
  }
  const s = summary;
  // Under a time range, the figures of the range (chunks stay those of the capture files).
  const r = s?.range ?? null;
  const inRange = t('timeRange.inRange');
  const hasPeriod = r !== null || (s !== null && s.first_ts_us !== null && s.last_ts_us !== null);
  const period = r !== null ? formatPeriod(r.from_us, r.to_us) : s === null ? '' : formatPeriod(s.first_ts_us, s.last_ts_us);
  const packets = r?.packets ?? s?.packets ?? 0;
  const bytes = r?.bytes ?? s?.bytes ?? 0;
  const avg = s !== null && packets > 0 ? formatBytes(bytes / packets) : null;
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
        value={
          s === null ? null : hasPeriod ? formatDuration((r?.duration_us ?? s.duration_us ?? 0) / 1e6) : t('views.overview.noPeriod')
        }
        hint={period === '' ? ' ' : period}
      />
      <StatCard
        icon={Layers}
        label={t('views.overview.stat.packets')}
        value={s === null ? null : formatCount(packets)}
        hint={r !== null ? inRange : links === '' ? ' ' : t('views.overview.linktypes', { list: links })}
      />
      <StatCard
        icon={HardDrive}
        label={t('views.overview.stat.volume')}
        value={s === null ? null : formatBytes(bytes)}
        {...(s === null ? {} : { title: formatByteCount(bytes) })}
        hint={avg === null ? ' ' : t('views.overview.avgPacket', { size: avg })}
      />
      <StatCard
        icon={Monitor}
        label={t('views.overview.stat.hosts')}
        value={s === null ? null : formatCount(r?.host_count ?? s.host_count)}
        {...(r === null ? {} : { hint: inRange })}
      />
      <StatCard
        icon={Cable}
        label={t('views.overview.stat.flows')}
        value={s === null ? null : formatCount(r?.flow_count ?? s.flow_count)}
        {...(r === null ? {} : { hint: inRange })}
      />
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

interface TrafficCardProps {
  sessionId: string;
  enabled: boolean;
  /** Time range of the views (URL), `null` for the whole session. */
  range: TimeRange | null;
  setRange: (range: TimeRange | null) => void;
  /** Captured period, bounds of Zoom out and of the range dialog. */
  firstUs: number | null;
  lastUs: number | null;
}

function TrafficCard({ sessionId, enabled, range, setRange, firstUs, lastUs }: TrafficCardProps) {
  const { t, i18n } = useTranslation();
  const small = !useMediaQuery(SM_QUERY);
  // A few hundred buckets are enough for the chart width (and keep short bursts readable). Under
  // a time range the series of the range is asked for: zooming gains resolution down to the
  // second instead of stretching the loaded series (docs/specs/time-filter.md).
  const params = useMemo(
    () => ({
      points: small ? SMALL_POINTS : POINTS,
      ...(range === null ? {} : { from_us: range.fromUs, to_us: range.toUs }),
    }),
    [small, range],
  );
  const traffic = useTraffic(sessionId, params, enabled);
  const [metric, setMetric] = useState<Metric>('bytes');
  const [scale, setScale] = useState<Scale>('linear');
  const [editing, setEditing] = useState(false);
  // The zoom window lives in the chart (never in the option, so dragging does not rebuild it).
  // Once it settles it becomes the time range of every view, and the chart is reset to show the
  // series of that range, fetched again.
  const chartHandle = useRef<ChartHandle>(null);
  const settle = useRef<ReturnType<typeof setTimeout> | null>(null);
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
    return {
      protocol: (p) => t(`views.overview.protocols.${p}`),
      value: (v) => (metric === 'bytes' ? formatBytes(v, lang) : formatCount(v, lang)),
      axis: (v) => (metric === 'bytes' ? formatBytes(v, lang, true) : formatCompact(v, lang)),
      bucket: (ms) =>
        t('views.overview.traffic.bucket', {
          time: formatTimestamp(ms * 1000, !oneDay),
          step: formatDuration(step, lang),
        }),
      total: t('views.overview.traffic.total'),
    };
  }, [t, lang, metric, data]);

  const option = useMemo(
    () =>
      data === undefined ? {} : buildTrafficOption({ data, selected, metric, scale, legend, compact: small, format }),
    [data, selected, metric, scale, legend, small, format],
  );

  const dataRef = useRef(data);
  useEffect(() => {
    dataRef.current = data;
  }, [data]);
  const onEvents = useMemo<ChartEvents>(
    () => ({
      datazoom: (event) => {
        const z = zoomOfEvent(event);
        if (settle.current !== null) clearTimeout(settle.current);
        settle.current = setTimeout(() => {
          settle.current = null;
          const shown = dataRef.current;
          const next = z === null || shown === undefined ? null : zoomRange(shown, z);
          if (next !== null) setRange(next);
        }, ZOOM_SETTLE_MS);
      },
    }),
    [setRange],
  );
  useEffect(
    () => () => {
      if (settle.current !== null) clearTimeout(settle.current);
    },
    [],
  );
  // A new series (another range, or the whole session again): the chart shows all of it.
  useEffect(() => {
    if (data !== undefined) chartHandle.current?.dispatchAction({ type: 'dataZoom', ...FULL_ZOOM });
  }, [data]);

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
            disabled={range === null}
            title={t('timeRange.controls.zoomOutTitle')}
            onClick={() => {
              if (range !== null) setRange(widen(range, firstUs, lastUs));
            }}
          >
            <ZoomOut aria-hidden size={16} strokeWidth={1.75} />
            {t('timeRange.controls.zoomOut')}
          </Button>
          <Button
            variant="ghost"
            title={t('timeRange.controls.editTitle')}
            onClick={() => {
              setEditing(true);
            }}
          >
            <CalendarRange aria-hidden size={16} strokeWidth={1.75} />
            {t('timeRange.controls.edit')}
          </Button>
          <Button
            variant="ghost"
            disabled={range === null}
            title={t('timeRange.controls.allTitle')}
            onClick={() => {
              setRange(null);
            }}
          >
            <Maximize2 aria-hidden size={16} strokeWidth={1.75} />
            {t('timeRange.controls.all')}
          </Button>
          <TimeRangeDialog
            open={editing}
            onClose={() => {
              setEditing(false);
            }}
            initial={range ?? (firstUs !== null && lastUs !== null ? { fromUs: firstUs, toUs: lastUs } : null)}
            onApply={setRange}
          />
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
            handleRef={chartHandle}
          />
        </div>
      </div>
    </Card>
  );
}
