import { getRouteApi } from '@tanstack/react-router';
import type { ColumnDef } from '@tanstack/react-table';
import { FileStack, TriangleAlert } from 'lucide-react';
import { type ReactNode, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useAnomalies, useChunks, useSession } from '../../api/sessionQueries';
import type { AnomalyInfo } from '../../api/types/AnomalyInfo';
import type { ChunkInfo } from '../../api/types/ChunkInfo';
import { Badge, type BadgeTone } from '../../components/Badge';
import { Card } from '../../components/Card';
import { DataTable } from '../../components/DataTable';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';
import { PageHeader } from '../../components/PageHeader';
import { Skeleton } from '../../components/Skeleton';
import { baseName, formatBytes, formatCount, formatSpan, formatTimestamp, timeZoneLabel } from '../../lib/format';
import { anomalyDetail, anomalyLabel, anomalySummary, anomalyWhere } from './anomalies';
import { buildCoverage } from './coverage';
import { CoverageTimeline } from './CoverageTimeline';

const route = getRouteApi('/sessions/$sessionId/sources');

const CHUNK_TONES: Record<string, BadgeTone> = {
  ok: 'success',
  truncated: 'warning',
  duplicate: 'neutral',
  skipped: 'neutral',
};
const CHUNK_STATES = new Set(['ok', 'truncated', 'duplicate', 'skipped'] as const);
type ChunkState = typeof CHUNK_STATES extends Set<infer S> ? S : never;
const isChunkState = (s: string): s is ChunkState => (CHUNK_STATES as Set<string>).has(s);

/** Session sources: chunk coverage timeline, chunk table, continuity anomalies. */
export default function SourcesView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const session = useSession(sessionId);
  const chunks = useChunks(sessionId);
  const anomalies = useAnomalies(sessionId);

  const coverage = useMemo(
    () => (chunks.data === undefined ? null : buildCoverage(chunks.data.items, anomalies.data?.items ?? [])),
    [chunks.data, anomalies.data],
  );
  const summary = anomalies.data === undefined ? [] : anomalySummary(t, anomalies.data.items);

  let timeline: ReactNode;
  if (chunks.isPending) timeline = <Skeleton height={72} />;
  else if (chunks.isError)
    timeline = (
      <ErrorState
        message={t('views.sources.loadError')}
        onRetry={() => {
          void chunks.refetch();
        }}
      />
    );
  else if (chunks.data.items.length === 0) timeline = <EmptyState icon={FileStack} title={t('views.sources.noChunks')} />;
  else if (coverage === null) timeline = <EmptyState icon={FileStack} title={t('views.sources.noTimestamps')} />;
  else timeline = <CoverageTimeline coverage={coverage} />;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('nav.items.sources')}
        subtitle={session.data?.name ?? t('views.sources.subtitle')}
        {...(chunks.data === undefined ? {} : { count: <Badge>{formatCount(chunks.data.items.length)}</Badge> })}
      />

      {summary.length > 0 && (
        <div
          role="status"
          data-testid="anomaly-summary"
          className="flex min-w-0 items-start gap-2 rounded-lg border border-line bg-surface px-3 py-2 sm:px-4"
        >
          <TriangleAlert aria-hidden size={16} strokeWidth={1.75} className="mt-0.5 shrink-0 text-warning" />
          <p className="min-w-0">{summary.join(', ')}</p>
        </div>
      )}

      <Card
        title={t('views.sources.coverage')}
        actions={<span className="text-meta text-muted">{t('views.captures.timeZone', { tz: timeZoneLabel() })}</span>}
      >
        {timeline}
      </Card>

      <Card title={t('views.sources.chunks')} flush>
        <ChunkTable query={chunks} />
      </Card>

      <Card title={t('views.sources.anomalies')} flush>
        <AnomalyTable query={anomalies} chunks={chunks.data?.items ?? []} />
      </Card>
    </div>
  );
}

interface ListQuery<T> {
  isPending: boolean;
  isError: boolean;
  data: { items: T[]; truncated: boolean } | undefined;
  refetch: () => Promise<unknown>;
}

function QueryBlock<T>({ query, children }: { query: ListQuery<T>; children: (items: T[]) => ReactNode }) {
  const { t } = useTranslation();
  if (query.isPending)
    return (
      <div className="flex flex-col gap-2 p-3 sm:p-4" aria-busy="true">
        <span className="sr-only">{t('common.loading')}</span>
        <Skeleton height={32} />
        <Skeleton height={32} />
      </div>
    );
  if (query.isError || query.data === undefined)
    return (
      <ErrorState
        message={t('views.sources.loadError')}
        onRetry={() => {
          void query.refetch();
        }}
      />
    );
  return (
    <>
      {children(query.data.items)}
      {query.data.truncated && (
        <p className="border-t border-line px-3 py-2 text-meta text-muted sm:px-4">
          {t('views.sources.truncatedList', { count: query.data.items.length })}
        </p>
      )}
    </>
  );
}

function ChunkTable({ query }: { query: ListQuery<ChunkInfo> }) {
  const { t } = useTranslation();
  const columns = useMemo<ColumnDef<ChunkInfo, unknown>[]>(
    () => [
      {
        id: 'index',
        accessorFn: (c) => c.id,
        header: t('views.sources.col.index'),
        size: 64,
        cell: ({ row }) => <span className="num font-mono text-meta">{row.original.id}</span>,
      },
      {
        id: 'name',
        accessorFn: (c) => baseName(c.path),
        header: t('views.sources.col.name'),
        size: 240,
        cell: ({ row }) => (
          <span data-testid="truncatable" title={row.original.path} className="block truncate font-mono text-meta">
            {baseName(row.original.path)}
          </span>
        ),
      },
      {
        id: 'size',
        accessorFn: (c) => c.bytes,
        header: t('views.sources.col.size'),
        size: 96,
        cell: ({ row }) => <span className="num">{formatBytes(row.original.bytes)}</span>,
      },
      {
        id: 'start',
        accessorFn: (c) => c.first_ts_us ?? Number.MAX_SAFE_INTEGER,
        header: t('views.sources.col.start'),
        size: 168,
        cell: ({ row }) => <Ts us={row.original.first_ts_us} />,
      },
      {
        id: 'end',
        accessorFn: (c) => c.last_ts_us ?? Number.MAX_SAFE_INTEGER,
        header: t('views.sources.col.end'),
        size: 168,
        cell: ({ row }) => <Ts us={row.original.last_ts_us} />,
      },
      {
        id: 'duration',
        accessorFn: (c) => (c.first_ts_us === null || c.last_ts_us === null ? -1 : c.last_ts_us - c.first_ts_us),
        header: t('views.sources.col.duration'),
        size: 104,
        cell: ({ row }) => <span className="num">{formatSpan(row.original.first_ts_us, row.original.last_ts_us)}</span>,
      },
      {
        id: 'packets',
        accessorFn: (c) => c.packets,
        header: t('views.sources.col.packets'),
        size: 96,
        cell: ({ row }) => <span className="num">{formatCount(row.original.packets)}</span>,
      },
      {
        id: 'format',
        accessorFn: (c) => c.format,
        header: t('views.sources.col.format'),
        size: 96,
        cell: ({ row }) => (
          <span className="font-mono text-meta">
            {row.original.format}
            {row.original.compressed ? '.gz' : ''}
          </span>
        ),
      },
      {
        id: 'state',
        accessorFn: (c) => c.state,
        header: t('views.sources.col.state'),
        size: 112,
        cell: ({ row }) => {
          const s = row.original.state;
          return (
            <Badge tone={CHUNK_TONES[s] ?? 'neutral'}>{isChunkState(s) ? t(`views.sources.chunkState.${s}`) : s}</Badge>
          );
        },
      },
    ],
    [t],
  );
  return (
    <QueryBlock query={query}>
      {(items) => (
        <DataTable
          ariaLabel={t('views.sources.chunksLabel')}
          columns={columns}
          data={items}
          getRowId={(c) => String(c.id)}
          maxHeight={480}
          emptyText={t('views.sources.noChunks')}
        />
      )}
    </QueryBlock>
  );
}

function Ts({ us }: { us: number | null }) {
  return <span className="num">{us === null ? '' : formatTimestamp(us)}</span>;
}

function AnomalyTable({ query, chunks }: { query: ListQuery<AnomalyInfo>; chunks: readonly ChunkInfo[] }) {
  const { t } = useTranslation();
  const names = useMemo(() => new Map(chunks.map((c) => [c.id, c.path])), [chunks]);
  const columns = useMemo<ColumnDef<AnomalyInfo, unknown>[]>(
    () => [
      {
        id: 'type',
        accessorFn: (a) => anomalyLabel(t, a.code),
        header: t('views.sources.anomalyCol.type'),
        size: 240,
        cell: ({ getValue }) => {
          const label = String(getValue());
          return (
            <span data-testid="truncatable" title={label} className="block truncate font-medium">
              {label}
            </span>
          );
        },
      },
      {
        id: 'where',
        accessorFn: (a) => a.chunk ?? -1,
        header: t('views.sources.anomalyCol.location'),
        size: 160,
        cell: ({ row }) => {
          const a = row.original;
          const path = a.chunk === null ? undefined : names.get(a.chunk);
          const where = anomalyWhere(t, a);
          return (
            <span data-testid="truncatable" title={path ?? where} className="block truncate">
              {where}
            </span>
          );
        },
      },
      {
        id: 'time',
        accessorFn: (a) => a.ts_us ?? Number.MAX_SAFE_INTEGER,
        header: t('views.sources.anomalyCol.time'),
        size: 168,
        cell: ({ row }) => <Ts us={row.original.ts_us} />,
      },
      {
        id: 'detail',
        accessorFn: (a) => anomalyDetail(t, a),
        header: t('views.sources.anomalyCol.detail'),
        size: 300,
        enableSorting: false,
        cell: ({ getValue }) => {
          const detail = String(getValue());
          return (
            <span data-testid="truncatable" title={detail} className="num block truncate text-muted">
              {detail}
            </span>
          );
        },
      },
    ],
    [t, names],
  );
  return (
    <QueryBlock query={query}>
      {(items) => (
        <DataTable
          ariaLabel={t('views.sources.anomalies')}
          columns={columns}
          data={items}
          getRowId={(a, i) => a.id ?? `${a.code}-${i}`}
          maxHeight={400}
          emptyText={t('views.sources.noAnomalies')}
        />
      )}
    </QueryBlock>
  );
}
