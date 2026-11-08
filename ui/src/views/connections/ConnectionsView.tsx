import { getRouteApi } from '@tanstack/react-router';
import type { ColumnDef } from '@tanstack/react-table';
import { Cable, Globe2, Search } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useConnectionStats, useConnectionTop, useConversations } from '../../api/connectionQueries';
import { TOP_SIZES, type TopSize } from '../../api/connections';
import { useSession } from '../../api/sessionQueries';
import type { ConnectionMatrix } from '../../api/types/ConnectionMatrix';
import type { ConversationInfo } from '../../api/types/ConversationInfo';
import type { CountrySide } from '../../api/types/CountrySide';
import { ADDRESS_CATEGORIES, ADDRESS_CATEGORY_ORDER, OTHER_COLOR } from '../../charts/palette';
import { Badge } from '../../components/Badge';
import { Card } from '../../components/Card';
import { DataTable } from '../../components/DataTable';
import { Endpoint } from '../../components/Endpoint';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';
import { Flag } from '../../components/Flag';
import { PageHeader } from '../../components/PageHeader';
import { SegmentedControl } from '../../components/SegmentedControl';
import { Skeleton } from '../../components/Skeleton';
import { Toggle } from '../../components/Toggle';
import { formatBytes, formatCount, formatDuration, formatTimestamp } from '../../lib/format';
import { useMediaQuery } from '../../lib/useMediaQuery';
import { ChordDiagram, type ChordNodeView } from './ChordDiagram';
import { countryName } from '../../lib/countries';
import { rankedPairs, truncateLabel } from './chordLayout';
import { LoadMore } from './LoadMore';
import { isViewable } from './session';
import { SessionGate } from './SessionGate';
import { useDebounced } from './useDebounced';

const route = getRouteApi('/sessions/$sessionId');

/** From this viewport width the chord diagram replaces the ranked list (spec). */
const MD_QUERY = '(min-width: 768px)';
/** Countries listed next to each other card. */
const TOP_COUNTRIES = 5;
/** Pairs listed by the narrow layout. */
const TOP_PAIRS = 10;

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

/** Connections: countries of the traffic, chord diagram of the top endpoints, conversations. */
export default function ConnectionsView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const session = useSession(sessionId);
  const viewable = isViewable(session.data);
  return (
    <div className="flex flex-col gap-4">
      <PageHeader title={t('nav.items.connections')} subtitle={session.data?.name ?? t('views.connections.subtitle')} />
      <SessionGate session={session}>
        <CountryCards sessionId={sessionId} enabled={viewable} />
        <ChordCard sessionId={sessionId} enabled={viewable} />
        <ConversationsCard sessionId={sessionId} enabled={viewable} />
      </SessionGate>
    </div>
  );
}

function CountryCards({ sessionId, enabled }: { sessionId: string; enabled: boolean }) {
  const { t } = useTranslation();
  const stats = useConnectionStats(sessionId, enabled);
  const sides = [
    { key: 'sources', title: t('views.connections.countries.sources'), hint: t('views.connections.countries.sourcesHint') },
    {
      key: 'destinations',
      title: t('views.connections.countries.destinations'),
      hint: t('views.connections.countries.destinationsHint'),
    },
  ] as const;
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      {sides.map((s) => (
        <Card key={s.key} title={s.title}>
          <p className="-mt-1 mb-3 text-meta text-muted">{s.hint}</p>
          {stats.isError ? (
            <ErrorState
              message={t('views.connections.countries.loadError')}
              onRetry={() => {
                void stats.refetch();
              }}
            />
          ) : stats.data === undefined ? (
            <Skeleton height={200} />
          ) : (
            <CountryList side={stats.data[s.key]} label={t('views.connections.countries.listLabel', { title: s.title })} />
          )}
        </Card>
      ))}
    </div>
  );
}

function CountryList({ side, label }: { side: CountrySide; label: string }) {
  const { t, i18n } = useTranslation();
  if (side.total_bytes === 0) return <EmptyState icon={Globe2} title={t('views.connections.countries.empty')} />;
  const top = side.countries.slice(0, TOP_COUNTRIES);
  const share = (bytes: number) => (side.total_bytes > 0 ? bytes / side.total_bytes : 0);
  const pct = (bytes: number) =>
    new Intl.NumberFormat(i18n.language, { style: 'percent', maximumFractionDigits: 1 }).format(share(bytes));
  const groups = [
    { key: 'unknown', label: t('views.connections.countries.unknown'), group: side.unknown },
    { key: 'local', label: t('views.connections.countries.local'), group: side.local },
  ].filter((g) => g.group.bytes > 0);
  return (
    <div className="flex flex-col gap-3">
      {top.length === 0 ? (
        <p className="text-muted">{t('views.connections.countries.noCountry')}</p>
      ) : (
        <ol aria-label={label} className="flex flex-col gap-2">
          {top.map((c) => {
            const name = countryName(c.country, i18n.language);
            return (
              <li key={c.country} className="flex min-w-0 flex-col gap-1">
                <div className="flex min-w-0 items-center gap-2">
                  <Flag country={c.country} />
                  <span data-testid="truncatable" title={`${name} (${c.country})`} className="min-w-0 flex-1 truncate">
                    {name}
                  </span>
                  <span className="num shrink-0 text-meta text-muted">
                    {t('views.connections.countries.hosts', { count: c.hosts })}
                  </span>
                  <span className="num w-20 shrink-0 text-right" title={pct(c.bytes)}>
                    {formatBytes(c.bytes)}
                  </span>
                </div>
                <div aria-hidden className="h-1.5 overflow-hidden rounded-full bg-subtle">
                  <div className="h-full rounded-full bg-accent" style={{ width: `${Math.max(1, share(c.bytes) * 100)}%` }} />
                </div>
              </li>
            );
          })}
        </ol>
      )}
      {groups.length > 0 && (
        <dl className="flex flex-col gap-1 border-t border-line pt-2 text-meta">
          {groups.map((g) => (
            <div key={g.key} className="flex min-w-0 items-center justify-between gap-2">
              <dt className="min-w-0 truncate text-muted" data-testid="truncatable" title={g.label}>
                {g.label}
              </dt>
              <dd className="num shrink-0">
                {formatBytes(g.group.bytes)}{' '}
                <span className="text-muted">({t('views.connections.countries.hosts', { count: g.group.hosts })})</span>
              </dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

/** Display data of the matrix nodes: label, category color and tooltip detail. */
function useChordNodes(data: ConnectionMatrix | undefined): ChordNodeView[] {
  const { t } = useTranslation();
  return useMemo(
    () =>
      (data?.nodes ?? []).map((n) =>
        n.endpoint === null
          ? { label: t('views.connections.chord.other'), color: OTHER_COLOR, detail: t('common.other') }
          : {
              label: n.endpoint.names[0] ?? n.endpoint.ip,
              color: ADDRESS_CATEGORIES[n.endpoint.category].color,
              detail: t(`addressCategories.${n.endpoint.category}`),
            },
      ),
    [data, t],
  );
}

function ChordCard({ sessionId, enabled }: { sessionId: string; enabled: boolean }) {
  const { t } = useTranslation();
  const [n, setN] = useState<TopSize>(10);
  const [dns, setDns] = useState(true);
  const top = useConnectionTop(sessionId, n, !dns, enabled);
  const wide = useMediaQuery(MD_QUERY);
  const [ref, width] = useElementWidth<HTMLDivElement>();
  const data = top.data;
  const nodes = useChordNodes(data);
  const legend = ADDRESS_CATEGORY_ORDER.slice(0, 6);
  const otherShown = data?.nodes.some((x) => x.endpoint === null || ADDRESS_CATEGORIES[x.endpoint.category].color === OTHER_COLOR);

  let body;
  if (top.isError) {
    body = (
      <ErrorState
        message={t('views.connections.chord.loadError')}
        onRetry={() => {
          void top.refetch();
        }}
      />
    );
  } else if (data === undefined || !enabled) {
    body = <Skeleton height={320} />;
  } else if (data.nodes.length === 0) {
    body = <EmptyState icon={Cable} title={t('views.connections.chord.empty')} />;
  } else {
    const chart =
      wide && width > 0 ? (
        <ChordDiagram
          matrix={data.matrix}
          nodes={nodes}
          width={width}
          ariaLabel={t('views.connections.chord.chartLabel', { count: data.nodes.length })}
        />
      ) : null;
    body = chart ?? <PairList data={data} nodes={nodes} />;
  }

  return (
    <Card
      title={t('views.connections.chord.title')}
      actions={
        <>
          <SegmentedControl
            hideLabel
            label={t('views.connections.chord.top')}
            value={String(n)}
            options={TOP_SIZES.map((s) => ({ value: String(s), label: t('views.connections.chord.topOption', { n: s }) }))}
            onChange={(v) => {
              setN(Number(v) as TopSize);
            }}
          />
          <Toggle label={t('views.connections.chord.includeDns')} checked={dns} onChange={setDns} />
        </>
      }
    >
      <div className="flex flex-col gap-3">
        {data !== undefined && data.nodes.length > 0 && (
          <p className="text-meta text-muted">
            {t('views.connections.chord.summary', { count: data.conversations, bytes: formatBytes(data.total_bytes) })}
          </p>
        )}
        <div ref={ref} className="min-w-0">
          {body}
        </div>
        <ul aria-label={t('views.connections.chord.legend')} className="flex flex-wrap gap-x-4 gap-y-1 text-meta text-muted">
          {legend.map((c) => (
            <li key={c} className="inline-flex items-center gap-1.5">
              <span aria-hidden className="size-2.5 rounded-sm" style={{ background: ADDRESS_CATEGORIES[c].color }} />
              {t(`addressCategories.${c}`)}
            </li>
          ))}
          {otherShown === true && (
            <li className="inline-flex items-center gap-1.5">
              <span aria-hidden className="size-2.5 rounded-sm" style={{ background: OTHER_COLOR }} />
              {t('common.other')}
            </li>
          )}
        </ul>
      </div>
    </Card>
  );
}

/** Narrow layout of the matrix: pairs of endpoints ranked by bytes, with bars. */
function PairList({ data, nodes }: { data: ConnectionMatrix; nodes: readonly ChordNodeView[] }) {
  const { t } = useTranslation();
  const pairs = rankedPairs(data.matrix).slice(0, TOP_PAIRS);
  const max = Math.max(1, ...pairs.map((p) => p.ab + p.ba));
  return (
    <ol aria-label={t('views.connections.chord.listLabel')} className="flex flex-col gap-2.5">
      {pairs.map((p) => {
        const a = nodes[p.a];
        const b = nodes[p.b];
        const title = [
          t('views.connections.chord.aToB', { a: a?.label ?? '', b: b?.label ?? '', bytes: formatBytes(p.ab) }),
          ...(p.a === p.b ? [] : [t('views.connections.chord.aToB', { a: b?.label ?? '', b: a?.label ?? '', bytes: formatBytes(p.ba) })]),
        ].join('\n');
        return (
          <li key={`${p.a}-${p.b}`} className="flex min-w-0 flex-col gap-1">
            <div className="flex min-w-0 items-center gap-2 text-meta">
              <span data-testid="truncatable" title={title} className="min-w-0 flex-1 truncate font-mono">
                {truncateLabel(a?.label ?? '')} / {truncateLabel(b?.label ?? '')}
              </span>
              <span className="num shrink-0">{formatBytes(p.ab + p.ba)}</span>
            </div>
            <div aria-hidden className="flex h-1.5 overflow-hidden rounded-full bg-subtle">
              <div style={{ width: `${(p.ab / max) * 100}%`, background: a?.color ?? OTHER_COLOR }} />
              <div style={{ width: `${(p.ba / max) * 100}%`, background: b?.color ?? OTHER_COLOR }} />
            </div>
          </li>
        );
      })}
    </ol>
  );
}

function FilterInput({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
  return (
    <label className="relative flex h-8 min-w-0 flex-1 basis-40 items-center sm:max-w-56">
      <span className="sr-only">{label}</span>
      <Search aria-hidden size={16} strokeWidth={1.75} className="pointer-events-none absolute left-2.5 text-faint" />
      <input
        type="search"
        value={value}
        placeholder={label}
        onChange={(e) => {
          onChange(e.target.value);
        }}
        className="h-8 w-full min-w-0 rounded-md border border-line bg-surface pr-2 pl-8 text-body placeholder:text-faint"
      />
    </label>
  );
}

function ConversationsCard({ sessionId, enabled }: { sessionId: string; enabled: boolean }) {
  const { t, i18n } = useTranslation();
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const filters = useDebounced(useMemo(() => ({ from, to }), [from, to]));
  const list = useConversations(sessionId, filters, enabled);
  const rows = useMemo(() => list.data?.pages.flatMap((p) => p.items) ?? [], [list.data]);
  const total = list.data?.pages[0]?.total_estimate ?? null;
  const lang = i18n.language;

  const columns = useMemo<ColumnDef<ConversationInfo>[]>(
    () => [
      {
        id: 'from',
        header: t('views.connections.table.from'),
        size: 200,
        cell: ({ row }) => <Endpoint endpoint={row.original.src} />,
      },
      {
        id: 'to',
        header: t('views.connections.table.to'),
        size: 200,
        cell: ({ row }) => <Endpoint endpoint={row.original.dst} />,
      },
      {
        id: 'bytes',
        header: t('views.connections.table.bytes'),
        size: 96,
        meta: { align: 'right' },
        cell: ({ row }) => <span className="num">{formatBytes(row.original.bytes_total, lang)}</span>,
      },
      {
        id: 'sent',
        header: () => <span title={t('views.connections.table.sentTitle')}>{t('views.connections.table.sent')}</span>,
        size: 96,
        meta: { align: 'right' },
        cell: ({ row }) => <span className="num text-muted">{formatBytes(row.original.bytes_fwd, lang)}</span>,
      },
      {
        id: 'received',
        header: () => <span title={t('views.connections.table.receivedTitle')}>{t('views.connections.table.received')}</span>,
        size: 96,
        meta: { align: 'right' },
        cell: ({ row }) => <span className="num text-muted">{formatBytes(row.original.bytes_rev, lang)}</span>,
      },
      {
        id: 'packets',
        header: t('views.connections.table.packets'),
        size: 88,
        meta: { align: 'right' },
        cell: ({ row }) => <span className="num">{formatCount(row.original.packets_total)}</span>,
      },
      {
        id: 'flows',
        header: t('views.connections.table.flows'),
        size: 64,
        meta: { align: 'right' },
        cell: ({ row }) => <span className="num">{formatCount(row.original.flows)}</span>,
      },
      {
        id: 'protocols',
        header: t('views.connections.table.protocols'),
        size: 150,
        cell: ({ row }) => {
          const text = row.original.protocols.join(', ');
          return (
            <span data-testid="truncatable" title={text} className="block truncate">
              {text}
            </span>
          );
        },
      },
      {
        id: 'duration',
        header: t('views.connections.table.duration'),
        size: 100,
        meta: { align: 'right' },
        cell: ({ row }) => <span className="num">{formatDuration(row.original.duration_us / 1e6, lang)}</span>,
      },
      {
        id: 'first',
        header: t('views.connections.table.first'),
        size: 160,
        cell: ({ row }) => <span className="num">{formatTimestamp(row.original.first_ts_us)}</span>,
      },
      {
        id: 'last',
        header: t('views.connections.table.last'),
        size: 160,
        cell: ({ row }) => <span className="num">{formatTimestamp(row.original.last_ts_us)}</span>,
      },
    ],
    [t, lang],
  );
  // The server sorts (bytes, descending): client-side sorting of a partial list would mislead.
  const unsorted = useMemo(() => columns.map((c) => ({ ...c, enableSorting: false })), [columns]);
  const filtered = from.trim() !== '' || to.trim() !== '';

  return (
    <Card
      title={
        <span className="inline-flex items-center gap-2">
          {t('views.connections.table.title')}
          {total !== null && <Badge>{formatCount(total)}</Badge>}
        </span>
      }
      actions={
        <div className="flex w-full min-w-0 flex-wrap gap-2 sm:w-auto">
          <FilterInput label={t('views.connections.table.fromFilter')} value={from} onChange={setFrom} />
          <FilterInput label={t('views.connections.table.toFilter')} value={to} onChange={setTo} />
        </div>
      }
      flush
    >
      {list.isError ? (
        <ErrorState
          message={t('views.connections.table.loadError')}
          onRetry={() => {
            void list.refetch();
          }}
        />
      ) : list.data === undefined ? (
        <div className="p-3 sm:p-4">
          <Skeleton height={240} />
        </div>
      ) : (
        <>
          <DataTable
            columns={unsorted}
            data={rows}
            getRowId={(r) => r.id}
            ariaLabel={t('views.connections.table.label')}
            emptyText={filtered ? t('views.connections.table.noMatch') : t('views.connections.table.empty')}
          />
          <LoadMore
            shown={rows.length}
            total={total}
            hasMore={list.hasNextPage}
            loading={list.isFetchingNextPage}
            onMore={() => {
              void list.fetchNextPage();
            }}
          />
        </>
      )}
    </Card>
  );
}
