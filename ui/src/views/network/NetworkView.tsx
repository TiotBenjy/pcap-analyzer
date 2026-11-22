import { getRouteApi } from '@tanstack/react-router';
import type Graph from 'graphology';
import { Share2 } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { type GraphParams, NETWORK_PROTOCOLS } from '../../api/network';
import { useNetworkGraph } from '../../api/networkQueries';
import { useSession } from '../../api/sessionQueries';
import type { NetworkGraph } from '../../api/types/NetworkGraph';
import type { NetworkMode } from '../../api/types/NetworkMode';
import type { NetworkProtocol } from '../../api/types/NetworkProtocol';
import { ADDRESS_CATEGORIES, ADDRESS_CATEGORY_ORDER, OTHER_COLOR } from '../../charts/palette';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';
import { FilterBar } from '../../components/FilterBar';
import { PageHeader } from '../../components/PageHeader';
import { WholeFlowsNote } from '../../components/WholeFlowsNote';
import { SegmentedControl } from '../../components/SegmentedControl';
import { Skeleton } from '../../components/Skeleton';
import { Toggle } from '../../components/Toggle';
import { countryName } from '../../lib/countries';
import { formatBytes, formatCount } from '../../lib/format';
import { MD_QUERY, useMediaQuery } from '../../lib/useMediaQuery';
import { useTheme } from '../../theme/theme';
import { isViewable } from '../connections/session';
import { SessionGate } from '../connections/SessionGate';
import { useDebounced } from '../connections/useDebounced';
import type { Positions } from './forceLayout';
import { buildGraph, type EdgeAttributes, findNode, type NodeAttributes, type NodeLabels } from './graphModel';
import { computeLayout } from './layout';
import { NodePanel } from './NodePanel';
import { PairList } from './PairList';
import { SigmaGraph } from './SigmaGraph';
import { hasWebGL } from './webgl';

const route = getRouteApi('/sessions/$sessionId');

/** Links listed by the narrow and fallback layouts. */
const LISTED_PAIRS = 15;
/** Address categories of the legend (the others use the "Other" grey). */
const LEGEND = ADDRESS_CATEGORY_ORDER.slice(0, 7);

/** Network: graph of the communications between hosts, bounded and folded by the server. */
export default function NetworkView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const session = useSession(sessionId);
  return (
    <div className="flex flex-col gap-4">
      <PageHeader title={t('nav.items.network')} subtitle={session.data?.name ?? t('views.network.subtitle')} />
      <WholeFlowsNote />
      <SessionGate session={session}>
        <GraphCard sessionId={sessionId} enabled={isViewable(session.data)} />
      </SessionGate>
    </div>
  );
}

/** Group node texts, resolved once per language. */
function useNodeLabels(): NodeLabels {
  const { t, i18n } = useTranslation();
  return useMemo(() => {
    const lang = i18n.language;
    return {
      other: (count) => t('views.network.nodes.other', { count }),
      local: (count) => t('views.network.nodes.local', { count }),
      unknown: (count) => t('views.network.nodes.unknown', { count }),
      cluster: (country, count) => t('views.network.nodes.cluster', { country: countryName(country, lang), count }),
      country: (country, count) => t('views.network.nodes.country', { country: countryName(country, lang), count }),
    };
  }, [t, i18n.language]);
}

/**
 * Force layout of the drawn graph, computed off the main thread whenever the nodes or links
 * change (not when only the labels do). `null` while it runs.
 */
function useLayout(data: NetworkGraph | undefined, hideOrphans: boolean, run: boolean): Positions | null {
  const [state, setState] = useState<{ data: NetworkGraph; hideOrphans: boolean; positions: Positions } | null>(null);
  useEffect(() => {
    if (data === undefined || !run) return;
    let cancelled = false;
    const g = buildGraph(data, {
      hideOrphans,
      resolveNames: false,
      labels: { other: String, local: String, unknown: String, cluster: String, country: String },
    });
    const input = {
      nodes: g.mapNodes((id, a) => ({ id, x: a.x, y: a.y, size: a.size })),
      edges: g.mapEdges((_e, a, source, target) => ({ source, target, weight: a.bytes })),
    };
    void computeLayout(input).then((positions) => {
      if (!cancelled) setState({ data, hideOrphans, positions });
    });
    return () => {
      cancelled = true;
    };
  }, [data, hideOrphans, run]);
  return state !== null && state.data === data && state.hideOrphans === hideOrphans ? state.positions : null;
}

function GraphCard({ sessionId, enabled }: { sessionId: string; enabled: boolean }) {
  const { t, i18n } = useTranslation();
  const { theme } = useTheme();
  const lang = i18n.language;
  const [mode, setMode] = useState<NetworkMode>('hosts');
  const [protocols, setProtocols] = useState<ReadonlySet<NetworkProtocol>>(() => new Set(NETWORK_PROTOCOLS));
  const [hideOrphans, setHideOrphans] = useState(true);
  const [resolveNames, setResolveNames] = useState(true);
  const [ipv6, setIpv6] = useState(true);
  const [expand, setExpand] = useState<string | null>(null);
  // Explicit selection (click), tied to the search text it was made with: a new search selects
  // its best match instead.
  const [pick, setPick] = useState<{ id: string | null; query: string }>({ id: null, query: '' });
  const [search, setSearch] = useState('');
  const query = useDebounced(search);
  const wide = useMediaQuery(MD_QUERY);
  const webgl = useMemo(() => hasWebGL(), []);
  const labels = useNodeLabels();

  const params = useMemo<GraphParams>(
    () => ({
      mode,
      protocols: protocols.size === NETWORK_PROTOCOLS.length ? undefined : NETWORK_PROTOCOLS.filter((p) => protocols.has(p)),
      ipv6,
      includeOrphans: !hideOrphans,
      expand,
    }),
    [mode, protocols, ipv6, hideOrphans, expand],
  );
  const graphQuery = useNetworkGraph(sessionId, params, enabled);
  const data = graphQuery.data;
  const drawn = wide && webgl;
  // Orphans are a host notion: a country group without links (all its traffic inside) stays.
  const hide = hideOrphans && data?.mode !== 'countries';
  const positions = useLayout(data, hide, drawn);

  const graph = useMemo<Graph<NodeAttributes, EdgeAttributes> | null>(() => {
    if (data === undefined) return null;
    const g = buildGraph(data, { hideOrphans: hide, resolveNames, labels });
    if (positions !== null) {
      g.updateEachNodeAttributes((id, a) => ({ ...a, ...(positions[id] ?? {}) }));
    }
    return g;
  }, [data, hide, resolveNames, labels, positions]);

  // Search: the largest matching node is selected (panel) and centered (graph).
  const found = useMemo(() => (graph === null ? null : findNode(graph, query)), [graph, query]);
  const selected = pick.query === query ? pick.id : (found ?? pick.id);
  // A selection that left the graph (filters, mode) is dropped.
  const selectedNode = data?.nodes.find((n) => n.id === selected) ?? null;

  const onSelect = useCallback(
    (id: string | null) => {
      setPick({ id, query });
    },
    [query],
  );
  const onExpandNode = useCallback((id: string) => {
    if (id.startsWith('k:')) setExpand(id.slice(2));
  }, []);

  const counts = new Map(data?.protocols.map((p) => [p.protocol, p.conversations]) ?? []);
  const filters = NETWORK_PROTOCOLS.map((p) => ({
    id: p,
    label: t(`views.network.protocols.${p}`),
    count: counts.get(p) ?? 0,
    active: protocols.has(p),
  }));

  let body;
  if (graphQuery.isError) {
    body = (
      <ErrorState
        message={t('views.network.graph.loadError')}
        onRetry={() => {
          void graphQuery.refetch();
        }}
      />
    );
  } else if (data === undefined || graph === null || !enabled) {
    body = <Skeleton height={420} />;
  } else if (graph.order === 0) {
    body = <EmptyState icon={Share2} title={t('views.network.graph.empty')} />;
  } else {
    const chart = drawn ? (
      positions === null ? (
        <div role="status" aria-label={t('views.network.graph.layout')}>
          <Skeleton height={420} />
        </div>
      ) : (
        <SigmaGraph
          graph={graph}
          theme={theme}
          selected={selectedNode?.id ?? null}
          focus={found}
          onSelect={onSelect}
          onExpand={onExpandNode}
          ariaLabel={t('views.network.graph.chartLabel', { nodes: graph.order, edges: graph.size })}
          labels={{
            zoomIn: t('views.network.graph.zoomIn'),
            zoomOut: t('views.network.graph.zoomOut'),
            reset: t('views.network.graph.resetView'),
          }}
        />
      )
    ) : (
      <div className="flex min-w-0 flex-col gap-2">
        {wide && !webgl && <p className="text-meta text-muted">{t('views.network.graph.noWebgl')}</p>}
        <PairList
          data={data}
          hideOrphans={hide}
          resolveNames={resolveNames}
          labels={labels}
          limit={LISTED_PAIRS}
          selected={selectedNode?.id ?? null}
        />
      </div>
    );
    body = (
      <div className="grid min-w-0 grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_18rem]">
        {chart}
        <NodePanel
          sessionId={sessionId}
          data={data}
          node={selectedNode}
          labels={labels}
          resolveNames={resolveNames}
          clickable={drawn}
          onExpand={setExpand}
        />
      </div>
    );
  }

  const capped = data !== undefined && data.edges_total > data.edges.length;
  const filtered = protocols.size !== NETWORK_PROTOCOLS.length;
  const hasCluster = data?.nodes.some((n) => n.kind === 'cluster') ?? false;
  const noCountry = data?.mode === 'countries' && data.nodes.length > 0 && !data.nodes.some((n) => n.kind === 'country');
  return (
    <Card
      title={t('views.network.graph.title')}
      actions={
        <SegmentedControl
          hideLabel
          label={t('views.network.graph.mode')}
          value={mode}
          options={[
            { value: 'hosts', label: t('views.network.graph.hosts') },
            { value: 'countries', label: t('views.network.graph.countries') },
          ]}
          onChange={(v) => {
            setMode(v);
            setPick({ id: null, query });
          }}
        />
      }
      filters={
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          {/* Full width below md: the "Filters" menu spans the bar, not only its button. */}
          <div className="w-full min-w-0 md:w-auto">
            <FilterBar
              search={search}
              onSearch={setSearch}
              searchPlaceholder={t('views.network.graph.search')}
              filters={filters}
              onToggle={(id, active) => {
                const next = new Set(protocols);
                if (active) next.add(id as NetworkProtocol);
                else next.delete(id as NetworkProtocol);
                setProtocols(next);
              }}
              onSetAll={(active) => {
                setProtocols(new Set(active ? NETWORK_PROTOCOLS : []));
              }}
            />
          </div>
          <Toggle
            label={t('views.network.graph.hideOrphans')}
            checked={hideOrphans}
            {...(data === undefined || mode !== 'hosts' ? {} : { count: data.orphans })}
            disabled={mode !== 'hosts'}
            onChange={setHideOrphans}
          />
          <Toggle label={t('views.network.graph.resolveNames')} checked={resolveNames} onChange={setResolveNames} />
          <Toggle label={t('views.network.graph.ipv6')} checked={ipv6} onChange={setIpv6} />
        </div>
      }
    >
      <div className="flex flex-col gap-3">
        {data !== undefined && (
          <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 text-meta text-muted">
            <span data-testid="network-summary">
              {data.mode === 'hosts'
                ? t('views.network.graph.summary', {
                    shown: formatCount(data.hosts_shown),
                    hosts: formatCount(data.hosts),
                    count: data.edges.length,
                    bytes: formatBytes(data.total_bytes, lang),
                  })
                : t('views.network.graph.summaryCountries', {
                    hosts: formatCount(data.hosts),
                    count: data.edges.length,
                    bytes: formatBytes(data.total_bytes, lang),
                  })}
            </span>
            {filtered && <span>{t('views.network.graph.wholeConversations')}</span>}
            {noCountry && <span>{t('views.network.graph.noCountry')}</span>}
            {capped && <span>{t('views.network.graph.capped', { shown: data.edges.length, total: formatCount(data.edges_total) })}</span>}
            {query.trim() !== '' && found === null && <span>{t('views.network.graph.noMatch')}</span>}
            {expand !== null && mode === 'hosts' && (
              <Button
                variant="ghost"
                onClick={() => {
                  setExpand(null);
                }}
              >
                {t('views.network.graph.collapse', { country: countryName(expand, lang) })}
              </Button>
            )}
          </div>
        )}
        <div className="min-w-0">{body}</div>
        <ul aria-label={t('views.network.graph.legend')} className="flex flex-wrap gap-x-4 gap-y-1 text-meta text-muted">
          {LEGEND.map((c) => (
            <li key={c} className="inline-flex items-center gap-1.5">
              <span aria-hidden className="size-2.5 rounded-full" style={{ background: ADDRESS_CATEGORIES[c].color }} />
              {t(`addressCategories.${c}`)}
            </li>
          ))}
          <li className="inline-flex items-center gap-1.5">
            <span aria-hidden className="size-2.5 rounded-full" style={{ background: OTHER_COLOR }} />
            {t('views.network.graph.legendOther')}
          </li>
          {drawn && hasCluster && <li>{t('views.network.graph.expandHint')}</li>}
        </ul>
      </div>
    </Card>
  );
}
