import { MousePointerClick } from 'lucide-react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useNetworkNode } from '../../api/networkQueries';
import type { NetworkGraph } from '../../api/types/NetworkGraph';
import type { NetworkNode } from '../../api/types/NetworkNode';
import { Badge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Endpoint } from '../../components/Endpoint';
import { ErrorState } from '../../components/ErrorState';
import { Flag } from '../../components/Flag';
import { Skeleton } from '../../components/Skeleton';
import { countryName } from '../../lib/countries';
import { formatBytes, formatCount, formatTimestamp } from '../../lib/format';
import { cleanLabel, type NodeLabels, neighborsOf, nodeText } from './graphModel';

/** Neighbors listed for a group node (host nodes get theirs from the API). */
const GROUP_NEIGHBORS = 10;

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 items-baseline justify-between gap-3">
      <dt className="shrink-0 text-muted">{label}</dt>
      <dd className="min-w-0 text-right [overflow-wrap:anywhere]">{children}</dd>
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex min-w-0 flex-col gap-1.5 border-t border-line pt-3">
      <h3 className="text-meta font-medium text-muted">{title}</h3>
      {children}
    </section>
  );
}

interface NodePanelProps {
  sessionId: string;
  data: NetworkGraph;
  node: NetworkNode | null;
  labels: NodeLabels;
  resolveNames: boolean;
  /** Nodes can be clicked (graph drawn); otherwise only the search selects. */
  clickable: boolean;
  onExpand: (country: string) => void;
}

/** Detail of the selected node; a hint and the graph figures when nothing is selected. */
export function NodePanel({ sessionId, data, node, labels, resolveNames, clickable, onExpand }: NodePanelProps) {
  const { t, i18n } = useTranslation();
  if (node === null) {
    return (
      <aside aria-label={t('views.network.panel.title')} className="flex min-w-0 flex-col gap-3 text-meta">
        <p className="flex items-start gap-2 text-muted">
          <MousePointerClick aria-hidden size={16} strokeWidth={1.75} className="mt-0.5 shrink-0" />
          {clickable ? t('views.network.panel.hint') : t('views.network.panel.hintSearch')}
        </p>
        <dl className="flex flex-col gap-1">
          <Row label={t('views.network.panel.hostsTotal')}>
            <span className="num">{formatCount(data.hosts)}</span>
          </Row>
          {data.mode === 'hosts' && (
            <Row label={t('views.network.panel.hostsShown')}>
              <span className="num">{formatCount(data.hosts_shown)}</span>
            </Row>
          )}
          <Row label={t('views.network.panel.links')}>
            <span className="num">{formatCount(data.edges.length)}</span>
          </Row>
          <Row label={t('views.network.panel.bytes')}>
            <span className="num">{formatBytes(data.total_bytes, i18n.language)}</span>
          </Row>
        </dl>
      </aside>
    );
  }
  return (
    <aside aria-label={t('views.network.panel.title')} className="flex min-w-0 flex-col gap-3 text-meta">
      {node.kind === 'host' && node.endpoint !== null ? (
        <HostDetail sessionId={sessionId} node={node} resolveNames={resolveNames} />
      ) : (
        <GroupDetail data={data} node={node} labels={labels} resolveNames={resolveNames} onExpand={onExpand} />
      )}
    </aside>
  );
}

function Protocols({ list }: { list: readonly string[] }) {
  const { t } = useTranslation();
  if (list.length === 0) return <p className="text-muted">{t('views.network.panel.none')}</p>;
  return (
    <ul className="flex flex-wrap gap-1">
      {list.map((p) => (
        <li key={p}>
          <Badge className="uppercase">{p}</Badge>
        </li>
      ))}
    </ul>
  );
}

function HostDetail({ sessionId, node, resolveNames }: { sessionId: string; node: NetworkNode; resolveNames: boolean }) {
  const { t, i18n } = useTranslation();
  const detail = useNetworkNode(sessionId, node.endpoint?.ip ?? null);
  const endpoint = node.endpoint;
  if (endpoint === null) return null;
  const lang = i18n.language;
  const d = detail.data;
  return (
    <>
      <div className="flex min-w-0 flex-col gap-1">
        <Endpoint endpoint={endpoint} className="text-body font-medium" />
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge>{t(`addressCategories.${endpoint.category}`)}</Badge>
          {endpoint.country !== null && (
            <span className="inline-flex items-center gap-1 text-muted">
              <Flag country={endpoint.country} />
              {countryName(endpoint.country, lang)}
            </span>
          )}
        </div>
      </div>
      <dl className="flex flex-col gap-1">
        {endpoint.names.length > 0 && (
          <>
            <Row label={t('views.network.panel.address')}>
              <span className="font-mono">{endpoint.ip}</span>
            </Row>
            <Row label={t('views.network.panel.names')}>{endpoint.names.map((n) => cleanLabel(n, 253)).join(', ')}</Row>
          </>
        )}
        <Row label={t('views.network.panel.sentInGraph')}>
          <span className="num">{formatBytes(node.bytes_sent, lang)}</span>
        </Row>
        <Row label={t('views.network.panel.receivedInGraph')}>
          <span className="num">{formatBytes(node.bytes_received, lang)}</span>
        </Row>
      </dl>
      {detail.isError ? (
        <ErrorState
          message={t('views.network.panel.loadError')}
          onRetry={() => {
            void detail.refetch();
          }}
        />
      ) : d === undefined ? (
        <Skeleton height={160} />
      ) : (
        <>
          <dl className="flex flex-col gap-1">
            {d.macs.length > 0 && (
              <Row label={t('views.network.panel.macs')}>
                <span className="font-mono">{d.macs.join(', ')}</span>
              </Row>
            )}
            <Row label={t('views.network.panel.sent')}>
              <span className="num">{formatBytes(d.bytes_sent, lang)}</span>
            </Row>
            <Row label={t('views.network.panel.received')}>
              <span className="num">{formatBytes(d.bytes_received, lang)}</span>
            </Row>
            <Row label={t('views.network.panel.packets')}>
              <span className="num">{formatCount(d.packets_sent + d.packets_received)}</span>
            </Row>
            <Row label={t('views.network.panel.peers')}>
              <span className="num">{formatCount(d.peers)}</span>
            </Row>
            {d.first_ts_us !== null && (
              <Row label={t('views.network.panel.first')}>
                <span className="num">{formatTimestamp(d.first_ts_us)}</span>
              </Row>
            )}
            {d.last_ts_us !== null && (
              <Row label={t('views.network.panel.last')}>
                <span className="num">{formatTimestamp(d.last_ts_us)}</span>
              </Row>
            )}
          </dl>
          <Section title={t('views.network.panel.protocols')}>
            <Protocols list={d.protocols} />
          </Section>
          <Section title={t('views.network.panel.ports')}>
            {d.open_ports.length === 0 ? (
              <p className="text-muted">{t('views.network.panel.none')}</p>
            ) : (
              <ul className="flex flex-wrap gap-1">
                {d.open_ports.map((p) => (
                  <li key={`${p.transport}-${p.port}`}>
                    <Badge {...(p.service === null ? {} : { title: p.service })}>
                      <span className="font-mono">
                        {p.port}/{p.transport}
                      </span>
                    </Badge>
                  </li>
                ))}
              </ul>
            )}
          </Section>
          <Section title={t('views.network.panel.neighbors')}>
            {d.neighbors.length === 0 ? (
              <p className="text-muted">{t('views.network.panel.none')}</p>
            ) : (
              <ol aria-label={t('views.network.panel.neighbors')} className="flex flex-col gap-1">
                {d.neighbors.map((n) => (
                  <li key={n.endpoint.ip} className="flex min-w-0 items-center justify-between gap-2">
                    <Endpoint endpoint={n.endpoint} showName={resolveNames} className="min-w-0" />
                    <span className="num shrink-0 text-muted">{formatBytes(n.bytes_sent + n.bytes_received, lang)}</span>
                  </li>
                ))}
              </ol>
            )}
          </Section>
        </>
      )}
    </>
  );
}

interface GroupDetailProps {
  data: NetworkGraph;
  node: NetworkNode;
  labels: NodeLabels;
  resolveNames: boolean;
  onExpand: (country: string) => void;
}

function GroupDetail({ data, node, labels, resolveNames, onExpand }: GroupDetailProps) {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  const neighbors = neighborsOf(data, node.id, GROUP_NEIGHBORS);
  const title = nodeText(node, resolveNames, labels);
  return (
    <>
      <div className="flex min-w-0 items-center gap-1.5">
        {node.country !== null && <Flag country={node.country} />}
        <span data-testid="truncatable" title={title} className="min-w-0 truncate text-body font-medium">
          {title}
        </span>
      </div>
      <p className="text-muted">{t(`views.network.kinds.${node.kind}`)}</p>
      <dl className="flex flex-col gap-1">
        <Row label={t('views.network.panel.hosts')}>
          <span className="num">{formatCount(node.hosts)}</span>
        </Row>
        <Row label={t('views.network.panel.sentInGraph')}>
          <span className="num">{formatBytes(node.bytes_sent, lang)}</span>
        </Row>
        <Row label={t('views.network.panel.receivedInGraph')}>
          <span className="num">{formatBytes(node.bytes_received, lang)}</span>
        </Row>
        <Row label={t('views.network.panel.packets')}>
          <span className="num">{formatCount(node.packets)}</span>
        </Row>
      </dl>
      {node.kind === 'cluster' && node.country !== null && (
        <Button
          variant="secondary"
          onClick={() => {
            if (node.country !== null) onExpand(node.country);
          }}
        >
          {t('views.network.panel.expand')}
        </Button>
      )}
      <Section title={t('views.network.panel.protocols')}>
        <Protocols list={node.protocols} />
      </Section>
      <Section title={t('views.network.panel.neighbors')}>
        {neighbors.length === 0 ? (
          <p className="text-muted">{t('views.network.panel.none')}</p>
        ) : (
          <ol aria-label={t('views.network.panel.neighbors')} className="flex flex-col gap-1">
            {neighbors.map((n) => {
              const text = nodeText(n.node, resolveNames, labels);
              return (
                <li key={n.node.id} className="flex min-w-0 items-center justify-between gap-2">
                  {n.node.endpoint !== null ? (
                    <Endpoint endpoint={n.node.endpoint} showName={resolveNames} className="min-w-0" />
                  ) : (
                    <span data-testid="truncatable" title={text} className="min-w-0 truncate">
                      {text}
                    </span>
                  )}
                  <span className="num shrink-0 text-muted">{formatBytes(n.edge.bytes, lang)}</span>
                </li>
              );
            })}
          </ol>
        )}
      </Section>
    </>
  );
}
