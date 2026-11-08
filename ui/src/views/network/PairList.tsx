import { useTranslation } from 'react-i18next';
import type { NetworkGraph } from '../../api/types/NetworkGraph';
import { formatBytes } from '../../lib/format';
import { cleanLabel, type NodeLabels, nodeColor, nodeText, nodeTitle, rankedPairs } from './graphModel';

interface PairListProps {
  data: NetworkGraph;
  hideOrphans: boolean;
  resolveNames: boolean;
  labels: NodeLabels;
  limit: number;
}

/**
 * Links ranked by bytes, with bars split by direction: the layout below 768 px and when WebGL is
 * unavailable (same role as the ranked pairs of the Connections chord diagram).
 */
export function PairList({ data, hideOrphans, resolveNames, labels, limit }: PairListProps) {
  const { t, i18n } = useTranslation();
  const pairs = rankedPairs(data, hideOrphans, limit);
  const max = Math.max(1, ...pairs.map((p) => p.edge.bytes));
  const lang = i18n.language;
  if (pairs.length === 0) return <p className="text-meta text-muted">{t('views.network.graph.noLinks')}</p>;
  return (
    <ol aria-label={t('views.network.graph.listLabel')} className="flex flex-col gap-2.5">
      {pairs.map(({ edge, source, target }) => {
        const a = cleanLabel(nodeText(source, resolveNames, labels));
        const b = cleanLabel(nodeText(target, resolveNames, labels));
        const title = [
          t('views.network.graph.aToB', { a: nodeTitle(source, labels), b: nodeTitle(target, labels), bytes: formatBytes(edge.bytes_fwd, lang) }),
          t('views.network.graph.aToB', { a: nodeTitle(target, labels), b: nodeTitle(source, labels), bytes: formatBytes(edge.bytes_rev, lang) }),
          edge.protocols.join(', '),
        ].join('\n');
        return (
          <li key={`${edge.source}|${edge.target}`} className="flex min-w-0 flex-col gap-1">
            <div className="flex min-w-0 items-center gap-2 text-meta">
              <span data-testid="truncatable" title={title} className="min-w-0 flex-1 truncate font-mono">
                {a} / {b}
              </span>
              <span className="num shrink-0">{formatBytes(edge.bytes, lang)}</span>
            </div>
            <div aria-hidden className="flex h-1.5 overflow-hidden rounded-full bg-subtle">
              <div style={{ width: `${(edge.bytes_fwd / max) * 100}%`, background: nodeColor(source) }} />
              <div style={{ width: `${(edge.bytes_rev / max) * 100}%`, background: nodeColor(target) }} />
            </div>
          </li>
        );
      })}
    </ol>
  );
}
