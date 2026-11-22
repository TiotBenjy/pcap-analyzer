import { useTranslation } from 'react-i18next';
import type { NetworkGraph } from '../../api/types/NetworkGraph';
import { BarList } from '../../components/BarList';
import { formatBytes } from '../../lib/format';
import { cleanLabel, type NodeLabels, nodeColor, nodeText, nodeTitle, rankedPairs } from './graphModel';

interface PairListProps {
  data: NetworkGraph;
  hideOrphans: boolean;
  resolveNames: boolean;
  labels: NodeLabels;
  limit: number;
  /** Selected node (search): its links are highlighted. */
  selected: string | null;
}

/**
 * Links ranked by bytes, with bars split by direction: the layout below 768 px and when WebGL is
 * unavailable (same role as the ranked pairs of the Connections chord diagram).
 */
export function PairList({ data, hideOrphans, resolveNames, labels, limit, selected }: PairListProps) {
  const { t, i18n } = useTranslation();
  const pairs = rankedPairs(data, hideOrphans, limit);
  const lang = i18n.language;
  if (pairs.length === 0) return <p className="text-meta text-muted">{t('views.network.graph.noLinks')}</p>;
  return (
    <BarList
      ariaLabel={t('views.network.graph.listLabel')}
      items={pairs.map(({ edge, source, target }) => ({
        key: `${edge.source}|${edge.target}`,
        label: `${cleanLabel(nodeText(source, resolveNames, labels))} / ${cleanLabel(nodeText(target, resolveNames, labels))}`,
        title: [
          t('views.network.graph.aToB', { a: nodeTitle(source, labels), b: nodeTitle(target, labels), bytes: formatBytes(edge.bytes_fwd, lang) }),
          t('views.network.graph.aToB', { a: nodeTitle(target, labels), b: nodeTitle(source, labels), bytes: formatBytes(edge.bytes_rev, lang) }),
          edge.protocols.join(', '),
        ].join('\n'),
        mono: true,
        value: edge.bytes,
        valueText: formatBytes(edge.bytes, lang),
        segments: [
          { value: edge.bytes_fwd, color: nodeColor(source) },
          { value: edge.bytes_rev, color: nodeColor(target) },
        ],
        active: selected !== null && (edge.source === selected || edge.target === selected),
      }))}
    />
  );
}
