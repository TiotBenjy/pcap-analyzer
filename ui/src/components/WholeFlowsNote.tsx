import { useTranslation } from 'react-i18next';
import { useViewRange } from '../app/timeRange';

/**
 * Under a time range, the views folded from flows (Connections, Network) count every flow active
 * in the range in full: its volumes include what it carried outside the range (ADR-030).
 */
export function WholeFlowsNote() {
  const { t } = useTranslation();
  const range = useViewRange();
  if (range === null) return null;
  return <p className="-mt-2 text-meta text-muted">{t('timeRange.wholeFlows')}</p>;
}
