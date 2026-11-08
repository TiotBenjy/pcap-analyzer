import { X } from 'lucide-react';
import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import type { HttpCount } from '../../api/types/HttpCount';
import type { HttpTransactionSummary } from '../../api/types/HttpTransactionSummary';
import { Badge } from '../../components/Badge';
import { Card } from '../../components/Card';
import { Chart } from '../../components/Chart';
import { Endpoint } from '../../components/Endpoint';
import { formatCount } from '../../lib/format';
import { barColor, barsHeight, barsOption, type ChartFormat, DONUT_CENTER_Y, DONUT_MAX, donutOption, METHOD_COLORS, PART_HEIGHT } from './charts';
import { displayTarget, statusTone } from './format';

/** Methods chart: donut up to five groups, horizontal bars beyond; total in the donut. */
export function MethodsChart({
  counts,
  loading,
  error,
  onRetry,
}: {
  counts: readonly HttpCount[] | undefined;
  loading: boolean;
  error: boolean;
  onRetry: () => void;
}) {
  const { t } = useTranslation();
  const fmt = useMemo<ChartFormat>(
    () => ({ count: formatCount, label: (k) => (k === 'other' ? t('views.http.otherMethods') : k) }),
    [t],
  );
  const list = useMemo(() => counts ?? [], [counts]);
  const donut = list.length <= DONUT_MAX;
  const option = useMemo(
    () => (donut ? donutOption(list, METHOD_COLORS, fmt) : barsOption(list, barColor, fmt)),
    [donut, list, fmt],
  );
  const total = list.reduce((s, c) => s + c.count, 0);
  const height = donut ? PART_HEIGHT : barsHeight(list.length);
  return (
    <Card title={t('views.http.methods')}>
      <div className="relative">
        <Chart
          option={option}
          height={height}
          ariaLabel={t('views.http.methodsLabel')}
          loading={loading}
          error={error ? t('views.http.loadError') : null}
          onRetry={onRetry}
          empty={!loading && !error && list.length === 0}
          emptyText={t('views.http.noTransactions')}
        />
        {donut && !loading && !error && list.length > 0 && (
          <div
            className="pointer-events-none absolute left-1/2 flex -translate-x-1/2 -translate-y-1/2 flex-col items-center"
            style={{ top: DONUT_CENTER_Y }}
          >
            <span className="num text-card font-semibold">{formatCount(total)}</span>
            <span className="text-meta text-muted">{t('views.http.requests', { count: total })}</span>
          </div>
        )}
      </div>
    </Card>
  );
}

/** Removable filter chip (host, status...). */
export function FilterChip({ label, onRemove, removeLabel }: { label: string; onRemove: () => void; removeLabel: string }) {
  return (
    <span className="inline-flex h-8 max-w-full min-w-0 items-center gap-1 rounded-md border border-accent bg-accent-soft pr-1 pl-2.5">
      <span data-testid="truncatable" title={label} className="min-w-0 truncate">
        {label}
      </span>
      <button
        type="button"
        aria-label={removeLabel}
        title={removeLabel}
        onClick={onRemove}
        className="inline-flex size-6 shrink-0 items-center justify-center rounded text-muted hover:bg-subtle hover:text-fg"
      >
        <X aria-hidden size={14} strokeWidth={1.75} />
      </button>
    </span>
  );
}

export function MethodBadge({ method }: { method: string | null }) {
  const { t } = useTranslation();
  return <Badge className="font-mono">{method ?? t('views.http.noRequestShort')}</Badge>;
}

export function StatusBadge({ status }: { status: number | null }) {
  const { t } = useTranslation();
  return (
    <Badge tone={statusTone(status)} {...(status === null ? { title: t('views.http.noResponse') } : {})}>
      {status ?? '-'}
    </Badge>
  );
}

export function TargetText({ tx }: { tx: HttpTransactionSummary }) {
  const target = displayTarget(tx);
  return (
    <span data-testid="truncatable" title={target} className="block min-w-0 truncate font-mono text-meta">
      {target === '' ? '-' : target}
    </span>
  );
}

/** Server address and port, after the host asked for (when it differs from the address). */
export function ServerCell({ tx }: { tx: HttpTransactionSummary }) {
  const host = tx.host !== null && tx.host !== '' && tx.host !== tx.server.ip ? tx.host : null;
  return (
    <span className="flex min-w-0 items-center gap-1.5">
      {host !== null && (
        <span data-testid="truncatable" title={host} className="min-w-0 shrink truncate">
          {host}
        </span>
      )}
      <Endpoint endpoint={tx.server} port={tx.server_port} showName={false} className="shrink-[2] text-meta" />
    </span>
  );
}
