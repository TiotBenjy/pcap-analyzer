import { ChevronDown, ShieldCheck, TriangleAlert } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { ArpConflict } from '../../api/types/ArpConflict';
import type { ArpConflicts } from '../../api/types/ArpConflicts';
import type { ArpSign } from '../../api/types/ArpSign';
import { useViewRange } from '../../app/timeRange';
import { Badge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { CopyButton } from '../../components/CopyButton';
import { EmptyState } from '../../components/EmptyState';
import { Endpoint } from '../../components/Endpoint';
import { ErrorState } from '../../components/ErrorState';
import { Skeleton } from '../../components/Skeleton';
import { cn } from '../../lib/cn';
import { formatPeriod } from '../../lib/format';

/** Signs that point to spoofing rather than to an ordinary change (written in the warning tone). */
const STRONG_SIGNS: ReadonlySet<ArpSign> = new Set<ArpSign>(['unsolicited', 'multiple_ips']);
const CONFIRM_STEPS = ['owner', 'table', 'gateway', 'host'] as const;

interface ConflictsCardProps {
  query: { data?: ArpConflicts | undefined; isPending: boolean; isError: boolean; refetch: () => unknown };
  /** Unsolicited replies of the session or range (a note when there is no conflict). */
  unsolicited: number;
  onShowMessages: (ip: string) => void;
  onShowUnsolicited: () => void;
  className?: string;
}

/** IP addresses claimed by several MAC addresses, with their signs explained. */
export function ConflictsCard({ query, unsolicited, onShowMessages, onShowUnsolicited, className }: ConflictsCardProps) {
  const { t } = useTranslation();
  let body;
  if (query.isPending) body = <Skeleton height={160} />;
  else if (query.isError || query.data === undefined)
    body = <ErrorState message={t('views.arp.loadError')} onRetry={() => void query.refetch()} />;
  else {
    const { items, total } = query.data;
    body = (
      <div className="flex min-w-0 flex-col gap-3">
        {items.length === 0 ? (
          <EmptyState icon={ShieldCheck} title={t('views.arp.conflicts.empty')} />
        ) : (
          <ul aria-label={t('views.arp.conflicts.title')} className="flex min-w-0 flex-col divide-y divide-line">
            {items.map((c) => (
              <ConflictItem key={c.ip.ip} conflict={c} onShowMessages={onShowMessages} />
            ))}
          </ul>
        )}
        {total > items.length && (
          <p className="text-meta text-muted">{t('views.arp.conflicts.shown', { shown: items.length, total })}</p>
        )}
        {unsolicited > 0 && items.length === 0 && (
          <div role="note" className="flex min-w-0 flex-wrap items-center gap-2 rounded-md border border-line px-3 py-2 text-meta">
            <TriangleAlert aria-hidden size={16} strokeWidth={1.75} className="shrink-0 text-warning" />
            <p className="min-w-0 flex-1">{t('views.arp.conflicts.unsolicitedNote', { count: unsolicited })}</p>
            <Button variant="ghost" onClick={onShowUnsolicited}>
              {t('views.arp.conflicts.showUnsolicited')}
            </Button>
          </div>
        )}
        {(items.length > 0 || unsolicited > 0) && <ConfirmHelp />}
      </div>
    );
  }
  return (
    <Card title={t('views.arp.conflicts.title')} {...(className === undefined ? {} : { className })}>
      {body}
    </Card>
  );
}

function ConflictItem({ conflict: c, onShowMessages }: { conflict: ArpConflict; onShowMessages: (ip: string) => void }) {
  const { t } = useTranslation();
  // Under a range, the period and counters of each MAC address are those of its folded binding.
  const ranged = useViewRange() !== null;
  return (
    <li className="flex min-w-0 flex-col gap-2 py-3 first:pt-0 last:pb-0" data-testid="arp-conflict">
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <span className="min-w-0 font-medium">
          <Endpoint endpoint={c.ip} show="both" />
        </span>
        <Badge tone="warning">{t('views.arp.conflicts.macs', { count: c.mac_count })}</Badge>
        <Button
          variant="ghost"
          className="ml-auto"
          onClick={() => {
            onShowMessages(c.ip.ip);
          }}
        >
          {t('views.arp.conflicts.showMessages')}
        </Button>
      </div>
      <ul className="flex min-w-0 flex-col gap-1">
        {c.macs.map((m) => (
          <li key={m.mac} className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-0.5 text-meta">
            <span className="inline-flex min-w-0 items-center">
              <span data-testid="truncatable" title={m.mac} className="truncate font-mono text-table">
                {m.mac}
              </span>
              <CopyButton value={m.mac} name={t('views.arp.mac')} />
            </span>
            {ranged && <span className="text-faint">{t('timeRange.wholeSession')}</span>}
            <span className="num text-muted">{t('views.arp.conflicts.seen', { period: formatPeriod(m.first_ts_us, m.last_ts_us) })}</span>
            <span className="num text-muted">{t('views.arp.conflicts.messages', { count: m.messages })}</span>
            {m.gratuitous > 0 && <span className="num text-muted">{t('views.arp.conflicts.gratuitous', { count: m.gratuitous })}</span>}
            {m.unsolicited > 0 && (
              <span className="num text-warning">{t('views.arp.conflicts.unsolicited', { count: m.unsolicited })}</span>
            )}
            {m.other_ips > 0 && <span className="num text-warning">{t('views.arp.conflicts.otherIps', { count: m.other_ips })}</span>}
          </li>
        ))}
      </ul>
      <ul className="flex min-w-0 flex-col gap-1 text-meta" aria-label={t('views.arp.conflicts.title')}>
        {c.signs.map((s) => (
          <li key={s} className="min-w-0">
            <span className={cn('font-medium', STRONG_SIGNS.has(s) ? 'text-warning' : 'text-fg')}>{t(`views.arp.sign.${s}`)}</span>
            <span className="text-muted">{` ${t(`views.arp.signText.${s}`)}`}</span>
          </li>
        ))}
      </ul>
    </li>
  );
}

function ConfirmHelp() {
  const { t } = useTranslation();
  return (
    <details className="group rounded-md border border-line" data-testid="arp-confirm">
      <summary className="flex min-h-8 cursor-pointer list-none items-center gap-1.5 px-3 py-1.5 text-body font-medium [&::-webkit-details-marker]:hidden">
        <ChevronDown aria-hidden size={16} strokeWidth={1.75} className="shrink-0 -rotate-90 text-faint group-open:rotate-0" />
        {t('views.arp.confirm.title')}
      </summary>
      <ol className="flex list-decimal flex-col gap-1 border-t border-line py-2 pr-3 pl-8 text-meta text-muted">
        {CONFIRM_STEPS.map((s) => (
          <li key={s}>{t(`views.arp.confirm.steps.${s}`)}</li>
        ))}
      </ol>
    </details>
  );
}
