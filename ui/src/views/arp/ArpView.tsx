import { getRouteApi } from '@tanstack/react-router';
import { Cable, Network, ShieldAlert, TriangleAlert, Waypoints } from 'lucide-react';
import { useCallback, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useArpConflicts, useArpStats } from '../../api/arpQueries';
import { useSession } from '../../api/sessionQueries';
import type { ArpStats } from '../../api/types/ArpStats';
import { useViewRange } from '../../app/timeRange';
import { Badge } from '../../components/Badge';
import { type BarItem, BarList } from '../../components/BarList';
import { Card } from '../../components/Card';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';
import { PageHeader } from '../../components/PageHeader';
import { Skeleton } from '../../components/Skeleton';
import { StatCard } from '../../components/StatCard';
import { formatCount, sameLocalDay } from '../../lib/format';
import { isViewable } from '../connections/session';
import { SessionGate } from '../connections/SessionGate';
import { BindingsCard } from './BindingsCard';
import { ConflictsCard } from './ConflictsCard';
import { type AddressFilter, MessagesCard } from './MessagesCard';

const route = getRouteApi('/sessions/$sessionId');

/** ARP view (docs/specs/arp.md): figures, conflicts, IP to MAC table and messages. */
export default function ArpView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const session = useSession(sessionId);
  const viewable = isViewable(session.data);
  const stats = useArpStats(sessionId, viewable);
  const ranged = useViewRange() !== null;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('nav.items.arp')}
        subtitle={session.data?.name ?? t('views.arp.subtitle')}
        {...(stats.data === undefined ? {} : { count: <Badge>{formatCount(stats.data.messages)}</Badge> })}
      />
      <SessionGate session={session}>
        {stats.isError ? (
          <Card>
            <ErrorState message={t('views.arp.loadError')} onRetry={() => void stats.refetch()} />
          </Card>
        ) : stats.data === undefined ? (
          <div className="flex flex-col gap-4" aria-busy="true">
            <span className="sr-only">{t('common.loading')}</span>
            <Skeleton height={88} />
            <Skeleton height={240} />
          </div>
        ) : stats.data.messages === 0 && stats.data.bindings === 0 ? (
          <Card>
            <EmptyState icon={Network} title={ranged ? t('timeRange.emptyTitle') : t('views.arp.empty')} />
          </Card>
        ) : (
          <ArpContent
            sessionId={sessionId}
            stats={stats.data}
            oneDay={
              session.data?.first_ts_us != null &&
              session.data.last_ts_us != null &&
              sameLocalDay(session.data.first_ts_us, session.data.last_ts_us)
            }
          />
        )}
      </SessionGate>
    </div>
  );
}

interface ContentProps {
  sessionId: string;
  stats: ArpStats;
  oneDay: boolean;
}

function ArpContent({ sessionId, stats, oneDay }: ContentProps) {
  const { t } = useTranslation();
  const conflicts = useArpConflicts(sessionId, true);
  const [address, setAddress] = useState<AddressFilter | null>(null);
  const [unsolicited, setUnsolicited] = useState(false);
  const messagesRef = useRef<HTMLDivElement>(null);
  const showMessages = useCallback((next: AddressFilter | null, onlyUnsolicited = false) => {
    setAddress(next);
    if (onlyUnsolicited) setUnsolicited(true);
    messagesRef.current?.scrollIntoView?.({ block: 'start', behavior: 'smooth' });
  }, []);

  const senders = useMemo<BarItem[]>(
    () =>
      stats.top_senders.map((s) => ({
        key: `${s.ip.ip} ${s.mac}`,
        label: s.ip.names[0] ?? s.ip.ip,
        detail: s.mac,
        title: `${s.ip.ip} ${s.mac}\n${t('views.arp.conflicts.messages', { count: s.messages })}`,
        value: s.messages,
        valueText: formatCount(s.messages),
        mono: s.ip.names.length === 0,
        active: address !== null && address.ip === s.ip.ip && address.mac === s.mac,
      })),
    [stats.top_senders, address, t],
  );

  return (
    <>
      <section
        aria-label={t('nav.items.arp')}
        data-testid="arp-summary"
        className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5"
      >
        <StatCard icon={Network} label={t('views.arp.stat.messages')} value={formatCount(stats.messages)} />
        <StatCard icon={Cable} label={t('views.arp.stat.bindings')} value={formatCount(stats.bindings)} />
        <StatCard icon={Waypoints} label={t('views.arp.stat.addresses')} value={formatCount(stats.addresses)} />
        <StatCard
          icon={ShieldAlert}
          label={t('views.arp.stat.conflicts')}
          value={formatCount(stats.conflicts)}
          title={t('views.arp.stat.conflictsHint')}
        />
        <StatCard
          icon={TriangleAlert}
          label={t('views.arp.stat.unsolicited')}
          value={formatCount(stats.unsolicited)}
          title={t('views.arp.stat.unsolicitedHint')}
        />
      </section>

      <div className="grid gap-4 xl:grid-cols-3">
        <ConflictsCard
          className="xl:col-span-2"
          query={conflicts}
          unsolicited={stats.unsolicited}
          onShowMessages={(ip) => {
            showMessages({ ip });
          }}
          onShowUnsolicited={() => {
            showMessages(null, true);
          }}
        />
        <Card title={t('views.arp.senders.title')}>
          <BarList
            items={senders}
            ariaLabel={t('views.arp.senders.label')}
            emptyText={t('views.arp.senders.empty')}
            onSelect={(key) => {
              const s = stats.top_senders.find((x) => `${x.ip.ip} ${x.mac}` === key);
              if (s !== undefined) showMessages({ ip: s.ip.ip, mac: s.mac });
            }}
            selectLabel={(item) => t('views.arp.senders.filter', { address: item.title?.split('\n')[0] ?? item.label })}
          />
        </Card>
      </div>

      <BindingsCard
        sessionId={sessionId}
        period={stats.first_ts_us === null || stats.last_ts_us === null ? null : [stats.first_ts_us, stats.last_ts_us]}
        oneDay={oneDay}
        onSelect={(b) => {
          showMessages({ ip: b.ip.ip, mac: b.mac });
        }}
      />

      <div ref={messagesRef} className="scroll-mt-4">
        <MessagesCard
          sessionId={sessionId}
          stats={stats}
          oneDay={oneDay}
          address={address}
          onAddress={setAddress}
          unsolicited={unsolicited}
          onUnsolicited={setUnsolicited}
        />
      </div>
    </>
  );
}
