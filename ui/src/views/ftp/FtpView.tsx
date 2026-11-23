import { getRouteApi } from '@tanstack/react-router';
import { Download, HardDrive, Lock, LogIn, Upload, Users } from 'lucide-react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useFtpStats } from '../../api/ftpQueries';
import type { FtpStats } from '../../api/types/FtpStats';
import { Badge } from '../../components/Badge';
import { Card } from '../../components/Card';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';
import { PageHeader } from '../../components/PageHeader';
import { StatCard } from '../../components/StatCard';
import { formatBytes, formatCount } from '../../lib/format';
import { SessionGate } from '../connections/SessionGate';
import { useViewableSession } from '../http/state';
import { SessionsCard } from './SessionsCard';
import { TransfersCard } from './TransfersCard';

const route = getRouteApi('/sessions/$sessionId');

/** FTP view (docs/specs/ftp.md): figures, control sessions with their transcript, transfers. */
export default function FtpView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const { session, viewable, oneDay } = useViewableSession(sessionId);
  const stats = useFtpStats(sessionId, viewable);
  const s = stats.data;

  let content: ReactNode;
  if (stats.isError)
    content = (
      <Card>
        <ErrorState
          message={t('views.ftp.loadError')}
          onRetry={() => {
            void stats.refetch();
          }}
        />
      </Card>
    );
  else if (s !== undefined && s.sessions === 0 && s.transfers === 0)
    content = (
      <Card>
        <EmptyState icon={Upload} title={t('views.ftp.empty')} />
      </Card>
    );
  else
    content = (
      <>
        <StatBand stats={s} />
        <SessionsCard sessionId={sessionId} enabled={viewable} oneDay={oneDay} />
        <TransfersCard sessionId={sessionId} enabled={viewable} oneDay={oneDay} />
      </>
    );

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('nav.items.ftp')}
        subtitle={session.data?.name ?? t('views.ftp.subtitle')}
        {...(s === undefined ? {} : { count: <Badge>{formatCount(s.sessions)}</Badge> })}
      />
      <SessionGate session={session}>{content}</SessionGate>
    </div>
  );
}

function StatBand({ stats }: { stats: FtpStats | undefined }) {
  const { t } = useTranslation();
  const v = (n: number | undefined) => (n === undefined ? null : formatCount(n));
  const hint = (key: 'sessionsHint' | 'rejectedHint' | 'storedHint', count: number | undefined) =>
    count === undefined ? ' ' : t(`views.ftp.stat.${key}`, { count });
  return (
    <section aria-label={t('views.ftp.stat.label')} data-testid="ftp-summary" className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
      <StatCard icon={Users} label={t('views.ftp.stat.sessions')} value={v(stats?.sessions)} hint={hint('sessionsHint', stats?.servers)} />
      <StatCard
        icon={LogIn}
        label={t('views.ftp.stat.accepted')}
        value={v(stats?.logins_accepted)}
        hint={hint('rejectedHint', stats?.logins_rejected)}
        tone={stats !== undefined && stats.logins_rejected > 0 ? 'warning' : 'neutral'}
      />
      <StatCard icon={Download} label={t('views.ftp.stat.downloads')} value={v(stats?.downloads)} hint=" " />
      <StatCard icon={Upload} label={t('views.ftp.stat.uploads')} value={v(stats?.uploads)} hint=" " />
      <StatCard
        icon={HardDrive}
        label={t('views.ftp.stat.bytes')}
        value={stats === undefined ? null : formatBytes(stats.bytes)}
        hint={hint('storedHint', stats?.stored)}
      />
      <StatCard icon={Lock} label={t('views.ftp.stat.tls')} value={v(stats?.tls_sessions)} hint={t('views.ftp.stat.tlsHint')} />
    </section>
  );
}
