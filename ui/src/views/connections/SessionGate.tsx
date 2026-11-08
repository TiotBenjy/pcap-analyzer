import { Link } from '@tanstack/react-router';
import { CircleAlert, Hourglass } from 'lucide-react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { SessionSummary } from '../../api/types/SessionSummary';
import { Card } from '../../components/Card';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';

interface SessionGateProps {
  session: { data?: SessionSummary | undefined; isError: boolean; refetch: () => unknown };
  /** The analysis blocks, rendered once the session can be read. */
  children: ReactNode;
}

/**
 * Shared states of the analysis views: session error, import in progress, failed import; the
 * blocks otherwise (each with its own loading, empty and error states).
 */
export function SessionGate({ session, children }: SessionGateProps) {
  const { t } = useTranslation();
  const state = session.data?.state;
  if (session.isError) {
    return (
      <Card>
        <ErrorState
          message={t('views.overview.loadError')}
          onRetry={() => {
            void session.refetch();
          }}
        />
      </Card>
    );
  }
  const capturesLink = (
    <Link to="/captures" className="text-accent hover:underline">
      {t('views.overview.followImport')}
    </Link>
  );
  if (state === 'importing') {
    return (
      <Card>
        <EmptyState
          icon={Hourglass}
          title={t('views.overview.importingTitle')}
          description={t('views.overview.importingText')}
          action={capturesLink}
        />
      </Card>
    );
  }
  if (state === 'failed') {
    return (
      <Card>
        <EmptyState
          icon={CircleAlert}
          title={t('views.overview.failedTitle')}
          description={session.data?.state_detail ?? t('views.overview.failedText')}
          action={capturesLink}
        />
      </Card>
    );
  }
  return <>{children}</>;
}
