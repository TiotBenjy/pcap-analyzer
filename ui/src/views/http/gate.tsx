import { Link } from '@tanstack/react-router';
import { CircleAlert, Hourglass } from 'lucide-react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { useSession } from '../../api/sessionQueries';
import { Card } from '../../components/Card';
import { EmptyState } from '../../components/EmptyState';
import { ErrorState } from '../../components/ErrorState';

/** Importing, failed or unreadable session: the block replacing the view content, else `null`. */
export function useSessionGate(session: ReturnType<typeof useSession>): ReactNode {
  const { t } = useTranslation();
  const back = (
    <Link to="/captures" className="text-accent hover:underline">
      {t('views.overview.followImport')}
    </Link>
  );
  if (session.isError)
    return (
      <Card>
        <ErrorState
          message={t('views.http.loadError')}
          onRetry={() => {
            void session.refetch();
          }}
        />
      </Card>
    );
  if (session.data?.state === 'importing')
    return (
      <Card>
        <EmptyState
          icon={Hourglass}
          title={t('views.overview.importingTitle')}
          description={t('views.http.importingText')}
          action={back}
        />
      </Card>
    );
  if (session.data?.state === 'failed')
    return (
      <Card>
        <EmptyState
          icon={CircleAlert}
          title={t('views.overview.failedTitle')}
          description={session.data.state_detail ?? t('views.overview.failedText')}
          action={back}
        />
      </Card>
    );
  return null;
}
