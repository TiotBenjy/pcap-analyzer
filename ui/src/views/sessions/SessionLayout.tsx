import { getRouteApi, Link, Outlet } from '@tanstack/react-router';
import { SearchX } from 'lucide-react';
import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { ApiError } from '../../api/client';
import { useSession } from '../../api/sessionQueries';
import { forgetSession, rememberSession } from '../../app/session';
import { Card } from '../../components/Card';
import { EmptyState } from '../../components/EmptyState';
import { PageHeader } from '../../components/PageHeader';

const route = getRouteApi('/sessions/$sessionId');

/**
 * Parent of the session-scoped views (`/sessions/$sessionId/...`): remembers the session as the
 * last opened one (sidebar, `/overview`), and replaces the view by a "not found" state when the
 * backend does not know the id. Other errors are left to the views (each block has its own).
 */
export default function SessionLayout() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  const session = useSession(sessionId);
  const notFound = session.error instanceof ApiError && session.error.status === 404;

  useEffect(() => {
    if (notFound) forgetSession(sessionId);
    else rememberSession(sessionId);
  }, [sessionId, notFound]);

  if (notFound) {
    return (
      <div className="flex flex-col gap-4">
        <PageHeader title={t('views.session.notFoundTitle')} />
        <Card>
          <EmptyState
            icon={SearchX}
            title={t('views.session.notFoundTitle')}
            description={t('views.session.notFoundText')}
            action={
              <Link to="/captures" className="text-accent hover:underline">
                {t('views.session.back')}
              </Link>
            }
          />
        </Card>
      </div>
    );
  }
  return <Outlet />;
}
