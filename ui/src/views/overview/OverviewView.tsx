import { getRouteApi, Link } from '@tanstack/react-router';
import { FileStack, LayoutDashboard } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Card } from '../../components/Card';
import { EmptyState } from '../../components/EmptyState';
import { PageHeader } from '../../components/PageHeader';

const route = getRouteApi('/sessions/$sessionId/overview');

// Placeholder until P2.4 (time series, module cards, session summary). Spec: docs/specs/overview.md.
export default function OverviewView() {
  const { t } = useTranslation();
  const { sessionId } = route.useParams();
  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={t('nav.items.overview')}
        subtitle={t('views.overview.subtitle')}
        actions={
          <Link
            to="/sessions/$sessionId/sources"
            params={{ sessionId }}
            className="inline-flex h-8 items-center gap-1.5 rounded-md border border-line bg-surface px-3 font-medium hover:bg-subtle"
          >
            <FileStack aria-hidden size={16} strokeWidth={1.75} />
            {t('views.session.sources')}
          </Link>
        }
      />
      <Card>
        <EmptyState
          icon={LayoutDashboard}
          title={t('views.placeholder.emptyTitle')}
          description={t('views.placeholder.emptyText')}
        />
      </Card>
    </div>
  );
}
