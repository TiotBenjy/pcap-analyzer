import { LayoutDashboard } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Card } from '../../components/Card';
import { EmptyState } from '../../components/EmptyState';
import { PageHeader } from '../../components/PageHeader';

// Placeholder until P2.4 (time series, module cards, session summary). Spec: docs/specs/overview.md.
export default function OverviewView() {
  const { t } = useTranslation();
  return (
    <div className="flex flex-col gap-4">
      <PageHeader title={t('nav.items.overview')} subtitle={t('views.overview.subtitle')} />
      <Card>
        <EmptyState
          icon={LayoutDashboard}
          title={t('views.overview.emptyTitle')}
          description={t('views.overview.emptyText')}
        />
      </Card>
    </div>
  );
}
