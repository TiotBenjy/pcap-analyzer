import { useRouterState } from '@tanstack/react-router';
import { Construction } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { findNavItem } from '../app/nav';
import { Card } from '../components/Card';
import { EmptyState } from '../components/EmptyState';
import { PageHeader } from '../components/PageHeader';

/** Shared empty route for views planned in later phases (reachable by URL only). */
export default function PlaceholderView() {
  const { t } = useTranslation();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const item = findNavItem(pathname);
  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={item === undefined ? t('app.name') : t(`nav.items.${item.id}`)}
        subtitle={t('views.placeholder.subtitle')}
      />
      <Card>
        <EmptyState
          icon={Construction}
          title={t('views.placeholder.emptyTitle')}
          description={t('views.placeholder.emptyText')}
        />
      </Card>
    </div>
  );
}
