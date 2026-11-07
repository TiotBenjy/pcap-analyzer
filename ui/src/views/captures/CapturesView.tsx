import { FolderOpen } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Card } from '../../components/Card';
import { EmptyState } from '../../components/EmptyState';
import { PageHeader } from '../../components/PageHeader';

// Placeholder until P2.3 (session list, import, chunk timeline). Spec: docs/specs/captures.md.
export default function CapturesView() {
  const { t } = useTranslation();
  return (
    <div className="flex flex-col gap-4">
      <PageHeader title={t('nav.items.captures')} subtitle={t('views.captures.subtitle')} />
      <Card>
        <EmptyState icon={FolderOpen} title={t('views.captures.emptyTitle')} description={t('views.captures.emptyText')} />
      </Card>
    </div>
  );
}
