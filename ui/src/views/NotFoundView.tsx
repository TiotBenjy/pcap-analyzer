import { Link } from '@tanstack/react-router';
import { MapPinOff } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Card } from '../components/Card';
import { EmptyState } from '../components/EmptyState';

export function NotFoundView() {
  const { t } = useTranslation();
  return (
    <Card>
      <EmptyState
        icon={MapPinOff}
        title={t('views.notFound.title')}
        description={t('views.notFound.text')}
        action={
          <Link to="/captures" className="text-accent hover:underline">
            {t('views.notFound.back')}
          </Link>
        }
      />
    </Card>
  );
}
