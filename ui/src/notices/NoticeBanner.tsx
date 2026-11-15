import { Info, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Button } from '../components/Button';
import type { Notice } from './types';

interface NoticeBannerProps {
  id: string;
  notice: Notice;
  onDismiss: () => void;
}

/**
 * One notice: accent icon, message, optional detail and actions, dismiss button. Text wraps,
 * actions go under the message on narrow screens.
 */
export function NoticeBanner({ id, notice, onDismiss }: NoticeBannerProps) {
  const { t } = useTranslation();
  return (
    <div
      className="flex min-w-0 items-start gap-2 border-b border-line bg-surface py-1.5 pr-1.5 pl-3 sm:pl-4"
      data-testid={`notice-${id}`}
    >
      <Info aria-hidden size={16} strokeWidth={1.75} className="mt-2 shrink-0 text-accent" />
      <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-1.5 py-1">
        <div className="flex min-w-0 flex-col gap-0.5">
          <p className="break-words">{notice.message}</p>
          {notice.detail !== undefined && (
            <div className="break-words text-meta text-muted [overflow-wrap:anywhere]">{notice.detail}</div>
          )}
        </div>
        {notice.actions !== undefined && notice.actions.length > 0 && (
          <div className="flex min-w-0 flex-wrap gap-2">
            {notice.actions.map((action) => (
              <Button
                key={action.label}
                variant={action.primary === true ? 'primary' : 'secondary'}
                disabled={action.disabled}
                title={action.title}
                onClick={action.onClick}
              >
                {action.label}
              </Button>
            ))}
          </div>
        )}
      </div>
      <Button variant="ghost" icon aria-label={t('notices.dismiss')} title={t('notices.dismiss')} onClick={onDismiss}>
        <X aria-hidden size={16} strokeWidth={1.75} />
      </Button>
    </div>
  );
}
