import type { ErrorComponentProps } from '@tanstack/react-router';
import { CircleAlert, Copy, RotateCw } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from './Button';
import { Card } from './Card';
import { copyText, errorDetails } from '../lib/errorReport';

// Error screen of the router (root and session routes), in place of the TanStack default, with
// the error report of lib/errorReport.ts ("Copy details").

export function RouteError({ error }: ErrorComponentProps) {
  const { t } = useTranslation();
  const [copy, setCopy] = useState<'idle' | 'done' | 'failed'>('idle');
  const details = errorDetails(error, window.location.hash, navigator.userAgent);
  const message = error instanceof Error && error.message !== '' ? error.message : t('common.error');

  return (
    <Card>
      <div role="alert" data-testid="route-error" className="flex flex-col items-center gap-3 px-2 py-8 text-center">
        <CircleAlert aria-hidden size={20} strokeWidth={1.75} className="text-danger" />
        <h1 className="text-card font-medium">{t('errors.route.title')}</h1>
        <p className="max-w-prose text-muted">{t('errors.route.text')}</p>
        <p className="max-w-full font-mono text-meta wrap-anywhere">{message}</p>
        <div className="flex flex-wrap justify-center gap-2">
          <Button
            variant="primary"
            onClick={() => {
              window.location.reload();
            }}
          >
            <RotateCw aria-hidden size={14} strokeWidth={1.75} />
            {t('errors.route.reload')}
          </Button>
          <Button
            onClick={() => {
              void copyText(details).then((ok) => {
                setCopy(ok ? 'done' : 'failed');
              });
            }}
          >
            <Copy aria-hidden size={14} strokeWidth={1.75} />
            {t('errors.route.copy')}
          </Button>
        </div>
        <p role="status" className="min-h-5 text-meta text-muted">
          {copy === 'done' ? t('errors.route.copied') : copy === 'failed' ? t('errors.route.copyFailed') : ''}
        </p>
        <details className="w-full max-w-3xl text-left">
          <summary className="cursor-pointer text-meta text-muted">{t('errors.route.details')}</summary>
          <textarea
            readOnly
            aria-label={t('errors.route.details')}
            value={details}
            rows={10}
            className="mt-2 w-full min-w-0 resize-y rounded-md border border-line bg-subtle p-2 font-mono text-meta"
          />
        </details>
      </div>
    </Card>
  );
}

/** Error of the root route (the shell itself failed): same screen, as a full page. */
export function RootRouteError(props: ErrorComponentProps) {
  return (
    <main id="main" className="min-h-screen bg-app p-3 text-fg sm:p-4 lg:p-6">
      <RouteError {...props} />
    </main>
  );
}
