import { useNavigate } from '@tanstack/react-router';
import { CircleAlert, CircleCheck, TriangleAlert, Unplug } from 'lucide-react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import {
  cancelTrackedImport,
  closeImportWizard,
  importFraction,
  isActive,
  type TrackedImport,
  trackImport,
} from '../../../app/importTracker';
import { Button } from '../../../components/Button';
import { ErrorNote } from '../../../components/ErrorNote';
import { formatBytes, formatCount, formatDuration } from '../../../lib/format';
import { anomalyDetail, anomalyLabel, anomalyWhere } from '../anomalies';
import { SessionStateBadge } from '../SessionStateBadge';
import { WizardDialog } from './WizardDialog';

/** Step 3: live progress of the tracked import, then its outcome. */
export function ProgressStep({ imp }: { imp: TrackedImport }) {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const active = isActive(imp);
  const p = imp.progress;
  const fraction = imp.status === 'done' ? 1 : importFraction(p?.bytes_done ?? 0, p?.bytes_total ?? 0);
  const percent = new Intl.NumberFormat(i18n.language, { style: 'percent', maximumFractionDigits: 0 }).format(fraction);

  const openSession = () => {
    const sessionId = imp.sessionId;
    closeImportWizard();
    void navigate({ to: '/sessions/$sessionId/overview', params: { sessionId } });
  };

  let footer: ReactNode;
  if (active) {
    footer = (
      <>
        <Button onClick={closeImportWizard}>{t('views.import.hide')}</Button>
        <Button
          variant="danger"
          disabled={imp.status === 'cancelling'}
          onClick={() => {
            void cancelTrackedImport();
          }}
        >
          {imp.status === 'cancelling' ? t('views.import.cancelling') : t('views.import.cancel')}
        </Button>
      </>
    );
  } else {
    footer = (
      <>
        <Button onClick={closeImportWizard}>{t('common.close')}</Button>
        {imp.status === 'lost' && (
          <Button
            variant="primary"
            onClick={() => {
              trackImport(imp.sessionId, imp.name);
            }}
          >
            {t('views.import.reconnect')}
          </Button>
        )}
        {imp.status === 'done' && (
          <Button variant="primary" data-autofocus onClick={openSession}>
            {t('views.import.open')}
          </Button>
        )}
      </>
    );
  }

  return (
    <WizardDialog step={3} kind="folder" footer={footer}>
      <div className="flex min-w-0 flex-col gap-4">
        <p data-testid="truncatable" title={imp.name} className="truncate font-medium">
          {imp.name}
        </p>

        <Outcome imp={imp} />

        <div className="flex min-w-0 flex-col gap-1.5">
          <div className="flex min-w-0 items-center justify-between gap-2 text-meta text-muted">
            <span className="min-w-0 truncate">
              {p === null
                ? t('views.import.waiting')
                : p.phase === 'finishing'
                  ? t('views.import.finishing')
                  : t('views.import.chunk', { n: Math.min(p.chunk_index + 1, p.chunk_count), total: p.chunk_count })}
            </span>
            <span className="num shrink-0">{percent}</span>
          </div>
          <div
            role="progressbar"
            aria-label={t('views.import.progressLabel')}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={Math.round(fraction * 100)}
            className="h-2 w-full overflow-hidden rounded-full bg-subtle"
          >
            <div className="h-full rounded-full bg-accent" style={{ width: `${fraction * 100}%` }} />
          </div>
          {p !== null && p.chunk_name !== '' && (
            <span data-testid="truncatable" title={p.chunk_name} className="truncate font-mono text-meta text-muted">
              {p.chunk_name}
            </span>
          )}
        </div>

        <dl className="grid grid-cols-[repeat(auto-fill,minmax(9rem,1fr))] gap-x-4 gap-y-2">
          <Stat label={t('views.import.packets')}>{p === null ? '' : formatCount(p.packets)}</Stat>
          <Stat label={t('views.import.rate')}>{p === null ? '' : `${formatBytes(p.rate_bps)}/s`}</Stat>
          <Stat label={t('views.import.eta')}>
            {p === null || !active ? '' : p.eta_s === null ? t('views.import.unknown') : formatDuration(p.eta_s)}
          </Stat>
        </dl>

        <section className="flex min-w-0 flex-col gap-1.5" aria-label={t('views.import.warnings')}>
          <h3 className="text-meta font-medium text-muted">
            {t('views.import.warnings')} <span className="num">({formatCount(imp.warningCount)})</span>
          </h3>
          {imp.warnings.length === 0 ? (
            <p className="text-meta text-muted">{t('views.import.noWarnings')}</p>
          ) : (
            <ul className="flex max-h-48 min-w-0 flex-col gap-1 overflow-y-auto rounded-md border border-line p-2 text-meta">
              {imp.warnings.map((w, i) => {
                const detail = anomalyDetail(t, w);
                return (
                  <li key={i} className="flex min-w-0 items-start gap-2">
                    <TriangleAlert aria-hidden size={14} strokeWidth={1.75} className="mt-0.5 shrink-0 text-warning" />
                    <span className="min-w-0 [overflow-wrap:anywhere]">
                      <span className="font-medium">{anomalyLabel(t, w.code)}</span>
                      <span className="text-muted">
                        {' '}
                        ({anomalyWhere(t, w)}){detail === '' ? '' : `: ${detail}`}
                      </span>
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
          {imp.warningCount > imp.warnings.length && (
            <p className="text-meta text-muted">
              {t('views.import.moreWarnings', { count: imp.warningCount - imp.warnings.length })}
            </p>
          )}
        </section>

        {imp.cancelError !== null && (
          <ErrorNote error={imp.cancelError} format={(message) => t('views.import.cancelError', { message })} />
        )}
      </div>
    </WizardDialog>
  );
}

function Stat({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-meta text-muted">{label}</dt>
      <dd className="num truncate">{children === '' ? ' ' : children}</dd>
    </div>
  );
}

function Outcome({ imp }: { imp: TrackedImport }) {
  const { t } = useTranslation();
  if (imp.status === 'lost') {
    return (
      <div role="status" className="flex min-w-0 items-start gap-2">
        <Unplug aria-hidden size={16} strokeWidth={1.75} className="mt-0.5 shrink-0 text-warning" />
        <div className="min-w-0 [overflow-wrap:anywhere]">
          <p className="font-medium">{t('views.import.lostTitle')}</p>
          <p className="text-muted">{t('views.import.lost')}</p>
        </div>
      </div>
    );
  }
  if (imp.status === 'failed') {
    return (
      <div role="alert" className="flex min-w-0 items-start gap-2">
        <CircleAlert aria-hidden size={16} strokeWidth={1.75} className="mt-0.5 shrink-0 text-danger" />
        <div className="flex min-w-0 flex-col gap-0.5 [overflow-wrap:anywhere]">
          <p className="font-medium">{t('views.import.failed')}</p>
          {/* The backend message is technical and in English: the log has the details. */}
          {imp.error !== null && <p className="text-muted">{t('views.import.failedDetail')}</p>}
          {imp.streamError !== null && <ErrorNote error={imp.streamError} />}
        </div>
      </div>
    );
  }
  if (imp.status !== 'done' || imp.result === null) return null;
  const r = imp.result;
  const complete = r.state === 'ready';
  return (
    <div role="status" className="flex min-w-0 flex-col gap-3">
      <div className="flex min-w-0 items-start gap-2">
        {complete ? (
          <CircleCheck aria-hidden size={16} strokeWidth={1.75} className="mt-0.5 shrink-0 text-success" />
        ) : (
          <TriangleAlert aria-hidden size={16} strokeWidth={1.75} className="mt-0.5 shrink-0 text-warning" />
        )}
        <p className="min-w-0 font-medium">{complete ? t('views.import.done') : t('views.import.doneIncomplete')}</p>
      </div>
      <dl className="grid grid-cols-[repeat(auto-fill,minmax(9rem,1fr))] gap-x-4 gap-y-2">
        <Stat label={t('views.import.state')}>
          <SessionStateBadge state={r.state} />
        </Stat>
        <Stat label={t('views.import.packets')}>{formatCount(r.packets)}</Stat>
        <Stat label={t('views.import.flows')}>{formatCount(r.flows)}</Stat>
        <Stat label={t('views.import.anomalies')}>{formatCount(r.anomalies)}</Stat>
        <Stat label={t('views.import.duration')}>{formatDuration(r.duration_s)}</Stat>
      </dl>
    </div>
  );
}
