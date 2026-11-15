import { Link, useNavigate } from '@tanstack/react-router';
import { CircleAlert, CircleCheck, TriangleAlert, Unplug } from 'lucide-react';
import type { ReactNode } from 'react';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import {
  cancelTrackedImport,
  closeImportWizard,
  isActive,
  isFinalizing,
  progressFraction,
  stepNumber,
  type TrackedImport,
  trackImport,
  warningTotal,
} from '../../../app/importTracker';
import { Button } from '../../../components/Button';
import { ErrorNote } from '../../../components/ErrorNote';
import { en } from '../../../i18n/en';
import { colon, formatCount, formatDuration, formatPercent, formatRate } from '../../../lib/format';
import { anomalyLabel, anomalyWhere, groupAnomalies } from '../anomalies';
import { SessionStateBadge } from '../SessionStateBadge';
import { WizardDialog } from './WizardDialog';

/** Step 3: live progress of the tracked import, then its outcome. */
export function ProgressStep({ imp }: { imp: TrackedImport }) {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const active = isActive(imp);
  const p = imp.progress;
  const fraction = imp.status === 'done' ? 1 : progressFraction(p);
  const finalizing = active && p !== null && isFinalizing(p);
  const percent =
    finalizing && p !== null
      ? t('views.import.stepOf', { n: stepNumber(p), total: p.steps_total })
      : formatPercent(fraction, 0, i18n.language);

  // Once reading is over, nothing listens to the cancel request any more: the import ends.
  // Identical warnings (same code and chunk) on one line, in order of first appearance.
  const total = warningTotal(imp);
  const groups = groupAnomalies(t, imp.warnings, total > imp.warnings.length);
  // Finished: the outcome gives the packets and nothing remains to estimate.
  const finished = imp.result !== null;

  const readingOver = p !== null && (p.phase === 'finishing' || p.phase === 'finalizing');
  const label =
    p === null
      ? t('views.import.waiting')
      : finalizing
        ? stepLabel(t, p.step)
        : readingOver
          ? t('views.import.finishing')
          : t('views.import.chunk', { n: Math.min(p.chunk_index + 1, p.chunk_count), total: p.chunk_count });

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
          disabled={imp.status === 'cancelling' || readingOver}
          {...(readingOver ? { title: t('views.import.cancelUnavailable') } : {})}
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
            <span data-testid="truncatable" title={label} className="min-w-0 truncate">
              {label}
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
          {p !== null && p.chunk_name !== '' && !finalizing && (
            <span data-testid="truncatable" title={p.chunk_name} className="truncate font-mono text-meta text-muted">
              {p.chunk_name}
            </span>
          )}
        </div>

        <dl className="grid grid-cols-[repeat(auto-fill,minmax(9rem,1fr))] gap-x-4 gap-y-2">
          {!finished && <Stat label={t('views.import.packets')}>{p === null ? '' : formatCount(p.packets)}</Stat>}
          <Stat label={t('views.import.rate')}>{p === null ? '' : formatRate(p.rate_bps)}</Stat>
          {active && (
            <Stat label={t('views.import.eta')}>
              {p === null ? '' : p.eta_s === null ? t('views.import.unknown') : formatDuration(p.eta_s)}
            </Stat>
          )}
        </dl>

        <section className="flex min-w-0 flex-col gap-1.5" aria-label={t('views.import.warnings')}>
          <h3 className="text-meta font-medium text-muted">
            {t('views.import.warnings')} <span className="num">({formatCount(total)})</span>
          </h3>
          {groups.length === 0 ? (
            <p className="text-meta text-muted">{t('views.import.noWarnings')}</p>
          ) : (
            <ul className="flex max-h-48 min-w-0 flex-col gap-1 overflow-y-auto rounded-md border border-line p-2 text-meta">
              {groups.map(({ first, count, capped, detail }, i) => (
                <li key={i} className="flex min-w-0 items-start gap-2">
                  <TriangleAlert aria-hidden size={14} strokeWidth={1.75} className="mt-0.5 shrink-0 text-warning" />
                  <span className="min-w-0 [overflow-wrap:anywhere]">
                    <span className="font-medium">{anomalyLabel(t, first)}</span>
                    <span className="text-muted">
                      {' '}
                      ({anomalyWhere(t, first)})
                      {count > 1 && (
                        <>
                          {' '}
                          <span className="num">
                            {t(capped ? 'views.import.repeatedCapped' : 'views.import.repeated', {
                              n: formatCount(count),
                            })}
                          </span>
                        </>
                      )}
                      {detail === '' ? '' : `${colon(i18n.language)} ${detail}`}
                    </span>
                  </span>
                </li>
              ))}
            </ul>
          )}
          {total > imp.warnings.length && (
            <p className="text-meta text-muted">
              {t('views.import.moreWarnings', { count: total - imp.warnings.length })} (
              {imp.status === 'done' ? (
                <Link
                  to="/sessions/$sessionId/sources"
                  params={{ sessionId: imp.sessionId }}
                  className="text-accent hover:underline"
                  onClick={closeImportWizard}
                >
                  {t('views.import.fullList')}
                </Link>
              ) : (
                t('views.import.fullList')
              )}
              )
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

type StepKey = keyof (typeof en)['views']['import']['steps'];

/** Label of an end-of-import step; unknown ids (a newer backend) get the generic label. */
function stepLabel(t: TFunction, step: string | null): string {
  return step !== null && Object.hasOwn(en.views.import.steps, step)
    ? t('views.import.finalizingStep', { step: t(`views.import.steps.${step as StepKey}`) })
    : t('views.import.finalizing');
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
