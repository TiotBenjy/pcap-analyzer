import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { TriangleAlert } from 'lucide-react';
import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useServerInfo } from '../../../api/queries';
import { sessionKeys } from '../../../api/sessionQueries';
import { scanImport, startImport } from '../../../api/sessions';
import type { ScanGroup } from '../../../api/types/ScanGroup';
import type { ScanResponse } from '../../../api/types/ScanResponse';
import { type PickKind, trackImport } from '../../../app/importTracker';
import { Badge } from '../../../components/Badge';
import { Button } from '../../../components/Button';
import { ErrorNote } from '../../../components/ErrorNote';
import { ErrorState } from '../../../components/ErrorState';
import { describeError } from '../../../lib/errors';
import { Skeleton } from '../../../components/Skeleton';
import { baseName, formatBytes, formatTimestamp, sameLocalDay } from '../../../lib/format';
import { anomalyDetail, anomalyLabel, anomalyWhere } from '../anomalies';
import { WizardDialog } from './WizardDialog';

const SKIP_REASONS = new Set(['empty', 'too_short', 'unrecognized', 'unreadable', 'not_regular'] as const);
type SkipReason = typeof SKIP_REASONS extends Set<infer S> ? S : never;
const isSkipReason = (r: string): r is SkipReason => (SKIP_REASONS as Set<string>).has(r);

/**
 * What gets imported: one group, or all of them merged. The API accepts exactly these cases
 * (a subset of several groups is refused), so the choice is a radio group, not checkboxes.
 */
type GroupChoice = number | 'all';

function groupIds(scan: ScanResponse, choice: GroupChoice | null): number[] {
  if (choice === 'all') return scan.groups.map((g) => g.id);
  const id = choice ?? scan.groups[0]?.id;
  return id === undefined ? [] : [id];
}

interface ReviewStepProps {
  kind: PickKind;
  path: string;
  onBack: () => void;
}

/** Step 2: scan result (detected groups), group choice, session name, start. */
export function ReviewStep({ kind, path, onBack }: ReviewStepProps) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const readOnly = useServerInfo().data?.read_only === true;
  const [recursive, setRecursive] = useState(false);
  const [choice, setChoice] = useState<GroupChoice | null>(null);
  const radioName = useId();
  const [name, setName] = useState(() => baseName(path));
  const nameId = useId();

  const scan = useQuery({
    queryKey: ['import', 'scan', path, recursive],
    queryFn: ({ signal }) => scanImport({ path, recursive }, signal),
    retry: false,
    staleTime: 0,
    gcTime: 0,
  });
  const selected = scan.data === undefined ? [] : groupIds(scan.data, choice);
  const effectiveChoice: GroupChoice | undefined = choice ?? scan.data?.groups[0]?.id;

  const start = useMutation({
    mutationFn: () =>
      startImport({
        path,
        group_ids: selected,
        name: name.trim() === '' ? null : name.trim(),
        recursive,
      }),
    onSuccess: (res) => {
      trackImport(res.session_id, name.trim() === '' ? baseName(path) : name.trim());
      void qc.invalidateQueries({ queryKey: sessionKeys.all });
    },
  });

  return (
    <WizardDialog
      step={2}
      kind={kind}
      footer={
        <>
          <Button onClick={onBack}>{t('common.back')}</Button>
          <Button
            variant="primary"
            disabled={selected.length === 0 || start.isPending || readOnly || scan.data === undefined}
            title={readOnly ? t('views.import.readOnly') : undefined}
            onClick={() => {
              start.mutate();
            }}
          >
            {start.isPending ? t('views.import.starting') : t('views.import.start')}
          </Button>
        </>
      }
    >
      <div className="flex min-w-0 flex-col gap-4">
        <div className="flex min-w-0 flex-wrap items-center gap-x-4 gap-y-2">
          <span data-testid="truncatable" title={path} className="min-w-0 flex-1 truncate font-mono text-meta text-muted">
            {path}
          </span>
          {kind === 'folder' && (
            <label className="inline-flex items-center gap-2 text-body">
              <input
                type="checkbox"
                checked={recursive}
                onChange={(e) => {
                  setChoice(null);
                  setRecursive(e.target.checked);
                }}
              />
              {t('views.import.recursive')}
            </label>
          )}
        </div>

        {scan.isPending ? (
          <div className="flex flex-col gap-2" aria-busy="true">
            <span className="sr-only">{t('views.import.scanning')}</span>
            <Skeleton height={72} />
            <Skeleton height={72} />
          </div>
        ) : scan.isError ? (
          <ErrorState
            message={t('views.import.scanError', { message: describeError(t, scan.error).message })}
            onRetry={() => {
              void scan.refetch();
            }}
          />
        ) : (
          <>
            {scan.data.truncated && <Notice>{t('views.import.truncated')}</Notice>}
            <fieldset className="flex min-w-0 flex-col gap-2">
              <legend className="mb-2 text-meta font-medium text-muted">{t('views.import.groups')}</legend>
              {scan.data.groups.length === 0 ? (
                <p className="text-muted">{t('views.import.noGroup')}</p>
              ) : (
                <>
                  {scan.data.groups.map((g) => (
                    <GroupOption
                      key={g.id}
                      group={g}
                      name={radioName}
                      checked={effectiveChoice === g.id}
                      onSelect={() => {
                        setChoice(g.id);
                      }}
                    />
                  ))}
                  {scan.data.groups.length > 1 && (
                    <label className="flex min-w-0 items-center gap-3 rounded-md border border-line p-3">
                      <input
                        type="radio"
                        name={radioName}
                        className="shrink-0"
                        checked={effectiveChoice === 'all'}
                        onChange={() => {
                          setChoice('all');
                        }}
                      />
                      <span className="font-medium">{t('views.import.allGroups')}</span>
                    </label>
                  )}
                </>
              )}
            </fieldset>
            {effectiveChoice === 'all' && <Notice>{t('views.import.merge')}</Notice>}
            {scan.data.skipped.length > 0 && (
              <details className="min-w-0 text-body">
                <summary className="cursor-pointer text-muted">
                  {t('views.import.skipped', { count: scan.data.skipped.length })}
                </summary>
                <ul className="mt-2 flex max-h-40 flex-col gap-1 overflow-y-auto">
                  {scan.data.skipped.map((s) => (
                    <li key={s.name} className="flex min-w-0 items-center gap-2 text-meta">
                      <span data-testid="truncatable" title={s.name} className="min-w-0 flex-1 truncate font-mono">
                        {s.name}
                      </span>
                      <span className="shrink-0 text-muted">
                        {isSkipReason(s.reason) ? t(`views.import.skipReason.${s.reason}`) : s.reason}
                      </span>
                    </li>
                  ))}
                </ul>
              </details>
            )}
            <div className="flex min-w-0 flex-col gap-1.5">
              <label htmlFor={nameId} className="text-meta font-medium text-muted">
                {t('views.import.sessionName')}
              </label>
              <input
                id={nameId}
                value={name}
                maxLength={200}
                onChange={(e) => {
                  setName(e.target.value);
                }}
                className="h-8 w-full min-w-0 rounded-md border border-line bg-surface px-2"
              />
            </div>
          </>
        )}
        {start.isError && (
          <ErrorNote error={start.error} format={(message) => t('views.import.startError', { message })} />
        )}
      </div>
    </WizardDialog>
  );
}

function Notice({ children }: { children: string }) {
  return (
    <p className="flex min-w-0 items-start gap-2 text-body">
      <TriangleAlert aria-hidden size={16} strokeWidth={1.75} className="mt-0.5 shrink-0 text-warning" />
      <span className="min-w-0">{children}</span>
    </p>
  );
}

interface GroupOptionProps {
  group: ScanGroup;
  name: string;
  checked: boolean;
  onSelect: () => void;
}

function GroupOption({ group, name, checked, onSelect }: GroupOptionProps) {
  const { t } = useTranslation();
  // The scan does not read whole files: `last_ts_us` is the start of the last chunk (null for a
  // single file). Only the start is exact; the last file start is given as an indication.
  const since = group.first_ts_us === null ? '' : t('views.import.since', { start: formatTimestamp(group.first_ts_us) });
  const lastStart =
    group.last_ts_us === null || group.file_count < 2
      ? ''
      : t('views.import.approxEnd', {
          end: formatTimestamp(
            group.last_ts_us,
            group.first_ts_us === null || !sameLocalDay(group.first_ts_us, group.last_ts_us),
          ),
        });
  const titleId = useId();
  return (
    <div className="flex min-w-0 gap-3 rounded-md border border-line p-3" data-testid="scan-group">
      <input
        type="radio"
        name={name}
        className="mt-1 shrink-0"
        checked={checked}
        aria-labelledby={titleId}
        onChange={onSelect}
      />
      <div className="flex min-w-0 flex-1 flex-col gap-1">
        <div id={titleId} className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
          <span className="font-medium">{t(`views.import.pattern.${group.pattern}`)}</span>
          {group.prefix !== '' && (
            <span data-testid="truncatable" title={group.prefix} className="min-w-0 truncate font-mono text-meta text-muted">
              {group.prefix}
            </span>
          )}
        </div>
        <div className="num flex min-w-0 flex-wrap gap-x-4 gap-y-1 text-meta text-muted">
          <span>{t('views.import.files', { count: group.file_count })}</span>
          <span>{formatBytes(group.total_bytes)}</span>
          {since !== '' && <span>{since}</span>}
          {lastStart !== '' && <span>{lastStart}</span>}
        </div>
        {group.anomalies.length === 0 ? (
          <span className="text-meta text-muted">{t('views.import.noExpected')}</span>
        ) : (
          <details className="min-w-0">
            <summary className="cursor-pointer text-meta">
              <Badge tone="warning">{t('views.import.expected', { count: group.anomalies.length })}</Badge>
            </summary>
            <ul className="mt-1 flex flex-col gap-0.5 text-meta">
              {group.anomalies.map((a, i) => {
                const detail = anomalyDetail(t, a);
                return (
                  <li key={i} className="min-w-0 [overflow-wrap:anywhere]">
                    <span className="font-medium">{anomalyLabel(t, a.code)}</span>
                    <span className="text-muted">
                      {' '}
                      ({anomalyWhere(t, a)}){detail === '' ? '' : `: ${detail}`}
                    </span>
                  </li>
                );
              })}
            </ul>
          </details>
        )}
      </div>
    </div>
  );
}
