import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useSessionExports, useStartExport } from '../../api/exportQueries';
import { useServerInfo } from '../../api/queries';
import type { ExportRequest } from '../../api/types/ExportRequest';
import { Button } from '../../components/Button';
import { Dialog } from '../../components/Dialog';
import { ErrorNote } from '../../components/ErrorNote';
import { SegmentedControl } from '../../components/SegmentedControl';
import { formatTimestamp, timeZoneLabel } from '../../lib/format';
import { ExportStatus } from './ExportStatus';
import { rangeRequest } from './range';

type Scope = 'session' | 'range';

interface SavePcapDialogProps {
  open: boolean;
  onClose: () => void;
  sessionId: string;
  /** Captured period, to prefill the range (microseconds). */
  firstUs: number | null;
  lastUs: number | null;
}

/** Save PCAP of the whole session or of a time range, then the progress of that export. */
export function SavePcapDialog({ open, onClose, sessionId, firstUs, lastUs }: SavePcapDialogProps) {
  const { t } = useTranslation();
  return (
    <Dialog open={open} onClose={onClose} title={t('views.exportPcap.dialog.title')} description={t('views.exportPcap.dialog.description')}>
      {open && <DialogBody sessionId={sessionId} firstUs={firstUs} lastUs={lastUs} onClose={onClose} />}
    </Dialog>
  );
}

function DialogBody({ sessionId, firstUs, lastUs, onClose }: Omit<SavePcapDialogProps, 'open'>) {
  const { t } = useTranslation();
  const [scope, setScope] = useState<Scope>('session');
  const [from, setFrom] = useState(firstUs === null ? '' : formatTimestamp(firstUs));
  const [to, setTo] = useState(lastUs === null ? '' : formatTimestamp(lastUs));
  const [jobId, setJobId] = useState<string | null>(null);
  const [touched, setTouched] = useState(false);
  const start = useStartExport(sessionId);
  const jobs = useSessionExports(sessionId, jobId !== null);
  const readOnly = useServerInfo().data?.read_only === true;
  const job = jobs.data?.find((j) => j.id === jobId) ?? (start.data?.id === jobId ? start.data : undefined);
  const running = job?.state === 'running';
  const range = rangeRequest(from, to);
  const invalid = scope === 'range' && 'error' in range;
  const hintId = useId();
  const errorId = useId();

  const submit = () => {
    setTouched(true);
    let request: ExportRequest = { scope: 'session' };
    if (scope === 'range') {
      if ('error' in range) return;
      request = range.request;
    }
    start.mutate(request, {
      onSuccess: (created) => {
        setJobId(created.id);
      },
    });
  };

  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        submit();
      }}
    >
      <SegmentedControl
        label={t('views.exportPcap.dialog.scope')}
        value={scope}
        options={[
          { value: 'session', label: t('views.exportPcap.dialog.session') },
          { value: 'range', label: t('views.exportPcap.dialog.range') },
        ]}
        onChange={setScope}
      />
      {scope === 'range' && (
        <div className="flex flex-col gap-2">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <TimeField label={t('views.exportPcap.dialog.from')} value={from} onChange={setFrom} describedBy={`${hintId} ${errorId}`} />
            <TimeField label={t('views.exportPcap.dialog.to')} value={to} onChange={setTo} describedBy={`${hintId} ${errorId}`} />
          </div>
          <p id={hintId} className="text-meta text-muted">
            {t('views.exportPcap.dialog.timeHint', { zone: timeZoneLabel() })}
          </p>
          <p id={errorId} role="alert" className="text-meta text-danger">
            {touched && 'error' in range ? t(`views.exportPcap.dialog.${range.error}`) : null}
          </p>
        </div>
      )}
      {start.isError && <ErrorNote error={start.error} />}
      {job !== undefined && <ExportStatus job={job} sessionId={sessionId} />}
      <div className="flex flex-wrap items-center justify-end gap-2 border-t border-line pt-3">
        <Button onClick={onClose}>{t('common.close')}</Button>
        <Button
          type="submit"
          variant="primary"
          disabled={readOnly || running || start.isPending || (touched && invalid)}
          title={readOnly ? t('views.exportPcap.dialog.readOnly') : undefined}
        >
          {t('views.exportPcap.dialog.start')}
        </Button>
      </div>
    </form>
  );
}

function TimeField({
  label,
  value,
  onChange,
  describedBy,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  describedBy: string;
}) {
  return (
    <label className="flex min-w-0 flex-col gap-1">
      <span className="text-meta text-muted">{label}</span>
      <input
        type="text"
        inputMode="numeric"
        spellCheck={false}
        autoComplete="off"
        value={value}
        aria-describedby={describedBy}
        onChange={(e) => {
          onChange(e.target.value);
        }}
        className="h-8 w-full min-w-0 rounded-md border border-line bg-surface px-2 font-mono text-body"
      />
    </label>
  );
}
