import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useSessionExports, useStartExport } from '../../api/exportQueries';
import { useServerInfo } from '../../api/queries';
import type { ExportRequest } from '../../api/types/ExportRequest';
import { Button } from '../../components/Button';
import { Dialog } from '../../components/Dialog';
import { ErrorNote } from '../../components/ErrorNote';
import { SegmentedControl } from '../../components/SegmentedControl';
import { TimeField } from '../../components/TimeField';
import { formatTimestamp, timeZoneLabel } from '../../lib/format';
import type { TimeRange } from '../../lib/timeRange';
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
  /** Active time range of the views: the dialog opens on it (docs/specs/time-filter.md). */
  activeRange?: TimeRange | null;
}

/** Save PCAP of the whole session or of a time range, then the progress of that export. */
export function SavePcapDialog({ open, ...rest }: SavePcapDialogProps) {
  // Mounted on opening: the form starts from the captured period each time.
  return open ? <OpenDialog {...rest} /> : null;
}

function OpenDialog({ sessionId, firstUs, lastUs, activeRange = null, onClose }: Omit<SavePcapDialogProps, 'open'>) {
  const { t } = useTranslation();
  const [scope, setScope] = useState<Scope>(activeRange === null ? 'session' : 'range');
  const startUs = activeRange?.fromUs ?? firstUs;
  const endUs = activeRange?.toUs ?? lastUs;
  const [from, setFrom] = useState(startUs === null ? '' : formatTimestamp(startUs));
  const [to, setTo] = useState(endUs === null ? '' : formatTimestamp(endUs));
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
  const formId = useId();
  const rangeError = touched && 'error' in range ? range.error : null;
  const describedBy = rangeError === null ? hintId : `${hintId} ${errorId}`;

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
    <Dialog
      open
      onClose={onClose}
      title={t('views.exportPcap.dialog.title')}
      description={t('views.exportPcap.dialog.description')}
      footer={
        <>
          <Button onClick={onClose}>{t('common.close')}</Button>
          <Button
            type="submit"
            form={formId}
            variant="primary"
            disabled={readOnly || running || start.isPending || (touched && invalid)}
            title={readOnly ? t('views.exportPcap.dialog.readOnly') : undefined}
          >
            {t('views.exportPcap.dialog.start')}
          </Button>
        </>
      }
    >
      <form
        id={formId}
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
              <TimeField label={t('views.exportPcap.dialog.from')} value={from} onChange={setFrom} describedBy={describedBy} />
              <TimeField label={t('views.exportPcap.dialog.to')} value={to} onChange={setTo} describedBy={describedBy} />
            </div>
            <p id={hintId} className="text-meta text-muted">
              {t('views.exportPcap.dialog.timeHint', { zone: timeZoneLabel() })}
            </p>
            {rangeError !== null && (
              <p id={errorId} role="alert" className="text-meta text-danger">
                {t(`views.exportPcap.dialog.${rangeError}`)}
              </p>
            )}
          </div>
        )}
        {start.isError && <ErrorNote error={start.error} />}
        {job !== undefined && <ExportStatus job={job} sessionId={sessionId} />}
      </form>
    </Dialog>
  );
}
