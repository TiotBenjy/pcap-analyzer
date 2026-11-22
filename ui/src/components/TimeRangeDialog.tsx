import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { timeZoneLabel } from '../lib/format';
import { parseRangeInput, rangeInput, type TimeRange } from '../lib/timeRange';
import { Button } from './Button';
import { Dialog } from './Dialog';
import { TimeField } from './TimeField';

interface TimeRangeDialogProps {
  open: boolean;
  onClose: () => void;
  /** Range in the fields on opening: the active one, else the captured period. */
  initial: TimeRange | null;
  /** `null` clears the range. */
  onApply: (range: TimeRange | null) => void;
}

/** Typed time range of the views (local ISO time, same rules as Save PCAP). */
export function TimeRangeDialog({ open, ...rest }: TimeRangeDialogProps) {
  // Mounted on opening: the fields start from the current range each time.
  return open ? <OpenDialog {...rest} /> : null;
}

function OpenDialog({ onClose, initial, onApply }: Omit<TimeRangeDialogProps, 'open'>) {
  const { t } = useTranslation();
  const start = initial === null ? { from: '', to: '' } : rangeInput(initial);
  const [from, setFrom] = useState(start.from);
  const [to, setTo] = useState(start.to);
  const [touched, setTouched] = useState(false);
  const parsed = parseRangeInput(from, to);
  const error = touched && 'error' in parsed ? parsed.error : null;
  const hintId = useId();
  const errorId = useId();
  const formId = useId();
  const describedBy = error === null ? hintId : `${hintId} ${errorId}`;

  const apply = () => {
    setTouched(true);
    if ('error' in parsed) return;
    onApply(parsed.range);
    onClose();
  };

  return (
    <Dialog
      open
      onClose={onClose}
      title={t('timeRange.dialog.title')}
      description={t('timeRange.dialog.description')}
      footer={
        <>
          <Button
            onClick={() => {
              onApply(null);
              onClose();
            }}
          >
            {t('timeRange.dialog.clear')}
          </Button>
          <Button onClick={onClose}>{t('common.cancel')}</Button>
          <Button type="submit" form={formId} variant="primary" disabled={error !== null}>
            {t('timeRange.dialog.apply')}
          </Button>
        </>
      }
    >
      <form
        id={formId}
        className="flex flex-col gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          apply();
        }}
      >
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <TimeField label={t('timeRange.dialog.from')} value={from} onChange={setFrom} describedBy={describedBy} autoFocus />
          <TimeField label={t('timeRange.dialog.to')} value={to} onChange={setTo} describedBy={describedBy} />
        </div>
        <p id={hintId} className="text-meta text-muted">
          {t('timeRange.dialog.timeHint', { zone: timeZoneLabel() })}
        </p>
        {error !== null && (
          <p id={errorId} role="alert" className="text-meta text-danger">
            {t(`timeRange.dialog.${error}`)}
          </p>
        )}
      </form>
    </Dialog>
  );
}
