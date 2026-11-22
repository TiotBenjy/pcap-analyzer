import { cn } from '../lib/cn';
import { formatPreciseTimestamp, formatTimestamp, isoTimestamp, timeZoneLabel } from '../lib/format';

interface TimestampProps {
  /** Microseconds since the epoch (UTC); nothing is rendered for `null`. */
  us: number | null;
  /** `false` drops the date (every time of the list falls on the same day). */
  withDate?: boolean;
  className?: string;
}

/**
 * The only rendering of a packet time in the UI: ISO-like 24-hour local time
 * (`2026-11-08 14:03:12`, the same in every language), tabular digits, and on hover the time
 * to the microsecond with its time zone. Text contexts (tooltips, sentences) use
 * `formatTimestamp` directly.
 */
export function Timestamp({ us, withDate = true, className }: TimestampProps) {
  if (us === null) return null;
  const text = formatTimestamp(us, withDate);
  if (text === '') return null;
  return (
    <time dateTime={isoTimestamp(us)} title={`${formatPreciseTimestamp(us)} ${timeZoneLabel()}`} className={cn('num', className)}>
      {text}
    </time>
  );
}
