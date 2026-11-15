import type { ExportRequest } from '../../api/types/ExportRequest';
import { parseTimestamp } from '../../lib/format';

/** Request of the form, or the reason it cannot be sent. */
export function rangeRequest(from: string, to: string): { request: ExportRequest } | { error: 'invalidTime' | 'reversed' } {
  const fromUs = parseTimestamp(from);
  const toUs = parseTimestamp(to, true);
  if (fromUs === null || toUs === null) return { error: 'invalidTime' };
  if (toUs < fromUs) return { error: 'reversed' };
  return { request: { scope: 'range', from_us: fromUs, to_us: toUs } };
}
