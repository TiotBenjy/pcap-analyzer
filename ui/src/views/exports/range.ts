import type { ExportRequest } from '../../api/types/ExportRequest';
import { parseRangeInput } from '../../lib/timeRange';

/** Request of the form, or the reason it cannot be sent (same rules as the range dialog). */
export function rangeRequest(from: string, to: string): { request: ExportRequest } | { error: 'invalidTime' | 'reversed' } {
  const parsed = parseRangeInput(from, to);
  if ('error' in parsed) return parsed;
  return { request: { scope: 'range', from_us: parsed.range.fromUs, to_us: parsed.range.toUs } };
}
