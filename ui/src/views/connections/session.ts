import type { SessionSummary } from '../../api/types/SessionSummary';

/** True when the analysis routes of the session answer (not importing, not failed). */
export function isViewable(session: SessionSummary | undefined): boolean {
  return session?.state === 'ready' || session?.state === 'incomplete';
}
