// Text helpers of chart labels and tooltips. Labels come from the capture (hostile input):
// ECharts tooltips are HTML, so every captured string goes through `escapeHtml`.

/** Chart labels longer than this are cut (the full text is in the tooltip). */
export const LABEL_MAX = 24;

/** Escapes text for an HTML tooltip. */
export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c);
}

/** Cuts a label at `max` characters, ending with an ellipsis. */
export function truncateLabel(s: string, max = LABEL_MAX): string {
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}

/** Cuts in the middle (`ECDHE_ECDSA…GCM_SHA256`) when both ends tell labels apart. */
export function truncateMiddle(s: string, max = LABEL_MAX): string {
  if (s.length <= max) return s;
  const tail = Math.floor((max - 1) / 2);
  const head = max - 1 - tail;
  return `${s.slice(0, head)}…${s.slice(s.length - tail)}`;
}
