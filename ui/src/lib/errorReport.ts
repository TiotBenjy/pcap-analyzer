// Error report of the route error screen (components/RouteError.tsx). A release build has no
// devtools: "Copy details" gives the message and the stack, so a desktop bug can be reported.
// The report holds no capture data: error, stack, route pattern (session id masked) and user
// agent only.

/** Text copied by "Copy details". */
export function errorDetails(error: unknown, hash: string, userAgent: string): string {
  const err = error instanceof Error ? error : null;
  const head = err !== null ? `${err.name}: ${err.message}` : `Non-Error thrown: ${safeString(error)}`;
  // Session ids are opaque, but the report only needs the view.
  const route = hash
    .replace(/^#/, '')
    .replace(/\/sessions\/[^/?#]+/, '/sessions/:id')
    .replace(/\?.*$/, '');
  return [head, '', `route: ${route || '/'}`, `user agent: ${userAgent}`, '', err?.stack ?? '(no stack)'].join('\n');
}

function safeString(value: unknown): string {
  try {
    return String(value);
  } catch {
    return typeof value;
  }
}

/** Copies through the Clipboard API, else through a selected text area (older webviews). */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return copyWithSelection(text);
  }
}

function copyWithSelection(text: string): boolean {
  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.className = 'fixed top-0 -left-[9999px]';
  document.body.append(area);
  area.select();
  try {
    return document.execCommand('copy');
  } catch {
    return false;
  } finally {
    area.remove();
  }
}
