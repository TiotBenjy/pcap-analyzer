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
