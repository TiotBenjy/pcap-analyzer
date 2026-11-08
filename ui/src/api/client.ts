// Typed access to the NetSift HTTP API.
//
// Endpoint resolution:
// - web (./x.sh dev, vite preview for screenshots): same-origin `/api/v1`, the Vite proxy adds
//   the bearer token, so it never reaches the page;
// - desktop (Tauri): URL and token come from the `get_api_endpoint` command (see resolveEndpoint).

export interface ApiEndpoint {
  baseUrl: string;
  token: string | null;
}

/** Error carrying an RFC 9457 problem document (or a network failure). */
export class ApiError extends Error {
  readonly status: number;
  readonly kind: string;

  constructor(status: number, kind: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.kind = kind;
  }
}

let endpointPromise: Promise<ApiEndpoint> | null = null;

/** True inside the Tauri webview (the IPC bridge is injected before any page script). */
export function isDesktop(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

async function resolveEndpoint(): Promise<ApiEndpoint> {
  if (isDesktop()) {
    // Loaded on demand: the web build never pulls the Tauri bridge into its main chunk.
    const { invoke } = await import('@tauri-apps/api/core');
    const ep = await invoke<{ base_url: string; token: string }>('get_api_endpoint');
    return { baseUrl: ep.base_url, token: ep.token };
  }
  return { baseUrl: '/api/v1', token: null };
}

export function getEndpoint(): Promise<ApiEndpoint> {
  // A failed resolution is not cached: the next request retries.
  endpointPromise ??= resolveEndpoint().catch((e: unknown) => {
    endpointPromise = null;
    throw e;
  });
  return endpointPromise;
}

interface Problem {
  type?: string;
  title?: string;
  detail?: string;
}

export type ApiPath = `/${string}`;

function isAbort(e: unknown): boolean {
  return e instanceof DOMException && e.name === 'AbortError';
}

/** Builds an `ApiError` from a non-2xx response (problem+json body when available). */
export async function errorFromResponse(res: Response): Promise<ApiError> {
  let problem: Problem = {};
  try {
    problem = (await res.json()) as Problem;
  } catch {
    /* not a problem document */
  }
  return new ApiError(res.status, problem.type ?? 'http', problem.detail ?? problem.title ?? res.statusText);
}

/** Sends a request with the bearer token (desktop) and maps failures to `ApiError`. */
export async function apiFetch(
  path: ApiPath,
  init: { method?: string; body?: unknown; accept?: string; signal?: AbortSignal | undefined } = {},
): Promise<Response> {
  const { baseUrl, token } = await getEndpoint();
  const headers: Record<string, string> = { Accept: init.accept ?? 'application/json' };
  if (token !== null) headers.Authorization = `Bearer ${token}`;
  const request: RequestInit = { method: init.method ?? 'GET', headers };
  if (init.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    request.body = JSON.stringify(init.body);
  }
  if (init.signal !== undefined) request.signal = init.signal;

  let res: Response;
  try {
    res = await fetch(`${baseUrl}${path}`, request);
  } catch (e) {
    if (isAbort(e)) throw e;
    throw new ApiError(0, 'network', 'Backend unreachable');
  }
  if (!res.ok) throw await errorFromResponse(res);
  return res;
}

export async function apiGet<T>(path: ApiPath, signal?: AbortSignal): Promise<T> {
  const res = await apiFetch(path, { signal });
  return (await res.json()) as T;
}

/** POST / PATCH / DELETE with an optional JSON body; resolves to the JSON response. */
export async function apiSend<T>(method: 'POST' | 'PATCH' | 'DELETE', path: ApiPath, body?: unknown, signal?: AbortSignal): Promise<T> {
  const res = await apiFetch(path, { method, body, signal });
  return (await res.json()) as T;
}

/** Same as `apiSend` for responses without body (202, 204). */
export async function apiSendEmpty(method: 'POST' | 'PATCH' | 'DELETE', path: ApiPath, body?: unknown): Promise<void> {
  const res = await apiFetch(path, { method, body });
  // Drain the body so the connection can be reused.
  await res.arrayBuffer().catch(() => undefined);
}

/** One server-sent event (`event:` name and joined `data:` lines). */
export interface SseMessage {
  event: string;
  data: string;
}

/**
 * Incremental SSE parser (https://html.spec.whatwg.org/multipage/server-sent-events.html):
 * feed text chunks of any size, get complete messages back. Comments and `id`/`retry`
 * fields are ignored.
 */
export class SseParser {
  private buffer = '';
  private event = '';
  private data: string[] = [];

  push(chunk: string): SseMessage[] {
    this.buffer += chunk;
    const out: SseMessage[] = [];
    for (;;) {
      const match = /\r\n|\r|\n/.exec(this.buffer);
      if (match === null) break;
      // A lone '\r' at the end may be the first half of '\r\n': wait for more input.
      if (match[0] === '\r' && match.index === this.buffer.length - 1) break;
      const line = this.buffer.slice(0, match.index);
      this.buffer = this.buffer.slice(match.index + match[0].length);
      const message = this.line(line);
      if (message !== null) out.push(message);
    }
    return out;
  }

  private line(line: string): SseMessage | null {
    if (line === '') {
      if (this.data.length === 0) {
        this.event = '';
        return null;
      }
      const message = { event: this.event === '' ? 'message' : this.event, data: this.data.join('\n') };
      this.event = '';
      this.data = [];
      return message;
    }
    if (line.startsWith(':')) return null;
    const colon = line.indexOf(':');
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? '' : line.slice(colon + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (field === 'event') this.event = value;
    else if (field === 'data') this.data.push(value);
    return null;
  }
}

/**
 * Reads an SSE response with `fetch` (so the bearer token can be sent) and calls `onMessage`
 * for each message until it returns `false`, the stream ends, or `signal` aborts (which
 * resolves). Rejects with `ApiError` on HTTP or network errors.
 */
export async function apiStream(
  path: ApiPath,
  onMessage: (message: SseMessage) => boolean,
  signal: AbortSignal,
): Promise<void> {
  let res: Response;
  try {
    res = await apiFetch(path, { accept: 'text/event-stream', signal });
  } catch (e) {
    if (isAbort(e)) return;
    throw e;
  }
  if (res.body === null) return;
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  const parser = new SseParser();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      for (const message of parser.push(decoder.decode(value, { stream: true }))) {
        if (!onMessage(message)) return;
      }
    }
  } catch (e) {
    if (isAbort(e) || signal.aborted) return;
    throw new ApiError(0, 'network', 'Event stream interrupted');
  } finally {
    reader.cancel().catch(() => undefined);
  }
}
