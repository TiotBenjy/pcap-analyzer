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
  endpointPromise ??= resolveEndpoint();
  return endpointPromise;
}

interface Problem {
  type?: string;
  title?: string;
  detail?: string;
}

export async function apiGet<T>(path: `/${string}`, signal?: AbortSignal): Promise<T> {
  const { baseUrl, token } = await getEndpoint();
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (token !== null) headers.Authorization = `Bearer ${token}`;

  let res: Response;
  try {
    res = await fetch(`${baseUrl}${path}`, { headers, ...(signal === undefined ? {} : { signal }) });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'AbortError') throw e;
    throw new ApiError(0, 'network', 'Backend unreachable');
  }
  if (!res.ok) {
    let problem: Problem = {};
    try {
      problem = (await res.json()) as Problem;
    } catch {
      /* not a problem document */
    }
    throw new ApiError(res.status, problem.type ?? 'http', problem.detail ?? problem.title ?? res.statusText);
  }
  return (await res.json()) as T;
}
