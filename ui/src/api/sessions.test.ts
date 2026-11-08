import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, SseParser } from './client';
import {
  browse,
  cancelImport,
  deleteSession,
  listChunks,
  listSessions,
  renameSession,
  scanImport,
  startImport,
  streamImportEvents,
} from './sessions';
import type { ImportEvent } from './types/ImportEvent';

const fetchMock = vi.fn<typeof fetch>();

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  fetchMock.mockReset();
  vi.unstubAllGlobals();
});

function json(body: unknown, status = 200, type = 'application/json'): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': type } });
}

/** Response whose body is delivered in the given text chunks. */
function sse(chunks: string[], onPull?: (index: number) => void): Response {
  const encoder = new TextEncoder();
  let index = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      onPull?.(index);
      const chunk = chunks[index];
      index += 1;
      if (chunk === undefined) controller.close();
      else controller.enqueue(encoder.encode(chunk));
    },
  });
  return new Response(body, { status: 200, headers: { 'Content-Type': 'text/event-stream' } });
}

function lastCall(): { url: string; init: RequestInit } {
  const call = fetchMock.mock.calls.at(-1);
  if (call === undefined) throw new Error('fetch not called');
  return { url: String(call[0]), init: call[1] ?? {} };
}

describe('sessions client', () => {
  it('lists sessions with page parameters', async () => {
    fetchMock.mockResolvedValueOnce(json({ items: [], next_cursor: null, total_estimate: 0 }));
    const page = await listSessions({ limit: 10, cursor: 'a~b' });
    expect(page.total_estimate).toBe(0);
    expect(lastCall().url).toBe('/api/v1/sessions?limit=10&cursor=a%7Eb');
    expect(lastCall().init.method).toBe('GET');

    fetchMock.mockResolvedValueOnce(json({ items: [], next_cursor: null, total_estimate: null }));
    await listChunks('01ABC', { cursor: null });
    expect(lastCall().url).toBe('/api/v1/sessions/01ABC/chunks');
  });

  it('sends JSON bodies for mutations', async () => {
    fetchMock.mockResolvedValueOnce(json({ id: 'x', name: 'New' }));
    await renameSession('x', 'New');
    const { url, init } = lastCall();
    expect(url).toBe('/api/v1/sessions/x');
    expect(init.method).toBe('PATCH');
    expect(init.body).toBe('{"name":"New"}');
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json');

    fetchMock.mockResolvedValueOnce(json({ session_id: 'S1' }, 202));
    await expect(startImport({ path: '/captures/run', group_ids: [0], name: null, recursive: false })).resolves.toEqual({
      session_id: 'S1',
    });
    expect(lastCall().init.method).toBe('POST');
    expect(lastCall().url).toBe('/api/v1/sessions/import');

    fetchMock.mockResolvedValueOnce(json({ path: '/c', groups: [], skipped: [], truncated: false }));
    await scanImport({ path: '/c', recursive: true });
    expect(lastCall().url).toBe('/api/v1/sessions/import/scan');
    expect(lastCall().init.body).toBe('{"path":"/c","recursive":true}');
  });

  it('resolves empty responses', async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));
    await expect(deleteSession('a/b')).resolves.toBeUndefined();
    expect(lastCall().url).toBe('/api/v1/sessions/a%2Fb');
    expect(lastCall().init.method).toBe('DELETE');

    fetchMock.mockResolvedValueOnce(new Response(null, { status: 202 }));
    await expect(cancelImport('S1')).resolves.toBeUndefined();
    expect(lastCall().url).toBe('/api/v1/sessions/S1/cancel');
  });

  it('maps problem documents and network failures to ApiError', async () => {
    fetchMock.mockResolvedValueOnce(
      json({ type: 'urn:netsift:problem:read-only', title: 'Server is read-only', status: 403 }, 403, 'application/problem+json'),
    );
    const err = await deleteSession('x').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 403, kind: 'urn:netsift:problem:read-only', message: 'Server is read-only' });

    fetchMock.mockRejectedValueOnce(new TypeError('failed'));
    await expect(listSessions()).rejects.toMatchObject({ status: 0, kind: 'network' });
  });

  it('encodes the browsed path', async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(json({ path: '/captures', parent: null, roots: ['/captures'], entries: [] })),
    );
    await browse();
    expect(lastCall().url).toBe('/api/v1/fs/browse');
    await browse('/captures/a b&c');
    expect(lastCall().url).toBe('/api/v1/fs/browse?path=%2Fcaptures%2Fa+b%26c');
  });
});

describe('streamImportEvents', () => {
  const progress =
    '{"type":"progress","bytes_done":5,"bytes_total":10,"chunk_index":0,"chunk_count":2,"chunk_name":"a","packets":3,"rate_bps":1.5,"eta_s":null,"phase":"reading"}';

  it('parses events split across chunks and stops at the final event', async () => {
    const pulled: number[] = [];
    fetchMock.mockResolvedValueOnce(
      sse(
        [
          ': keep-alive\n\nevent: prog',
          `ress\r\ndata: ${progress.slice(0, 20)}`,
          `${progress.slice(20)}\r`,
          '\n\r\nevent: done\ndata: {"type":"done","state":"ready","packets":3,"flows":1,"anomalies":0,"duration_s":0.5}\n\n',
          'event: progress\ndata: {"type":"progress"}\n\n',
        ],
        (i) => pulled.push(i),
      ),
    );
    const events: ImportEvent[] = [];
    await streamImportEvents('S1', (e) => events.push(e), new AbortController().signal);
    expect(events.map((e) => e.type)).toEqual(['progress', 'done']);
    expect(events[0]).toMatchObject({ bytes_done: 5, chunk_name: 'a' });
    expect(events[1]).toMatchObject({ state: 'ready', flows: 1 });
    expect(pulled).not.toContain(5);
    const { url, init } = lastCall();
    expect(url).toBe('/api/v1/sessions/S1/events');
    expect((init.headers as Record<string, string>).Accept).toBe('text/event-stream');
  });

  it('resolves at the end of the stream and skips malformed data', async () => {
    fetchMock.mockResolvedValueOnce(sse(['event: warning\ndata: {oops\n\n', 'data: {"type":"other"}\n\n']));
    const onEvent = vi.fn();
    await streamImportEvents('S1', onEvent, new AbortController().signal);
    expect(onEvent).not.toHaveBeenCalled();
  });

  it('rejects with ApiError on an HTTP error', async () => {
    fetchMock.mockResolvedValueOnce(
      json({ type: 'urn:netsift:problem:not-found', title: 'Resource not found' }, 404, 'application/problem+json'),
    );
    await expect(streamImportEvents('S1', vi.fn(), new AbortController().signal)).rejects.toMatchObject({
      status: 404,
      kind: 'urn:netsift:problem:not-found',
    });
  });

  it('resolves when the signal aborts', async () => {
    const controller = new AbortController();
    fetchMock.mockImplementationOnce((_url, init) => {
      const signal = init?.signal;
      const body = new ReadableStream<Uint8Array>({
        start(c) {
          c.enqueue(new TextEncoder().encode(`event: progress\ndata: ${progress}\n\n`));
          signal?.addEventListener('abort', () => c.error(new DOMException('aborted', 'AbortError')));
        },
      });
      return Promise.resolve(new Response(body, { status: 200 }));
    });
    const events: ImportEvent[] = [];
    const done = streamImportEvents(
      'S1',
      (e) => {
        events.push(e);
        controller.abort();
      },
      controller.signal,
    );
    await expect(done).resolves.toBeUndefined();
    expect(events).toHaveLength(1);
  });

  it('turns a broken stream into a network ApiError', async () => {
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        c.error(new TypeError('connection reset'));
      },
    });
    fetchMock.mockResolvedValueOnce(new Response(body, { status: 200 }));
    await expect(streamImportEvents('S1', vi.fn(), new AbortController().signal)).rejects.toMatchObject({
      status: 0,
      kind: 'network',
    });
  });
});

describe('SseParser', () => {
  it('joins data lines, ignores comments and unknown fields', () => {
    const p = new SseParser();
    expect(p.push('id: 1\nretry: 5\n: c\ndata: a\ndata:b\n')).toEqual([]);
    expect(p.push('\n')).toEqual([{ event: 'message', data: 'a\nb' }]);
    expect(p.push('event: x\r')).toEqual([]);
    // A trailing '\r' may be the start of '\r\n': kept until the next chunk.
    expect(p.push('\ndata: y\r\r')).toEqual([]);
    expect(p.push('\n')).toEqual([{ event: 'x', data: 'y' }]);
  });
});
