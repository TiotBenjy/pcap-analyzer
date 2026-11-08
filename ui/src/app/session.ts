import { useRouterState } from '@tanstack/react-router';
import { useSyncExternalStore } from 'react';
import { readPref, writePref } from '../lib/storage';

// Session-scoped routes (ADR-010): analysis views live under
// `/sessions/$sessionId/<view>`. The last opened session is remembered (an opaque ULID, no capture
// data) so that the sidebar and legacy links such as `/overview` can point to it.

const STORAGE_KEY = 'netsift.session.last';
const SESSION_PATH = /^\/sessions\/([^/]+)(\/.*)?$/;

/** Crockford base32 ULID, the only session id format written to storage. */
const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/i;

export function isSessionId(id: string): boolean {
  return ULID.test(id);
}

const listeners = new Set<() => void>();
const stored = readPref(STORAGE_KEY);
let lastId: string | null = stored !== null && isSessionId(stored) ? stored : null;

function emit(): void {
  listeners.forEach((l) => {
    l();
  });
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function getLastSessionId(): string | null {
  return lastId;
}

/** Remembers `id` as the last opened session; ignores anything that is not a ULID. */
export function rememberSession(id: string): void {
  if (lastId === id || !isSessionId(id)) return;
  lastId = id;
  writePref(STORAGE_KEY, id);
  emit();
}

/** Forgets `id` if it is the remembered session (deleted, or unknown to the backend). */
export function forgetSession(id: string): void {
  if (lastId !== id) return;
  lastId = null;
  writePref(STORAGE_KEY, null);
  emit();
}

/** Splits a session route: `/sessions/abc/dns` -> `{ sessionId: 'abc', rest: '/dns' }`. */
export function parseSessionPath(pathname: string): { sessionId: string; rest: string } | null {
  const m = SESSION_PATH.exec(pathname);
  if (m === null || m[1] === undefined) return null;
  return { sessionId: decodeURIComponent(m[1]), rest: m[2] ?? '/' };
}

export function sessionPath(sessionId: string, view: string): string {
  return `/sessions/${encodeURIComponent(sessionId)}/${view.replace(/^\//, '')}`;
}

export function useLastSessionId(): string | null {
  return useSyncExternalStore(subscribe, getLastSessionId, getLastSessionId);
}

/** Session shown by the analysis views: the one in the URL, else the last opened one. */
export function useActiveSessionId(): string | null {
  const fromUrl = useRouterState({ select: (s) => parseSessionPath(s.location.pathname)?.sessionId ?? null });
  const last = useLastSessionId();
  return fromUrl ?? last;
}
