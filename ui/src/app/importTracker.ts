import { useSyncExternalStore } from 'react';
import { ApiError } from '../api/client';
import { cancelImport, streamImportEvents } from '../api/sessions';
import type { AnomalyInfo } from '../api/types/AnomalyInfo';
import type { ImportEvent } from '../api/types/ImportEvent';
import type { ImportProgress } from '../api/types/ImportProgress';

// Running import, kept outside React so that it survives closing the import wizard and changing
// views. The AppShell shows a discreet indicator that reopens the progress.

export type PickKind = 'folder' | 'file';
/**
 * `lost`: the event stream ended (or the connection dropped) without a final event; the import
 * may still be running on the backend, and `trackImport` reconnects to it.
 */
export type ImportStatus = 'running' | 'cancelling' | 'done' | 'failed' | 'lost';
export type ImportResult = Extract<ImportEvent, { type: 'done' }>;

/** Warnings kept for the log; further ones are only counted. */
export const MAX_WARNINGS = 500;

export interface TrackedImport {
  sessionId: string;
  name: string;
  status: ImportStatus;
  progress: ImportProgress | null;
  warnings: AnomalyInfo[];
  warningCount: number;
  result: ImportResult | null;
  /** Backend message of a `failed` event. */
  error: string | null;
  /** HTTP error that ended the stream (`failed` without a backend message). */
  streamError: Error | null;
  /** Last cancel request failed. */
  cancelError: Error | null;
}

export interface ImportState {
  current: TrackedImport | null;
  wizardOpen: boolean;
  wizardKind: PickKind;
}

let state: ImportState = { current: null, wizardOpen: false, wizardKind: 'folder' };
let controller: AbortController | null = null;
const listeners = new Set<() => void>();
const settledListeners = new Set<(imp: TrackedImport) => void>();

function set(next: Partial<ImportState>): void {
  state = { ...state, ...next };
  listeners.forEach((l) => {
    l();
  });
}

function update(sessionId: string, patch: (cur: TrackedImport) => Partial<TrackedImport>): void {
  const cur = state.current;
  if (cur?.sessionId !== sessionId) return; // stale stream of a replaced import
  const next = { ...cur, ...patch(cur) };
  set({ current: next });
  if (!isActive(next) && isActive(cur)) {
    settledListeners.forEach((l) => {
      l(next);
    });
  }
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function getImportState(): ImportState {
  return state;
}

export function useImportState(): ImportState {
  return useSyncExternalStore(subscribe, getImportState, getImportState);
}

/** Called when the tracked import stops being active (done, failed, lost). Returns an unsubscribe. */
export function onImportSettled(listener: (imp: TrackedImport) => void): () => void {
  settledListeners.add(listener);
  return () => settledListeners.delete(listener);
}

export function isActive(imp: TrackedImport | null): boolean {
  return imp !== null && (imp.status === 'running' || imp.status === 'cancelling');
}

/** Share of bytes read, 0..1 (0 while unknown). */
export function importFraction(done: number, total: number): number {
  return total > 0 ? Math.min(1, Math.max(0, done / total)) : 0;
}

function onEvent(sessionId: string, ev: ImportEvent): void {
  switch (ev.type) {
    case 'progress': {
      const { bytes_done, bytes_total, chunk_index, chunk_count, chunk_name, packets, rate_bps, eta_s, phase } = ev;
      const progress: ImportProgress = {
        bytes_done,
        bytes_total,
        chunk_index,
        chunk_count,
        chunk_name,
        packets,
        rate_bps,
        eta_s,
        phase,
      };
      update(sessionId, () => ({ progress }));
      break;
    }
    case 'warning': {
      const warning: AnomalyInfo = { id: ev.id, code: ev.code, chunk: ev.chunk, ts_us: ev.ts_us, detail: ev.detail };
      update(sessionId, (cur) => ({
        warnings: cur.warnings.length < MAX_WARNINGS ? [...cur.warnings, warning] : cur.warnings,
        warningCount: cur.warningCount + 1,
      }));
      break;
    }
    case 'done':
      update(sessionId, () => ({ status: 'done', result: ev }));
      break;
    case 'failed':
      update(sessionId, () => ({ status: 'failed', error: ev.message }));
      break;
  }
}

/**
 * Follows the events of an import (just started, or found `importing` in the sessions list).
 * Replaces any previously tracked import.
 */
export function trackImport(sessionId: string, name: string): void {
  controller?.abort();
  const ctrl = new AbortController();
  controller = ctrl;
  set({
    current: {
      sessionId,
      name,
      status: 'running',
      progress: null,
      warnings: [],
      warningCount: 0,
      result: null,
      error: null,
      streamError: null,
      cancelError: null,
    },
  });
  // End of the stream without a final event: lost, unless the backend answered with an HTTP error.
  const finish = (error: unknown) => {
    if (ctrl.signal.aborted) return;
    const httpError = error instanceof ApiError && error.status !== 0 ? error : null;
    update(sessionId, (cur) =>
      isActive(cur) ? (httpError === null ? { status: 'lost' } : { status: 'failed', streamError: httpError }) : {},
    );
  };
  let started: Promise<void>;
  try {
    const onStreamEvent = (ev: ImportEvent) => {
      if (!ctrl.signal.aborted) onEvent(sessionId, ev);
    };
    started = streamImportEvents(sessionId, onStreamEvent, ctrl.signal);
  } catch (e) {
    started = Promise.reject(e instanceof Error ? e : new Error(String(e)));
  }
  started.then(
    () => {
      finish(null);
    },
    (e: unknown) => {
      finish(e);
    },
  );
}

/** Asks the backend to stop; the stream then ends with `done` (state `incomplete`). */
export async function cancelTrackedImport(): Promise<void> {
  const cur = state.current;
  if (cur === null || cur.status !== 'running') return;
  const { sessionId } = cur;
  update(sessionId, () => ({ status: 'cancelling', cancelError: null }));
  try {
    await cancelImport(sessionId);
  } catch (e) {
    update(sessionId, (c) =>
      c.status === 'cancelling' ? { status: 'running', cancelError: e instanceof Error ? e : new Error(String(e)) } : {},
    );
  }
}

/** Forgets a finished import (the indicator disappears). Running imports are kept. */
export function clearTrackedImport(): void {
  if (isActive(state.current)) return;
  controller?.abort();
  controller = null;
  set({ current: null });
}

/** Opens the wizard: progress of the running import if any, else a new import of `kind`. */
export function openImportWizard(kind: PickKind): void {
  if (!isActive(state.current)) clearTrackedImport();
  set({ wizardOpen: true, wizardKind: kind });
}

export function reopenImportProgress(): void {
  set({ wizardOpen: true });
}

/** Closes the wizard; a running import goes on, a finished one is forgotten. */
export function closeImportWizard(): void {
  set({ wizardOpen: false });
  if (state.current !== null && !isActive(state.current)) clearTrackedImport();
}

/** Test helper: back to the initial state. */
export function resetImportTracker(): void {
  controller?.abort();
  controller = null;
  state = { current: null, wizardOpen: false, wizardKind: 'folder' };
  listeners.forEach((l) => {
    l();
  });
}
