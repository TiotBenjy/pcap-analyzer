import { useMutation, useMutationState, useQuery, useQueryClient } from '@tanstack/react-query';
import { downloadGeoip, getGeoipStatus, getGeoipUpdate, importGeoip } from './geoip';
import type { GeoipInfo } from './types/GeoipInfo';
import type { ServerInfo } from './types/ServerInfo';

// Query hooks of the country database, shared by Settings > About, Settings > Online and the
// GeoIP notice: one update logic, whichever place starts it.

export const geoipKeys = {
  status: ['geoip-status'] as const,
  update: ['geoip-update'] as const,
  /** Mutation key of the updates: every place sees an update started by another one. */
  run: ['geoip-update-run'] as const,
};

export type GeoipUpdateRequest = { kind: 'download' } | { kind: 'import'; path: string };

/** Result of an update, whichever its kind. */
export interface GeoipUpdateResult {
  info: GeoipInfo;
  /** Built after the database it replaces (always true for an imported file). */
  newer: boolean;
  /** Nothing newer is published yet: the notice is dismissed until the next month. */
  dismissed: boolean;
}

/** Interval of the status requests while the startup check of DB-IP runs. */
const PENDING_INTERVAL = 2_000;
/** Status requests at most while the check runs (about one minute, longer than its timeouts). */
const PENDING_POLLS = 30;

/** Freshness of the database in use (`GET /geoip/status`). */
export function useGeoipStatus() {
  return useQuery({
    queryKey: geoipKeys.status,
    queryFn: ({ signal }) => getGeoipStatus(signal),
    staleTime: 5 * 60_000,
    refetchInterval: (query) => pendingInterval(query.state),
  });
}

/**
 * Interval of the next status request: the startup check of DB-IP decides the offer, so ask
 * again until it ends, a bounded number of times, and never after an error.
 */
export function pendingInterval(state: {
  status: string;
  data?: { online?: unknown } | undefined;
  dataUpdateCount: number;
}): number | false {
  return state.status !== 'error' && state.data?.online === 'pending' && state.dataUpdateCount < PENDING_POLLS
    ? PENDING_INTERVAL
    : false;
}

async function runUpdate(req: GeoipUpdateRequest): Promise<GeoipUpdateResult> {
  if (req.kind === 'import') return { info: await importGeoip(req.path), newer: true, dismissed: false };
  const { info, newer, dismissed } = await downloadGeoip();
  return { info, newer, dismissed };
}

/**
 * Update of the database by download (ADR-015, done by the backend) or from a file, with the
 * progress of a download. `busy` and `downloading` cover the updates started from any place (one
 * runs at a time on the server); the result and the error are those of this place. A success
 * refreshes the state of Settings > About and the freshness.
 */
export function useGeoipUpdate() {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationKey: geoipKeys.run,
    mutationFn: runUpdate,
    // The progress of a previous download must not show at the start of the next one.
    onMutate: () => {
      queryClient.removeQueries({ queryKey: geoipKeys.update });
    },
    onSuccess: ({ info }) => {
      queryClient.setQueryData<ServerInfo>(['server-info'], (old) => (old === undefined ? old : { ...old, geoip: info }));
      void queryClient.invalidateQueries({ queryKey: geoipKeys.status });
    },
  });
  const running = useMutationState({
    filters: { mutationKey: geoipKeys.run, status: 'pending' },
    select: (m) => m.state.variables as GeoipUpdateRequest | undefined,
  });
  const busy = running.length > 0;
  const downloading = running.some((req) => req?.kind === 'download');
  const progress = useQuery({
    queryKey: geoipKeys.update,
    queryFn: ({ signal }) => getGeoipUpdate(signal),
    enabled: downloading,
    refetchInterval: 500,
    staleTime: 0,
  });
  return { mutation, busy, downloading, progress: progress.data };
}
