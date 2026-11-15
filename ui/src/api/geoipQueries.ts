import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { downloadGeoip, getGeoipStatus, getGeoipUpdate, importGeoip } from './geoip';
import type { ServerInfo } from './types/ServerInfo';

// Query hooks of the country database, shared by Settings > About, Settings > Online and the
// GeoIP notice: one update logic, whichever place starts it.

export const geoipKeys = {
  status: ['geoip-status'] as const,
  update: ['geoip-update'] as const,
};

export type GeoipUpdateRequest = { kind: 'download' } | { kind: 'import'; path: string };

/** Interval of the status requests while the startup check of DB-IP runs. */
const PENDING_INTERVAL = 2_000;

/** Freshness of the database in use (`GET /geoip/status`). */
export function useGeoipStatus() {
  return useQuery({
    queryKey: geoipKeys.status,
    queryFn: ({ signal }) => getGeoipStatus(signal),
    staleTime: 5 * 60_000,
    // The startup check of DB-IP decides the offer: ask again until it ends.
    refetchInterval: (query) => (query.state.data?.online === 'pending' ? PENDING_INTERVAL : false),
  });
}

/**
 * Update of the database by download (ADR-015, done by the backend) or from a file, with the
 * progress of a download. A success refreshes the state of Settings > About and the freshness.
 */
export function useGeoipUpdate() {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: (req: GeoipUpdateRequest) => (req.kind === 'download' ? downloadGeoip() : importGeoip(req.path)),
    // The progress of a previous download must not show at the start of the next one.
    onMutate: () => {
      queryClient.removeQueries({ queryKey: geoipKeys.update });
    },
    onSuccess: (geoip) => {
      queryClient.setQueryData<ServerInfo>(['server-info'], (old) => (old === undefined ? old : { ...old, geoip }));
      void queryClient.invalidateQueries({ queryKey: geoipKeys.status });
    },
  });
  const downloading = mutation.isPending && mutation.variables.kind === 'download';
  const progress = useQuery({
    queryKey: geoipKeys.update,
    queryFn: ({ signal }) => getGeoipUpdate(signal),
    enabled: downloading,
    refetchInterval: 500,
    staleTime: 0,
  });
  return { mutation, downloading, progress: progress.data };
}
