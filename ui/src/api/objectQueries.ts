import { useViewRange } from '../app/timeRange';
import { rangeKey, type TimeRange } from '../lib/timeRange';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { fetchRendition, getPictureStats, listPictures, type PictureFilters } from './objects';
import { fetchAll } from './sessionQueries';

// Query hooks of the Pictures view, under the session detail key (invalidated with the session).

/** Pictures loaded in the grid (the view tells when the list is cut). */
export const PICTURES_LIST_LIMIT = 5000;

export const objectKeys = {
  stats: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'objects', 'stats', rangeKey(range)] as const,
  pictures: (id: string, filters: PictureFilters, range: TimeRange | null = null) => ['sessions', 'detail', id, 'objects', 'pictures', filters, rangeKey(range)] as const,
  rendition: (id: string, sha256: string, kind: 'thumb' | 'preview') =>
    ['sessions', 'detail', id, 'objects', kind, sha256] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function usePictureStats(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({ queryKey: objectKeys.stats(id, range), queryFn: ({ signal }) => getPictureStats(id, signal, range), enabled });
}

export function usePictures(id: string, filters: PictureFilters, enabled: boolean) {
  const range = useViewRange();
  return useQuery({
    queryKey: objectKeys.pictures(id, filters, range),
    queryFn: ({ signal }) => fetchAll((p) => listPictures(id, filters, p, signal, range), PICTURES_LIST_LIMIT),
    enabled,
    placeholderData: keepPreviousData,
  });
}

/** PNG rendition as a `data:` URL; content-addressed, so never stale. */
export function useRendition(id: string, sha256: string, kind: 'thumb' | 'preview', enabled: boolean) {
  return useQuery({
    queryKey: objectKeys.rendition(id, sha256, kind),
    queryFn: ({ signal }) => fetchRendition(id, sha256, kind, signal),
    enabled,
    staleTime: Infinity,
    // Data URLs live in memory: dropped soon after their tile scrolls away or the viewer moves on.
    gcTime: kind === 'preview' ? 30_000 : 60_000,
    retry: false,
  });
}
