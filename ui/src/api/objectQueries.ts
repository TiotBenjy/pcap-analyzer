import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { fetchRendition, getPictureStats, listPictures, type PictureFilters } from './objects';
import { fetchAll } from './sessionQueries';

// Query hooks of the Pictures view, under the session detail key (invalidated with the session).

/** Pictures loaded in the grid (the view tells when the list is cut). */
export const PICTURES_LIST_LIMIT = 5000;

export const objectKeys = {
  stats: (id: string) => ['sessions', 'detail', id, 'objects', 'stats'] as const,
  pictures: (id: string, filters: PictureFilters) => ['sessions', 'detail', id, 'objects', 'pictures', filters] as const,
  rendition: (id: string, sha256: string, kind: 'thumb' | 'preview') =>
    ['sessions', 'detail', id, 'objects', kind, sha256] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function usePictureStats(id: string, enabled: boolean) {
  return useQuery({ queryKey: objectKeys.stats(id), queryFn: ({ signal }) => getPictureStats(id, signal), enabled });
}

export function usePictures(id: string, filters: PictureFilters, enabled: boolean) {
  return useQuery({
    queryKey: objectKeys.pictures(id, filters),
    queryFn: ({ signal }) => fetchAll((p) => listPictures(id, filters, p, signal), PICTURES_LIST_LIMIT),
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
