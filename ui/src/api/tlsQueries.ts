import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { fetchAll } from './sessionQueries';
import {
  getTlsSession,
  getTlsStats,
  listTlsCertificates,
  listTlsSessions,
  type TlsCertificateFilters,
  type TlsSessionFilters,
} from './tls';

// Query hooks of the TLS view, under the session detail key (invalidated with the session).

/** Rows loaded in the tables (the view tells when the list is cut). */
export const TLS_LIST_LIMIT = 5000;

export const tlsKeys = {
  stats: (id: string) => ['sessions', 'detail', id, 'tls', 'stats'] as const,
  sessions: (id: string, filters: TlsSessionFilters) => ['sessions', 'detail', id, 'tls', 'sessions', filters] as const,
  session: (id: string, flow: string) => ['sessions', 'detail', id, 'tls', 'session', flow] as const,
  certificates: (id: string, filters: TlsCertificateFilters) =>
    ['sessions', 'detail', id, 'tls', 'certificates', filters] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useTlsStats(id: string, enabled: boolean) {
  return useQuery({ queryKey: tlsKeys.stats(id), queryFn: ({ signal }) => getTlsStats(id, signal), enabled });
}

export function useTlsSessions(id: string, filters: TlsSessionFilters, enabled: boolean) {
  return useQuery({
    queryKey: tlsKeys.sessions(id, filters),
    queryFn: ({ signal }) => fetchAll((p) => listTlsSessions(id, filters, p, signal), TLS_LIST_LIMIT),
    enabled,
    placeholderData: keepPreviousData,
  });
}

export function useTlsSession(id: string, flow: string | null) {
  return useQuery({
    queryKey: tlsKeys.session(id, flow ?? ''),
    queryFn: ({ signal }) => getTlsSession(id, flow ?? '', signal),
    enabled: flow !== null,
  });
}

export function useTlsCertificates(id: string, filters: TlsCertificateFilters, enabled: boolean) {
  return useQuery({
    queryKey: tlsKeys.certificates(id, filters),
    queryFn: ({ signal }) => fetchAll((p) => listTlsCertificates(id, filters, p, signal), TLS_LIST_LIMIT),
    enabled,
    placeholderData: keepPreviousData,
  });
}
