import { useViewRange } from '../app/timeRange';
import { rangeKey, type TimeRange } from '../lib/timeRange';
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
  stats: (id: string, range: TimeRange | null = null) => ['sessions', 'detail', id, 'tls', 'stats', rangeKey(range)] as const,
  sessions: (id: string, filters: TlsSessionFilters, range: TimeRange | null = null) => ['sessions', 'detail', id, 'tls', 'sessions', filters, rangeKey(range)] as const,
  session: (id: string, flow: string) => ['sessions', 'detail', id, 'tls', 'session', flow] as const,
  certificates: (id: string, filters: TlsCertificateFilters, range: TimeRange | null = null) =>
    ['sessions', 'detail', id, 'tls', 'certificates', filters, rangeKey(range)] as const,
};

/** `enabled`: false while the session is importing or failed (the routes answer 409). */
export function useTlsStats(id: string, enabled: boolean) {
  const range = useViewRange();
  return useQuery({ queryKey: tlsKeys.stats(id, range), queryFn: ({ signal }) => getTlsStats(id, signal, range), enabled });
}

export function useTlsSessions(id: string, filters: TlsSessionFilters, enabled: boolean) {
  const range = useViewRange();
  return useQuery({
    queryKey: tlsKeys.sessions(id, filters, range),
    queryFn: ({ signal }) => fetchAll((p) => listTlsSessions(id, filters, p, signal, range), TLS_LIST_LIMIT),
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
  const range = useViewRange();
  return useQuery({
    queryKey: tlsKeys.certificates(id, filters, range),
    queryFn: ({ signal }) => fetchAll((p) => listTlsCertificates(id, filters, p, signal, range), TLS_LIST_LIMIT),
    enabled,
    placeholderData: keepPreviousData,
  });
}
