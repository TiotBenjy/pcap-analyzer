import { useQuery } from '@tanstack/react-query';
import { apiGet } from './client';
import type { HealthResponse } from './types/HealthResponse';
import type { ServerInfo } from './types/ServerInfo';

export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: ({ signal }) => apiGet<HealthResponse>('/health', signal),
    refetchInterval: 15_000,
  });
}

export function useServerInfo() {
  return useQuery({
    queryKey: ['server-info'],
    queryFn: ({ signal }) => apiGet<ServerInfo>('/server-info', signal),
  });
}
