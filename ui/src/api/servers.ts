// Typed client of the Servers route (crates/netsift-api/src/servers.rs).

import { apiGet } from './client';
import type { AddressCategory } from './types/AddressCategory';
import type { ServerRole } from './types/ServerRole';
import type { ServersOverview } from './types/ServersOverview';

export interface ServerFilters {
  /** Only this role; every role when absent. */
  role?: ServerRole;
  /** Address categories of the servers; `undefined` = all, empty = none. */
  categories?: readonly AddressCategory[];
  /** Servers listed per role (the API defaults to 50, at most 500). */
  limit?: number;
}

export function getServers(id: string, filters: ServerFilters = {}, signal?: AbortSignal): Promise<ServersOverview> {
  const q = new URLSearchParams();
  if (filters.role !== undefined) q.set('role', filters.role);
  if (filters.categories !== undefined) q.set('category', filters.categories.join(','));
  if (filters.limit !== undefined) q.set('limit', String(filters.limit));
  const text = q.toString();
  return apiGet(`/sessions/${encodeURIComponent(id)}/servers${text === '' ? '' : `?${text}`}`, signal);
}
