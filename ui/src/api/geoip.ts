import { apiGet, apiSend } from './client';
import type { GeoipInfo } from './types/GeoipInfo';
import type { GeoipUpdate } from './types/GeoipUpdate';

// Updates of the country database (Settings > About). The download is done by the backend
// (ADR-015): the webview itself never contacts any outside host.

/** Downloads the latest DB-IP database and installs it; resolves to the new state. */
export function downloadGeoip(): Promise<GeoipInfo> {
  return apiSend<GeoipInfo>('POST', '/geoip/download');
}

/** Installs a `.mmdb` or `.mmdb.gz` file chosen by the user; resolves to the new state. */
export function importGeoip(path: string): Promise<GeoipInfo> {
  return apiSend<GeoipInfo>('POST', '/geoip/import', { path });
}

/** Progress of the running update. */
export function getGeoipUpdate(signal?: AbortSignal): Promise<GeoipUpdate> {
  return apiGet<GeoipUpdate>('/geoip/update', signal);
}
