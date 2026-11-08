import type { Endpoint } from '../api/types/Endpoint';

/** `ip`, or `ip:port` (`[ip]:port` for IPv6) when a port is given. */
export function endpointAddress(e: Endpoint, port?: number): string {
  if (port === undefined) return e.ip;
  return e.ip.includes(':') ? `[${e.ip}]:${port}` : `${e.ip}:${port}`;
}

/** Full description of an endpoint, for the title (hover) and assistive technologies. */
export function endpointTitle(e: Endpoint, port?: number): string {
  const parts = [endpointAddress(e, port), ...e.names];
  if (e.country !== null) parts.push(e.country);
  return parts.join(' ');
}
