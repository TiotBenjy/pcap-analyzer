import type { Endpoint } from '../api/types/Endpoint';

/** What `Endpoint` needs of a host: the API DTO, or a bare address (`names` empty, no country). */
export type EndpointLike = Pick<Endpoint, 'ip' | 'names' | 'country'>;

/** A bare address as an endpoint without names nor country (rows that carry only the IP). */
export function toEndpoint(e: EndpointLike | string): EndpointLike {
  return typeof e === 'string' ? { ip: e, names: [], country: null } : e;
}

/** Address part of `ip:port`: the IP, in brackets for IPv6 when a port follows. */
export function endpointHost(e: EndpointLike, port?: number | null): string {
  return port != null && e.ip.includes(':') ? `[${e.ip}]` : e.ip;
}

/** `ip`, or `ip:port` (`[ip]:port` for IPv6) when a port is given. */
export function endpointAddress(e: EndpointLike, port?: number | null): string {
  return port == null ? e.ip : `${endpointHost(e, port)}:${port}`;
}

/** Full description of an endpoint, for the title (hover) and assistive technologies. */
export function endpointTitle(e: EndpointLike, port?: number | null): string {
  const parts = [endpointAddress(e, port), ...e.names];
  if (e.country !== null) parts.push(e.country);
  return parts.join(' ');
}
