import type { Endpoint as EndpointInfo } from '../api/types/Endpoint';
import { cn } from '../lib/cn';
import { endpointAddress, endpointTitle } from './endpointText';
import { Flag } from './Flag';

interface EndpointProps {
  /** `Endpoint` DTO of the API (address, names, category, country). */
  endpoint: EndpointInfo;
  /** Shows the first resolved name instead of the address when there is one. */
  showName?: boolean;
  /** Optional port, appended as `ip:port` (`[ip]:port` for IPv6). */
  port?: number;
  className?: string;
}

/**
 * Shared rendering of a host in tables and lists: address (mono) or first resolved name, with
 * the country flag; truncated, the full description (address, names, country) on hover.
 */
export function Endpoint({ endpoint, showName = true, port, className }: EndpointProps) {
  const name = showName ? endpoint.names[0] : undefined;
  const address = endpointAddress(endpoint, port);
  const title = endpointTitle(endpoint, port);
  return (
    <span className={cn('inline-flex max-w-full min-w-0 items-center gap-1.5 align-middle', className)}>
      {endpoint.country !== null && <Flag country={endpoint.country} />}
      <span data-testid="truncatable" title={title} className={cn('truncate', name === undefined && 'font-mono')}>
        {name ?? address}
      </span>
    </span>
  );
}
