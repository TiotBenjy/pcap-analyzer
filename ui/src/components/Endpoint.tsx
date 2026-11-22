import { type ReactNode, useContext } from 'react';
import type { Endpoint as EndpointInfo } from '../api/types/Endpoint';
import { cn } from '../lib/cn';
import { CopyButton } from './CopyButton';
import { endpointAddress, endpointHost, endpointTitle, toEndpoint } from './endpointText';
import { Flag } from './Flag';
import { HostLinkContext } from './hostLink';

/**
 * What an endpoint shows:
 * - `name`: the first resolved name, else the address (default);
 * - `address`: always the address (names in the tooltip);
 * - `both`: the address, then the first name in grey on the same line;
 * - `stacked`: the name, and the address below it when there is a name.
 */
export type EndpointShow = 'name' | 'address' | 'both' | 'stacked';

interface EndpointProps {
  /** `Endpoint` DTO of the API, or a bare IP for rows that carry only the address. */
  endpoint: EndpointInfo | string;
  /** Optional port, appended as `ip:port` (`[ip]:port` for IPv6), in grey. */
  port?: number | null;
  show?: EndpointShow;
  /** Adds a copy button for `ip[:port]` (detail panels; tables stay compact). */
  copy?: boolean;
  className?: string;
}

/**
 * The only rendering of a host address in the UI (docs/specs/README.md): country flag, address
 * in mono with the port in grey, or the resolved name; truncated, with the full description
 * (address, names, country) on hover. The address becomes a link to the host page when a
 * `HostLinkContext` is provided (P5.12).
 */
export function Endpoint({ endpoint, port, show = 'name', copy = false, className }: EndpointProps) {
  const link = useContext(HostLinkContext);
  const e = toEndpoint(endpoint);
  const name = e.names[0];
  const address = endpointAddress(e, port);
  const title = endpointTitle(e, port);
  const named = name !== undefined && (show === 'name' || show === 'stacked');

  const addressText = (
    <>
      {endpointHost(e, port)}
      {port != null && <span className="text-faint">:{port}</span>}
    </>
  );
  const text = (content: ReactNode, mono: boolean, extra?: string) => (
    <span data-testid="truncatable" title={title} className={cn('min-w-0 truncate', mono && 'font-mono', extra)}>
      {content}
    </span>
  );
  let main = named ? text(name, false) : text(addressText, true);
  if (link !== null) {
    main = (
      <button
        type="button"
        aria-label={link.label(e.ip)}
        onClick={(ev) => {
          ev.stopPropagation();
          link.open(e.ip);
        }}
        className="flex min-w-0 text-left hover:text-accent hover:underline"
      >
        {main}
      </button>
    );
  }

  const head = (
    <span className="inline-flex max-w-full min-w-0 items-center gap-1.5">
      {e.country !== null && <Flag country={e.country} />}
      {main}
      {show === 'both' && name !== undefined && (
        <span data-testid="truncatable" title={name} className="min-w-0 shrink-[2] truncate text-meta text-muted">
          {name}
        </span>
      )}
    </span>
  );
  return (
    <span className={cn('inline-flex max-w-full min-w-0 items-center gap-1 align-middle', className)}>
      {show === 'stacked' && named ? (
        <span className="flex min-w-0 flex-col">
          {head}
          {text(address, true, 'text-meta text-muted')}
        </span>
      ) : (
        head
      )}
      {copy && <CopyButton value={address} name={address} />}
    </span>
  );
}
