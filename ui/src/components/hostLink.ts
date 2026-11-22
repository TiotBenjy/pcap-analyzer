import { createContext } from 'react';

/**
 * Extension point of `Endpoint` for the host page (P5.12, not implemented yet): a provider
 * placed around a view turns every address into a button that opens the page of that host.
 * Without a provider (today), an address is plain text.
 */
export interface HostLink {
  /** Opens the host page of `ip`. */
  open: (ip: string) => void;
  /** Accessible label of the action ("Open host 10.0.0.1"). */
  label: (ip: string) => string;
}

export const HostLinkContext = createContext<HostLink | null>(null);
