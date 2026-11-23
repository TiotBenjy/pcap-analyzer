import type { NavId } from './nav';

// REGISTRATION POINT (ADR-030): one line per session view that applies the global time range,
// sorted by id. A view absent from this list shows the whole session, and the range chip of the
// header says so. A new view applies the range from its creation, or its spec says why not.
export const TIME_FILTER_VIEWS: ReadonlySet<NavId> = new Set<NavId>([
  'arp',
  'connections',
  'credentials',
  'dns',
  'ethernet',
  'ftp',
  'http',
  'httpHeaders',
  'mqtt',
  'network',
  'openPorts',
  'overview',
  'pictures',
  'servers',
  'sip',
  'smb',
  'ssdp',
  'telnet',
  'tls',
]);
