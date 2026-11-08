import type { LucideIcon } from 'lucide-react';
import {
  ArrowLeftRight,
  Cable,
  DoorOpen,
  FileStack,
  FileText,
  FolderOpen,
  FolderTree,
  Globe,
  Image,
  KeyRound,
  LayoutDashboard,
  ListTree,
  Lock,
  Monitor,
  Network,
  Phone,
  Radar,
  Router,
  Server,
  Settings,
  Share2,
  SquareTerminal,
  Upload,
  Wifi,
} from 'lucide-react';
import type { en } from '../i18n/en';
import { parseSessionPath, sessionPath } from './session';

export type NavId = keyof (typeof en)['nav']['items'];
export type NavGroup = keyof (typeof en)['nav']['groups'];

export interface NavItem {
  id: NavId;
  /**
   * `global` views: absolute path. `session` views: path relative to `/sessions/$sessionId`
   * (`/dns` -> `/sessions/<id>/dns`), linked to the current or last opened session.
   */
  scope: 'global' | 'session';
  path: `/${string}`;
  icon: LucideIcon;
  group: NavGroup;
  /** False for views planned in later phases: shown dimmed, not navigable. */
  enabled: boolean;
}

// Registration point: when a view is implemented, flip `enabled` and give it its own route module
// (see src/app/router.ts). Keep one line per item to make parallel merges trivial.
export const NAV_ITEMS: readonly NavItem[] = [
  { id: 'captures', scope: 'global', path: '/captures', icon: FolderOpen, group: 'session', enabled: true },
  { id: 'overview', scope: 'session', path: '/overview', icon: LayoutDashboard, group: 'session', enabled: true },
  { id: 'sources', scope: 'session', path: '/sources', icon: FileStack, group: 'session', enabled: true },
  { id: 'dns', scope: 'session', path: '/dns', icon: Globe, group: 'analysis', enabled: true },
  { id: 'http', scope: 'session', path: '/http', icon: ArrowLeftRight, group: 'analysis', enabled: true },
  { id: 'httpHeaders', scope: 'session', path: '/http-headers', icon: ListTree, group: 'analysis', enabled: true },
  { id: 'tls', scope: 'session', path: '/tls', icon: Lock, group: 'analysis', enabled: true },
  { id: 'connections', scope: 'session', path: '/connections', icon: Cable, group: 'analysis', enabled: true },
  { id: 'openPorts', scope: 'session', path: '/open-ports', icon: DoorOpen, group: 'analysis', enabled: true },
  { id: 'smb', scope: 'session', path: '/smb', icon: FolderTree, group: 'analysis', enabled: true },
  { id: 'pictures', scope: 'session', path: '/pictures', icon: Image, group: 'analysis', enabled: false },
  { id: 'credentials', scope: 'session', path: '/credentials', icon: KeyRound, group: 'analysis', enabled: false },
  { id: 'servers', scope: 'session', path: '/servers', icon: Server, group: 'analysis', enabled: true },
  { id: 'network', scope: 'session', path: '/network', icon: Share2, group: 'analysis', enabled: false },
  { id: 'hosts', scope: 'session', path: '/hosts', icon: Monitor, group: 'more', enabled: false },
  { id: 'documents', scope: 'session', path: '/documents', icon: FileText, group: 'more', enabled: false },
  { id: 'ftp', scope: 'session', path: '/ftp', icon: Upload, group: 'more', enabled: false },
  { id: 'telnet', scope: 'session', path: '/telnet', icon: SquareTerminal, group: 'more', enabled: false },
  { id: 'ssdp', scope: 'session', path: '/ssdp', icon: Radar, group: 'more', enabled: false },
  { id: 'sip', scope: 'session', path: '/sip', icon: Phone, group: 'more', enabled: false },
  { id: 'arp', scope: 'session', path: '/arp', icon: Network, group: 'more', enabled: false },
  { id: 'ethernet', scope: 'session', path: '/ethernet', icon: Router, group: 'more', enabled: false },
  { id: 'wifi', scope: 'session', path: '/wifi', icon: Wifi, group: 'more', enabled: false },
];

export const SETTINGS_ITEM: NavItem = {
  id: 'settings',
  scope: 'global',
  path: '/settings',
  icon: Settings,
  group: 'more',
  enabled: true,
};

export const NAV_GROUPS: readonly NavGroup[] = ['session', 'analysis', 'more'];

const matches = (pathname: string, path: string) => pathname === path || pathname.startsWith(`${path}/`);

/** Nav item of a location, session routes included (`/sessions/<id>/dns` -> DNS). */
export function findNavItem(pathname: string): NavItem | undefined {
  const session = parseSessionPath(pathname);
  if (session !== null) return NAV_ITEMS.find((i) => i.scope === 'session' && matches(session.rest, i.path));
  return [...NAV_ITEMS, SETTINGS_ITEM].find((i) => i.scope === 'global' && matches(pathname, i.path));
}

/** Link target of an item; `null` for a session view when no session is open. */
export function navHref(item: NavItem, sessionId: string | null): string | null {
  if (item.scope === 'global') return item.path;
  return sessionId === null ? null : sessionPath(sessionId, item.path);
}
