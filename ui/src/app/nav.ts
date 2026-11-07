import type { LucideIcon } from 'lucide-react';
import {
  ArrowLeftRight,
  Cable,
  DoorOpen,
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

export type NavId = keyof (typeof en)['nav']['items'];
export type NavGroup = keyof (typeof en)['nav']['groups'];

export interface NavItem {
  id: NavId;
  path: `/${string}`;
  icon: LucideIcon;
  group: NavGroup;
  /** False for views planned in later phases: shown dimmed, not navigable. */
  enabled: boolean;
}

// Registration point: when a view is implemented, flip `enabled` and give it its own route module
// (see src/app/router.tsx). Keep one line per item to make parallel merges trivial.
export const NAV_ITEMS: readonly NavItem[] = [
  { id: 'captures', path: '/captures', icon: FolderOpen, group: 'session', enabled: true },
  { id: 'overview', path: '/overview', icon: LayoutDashboard, group: 'session', enabled: true },
  { id: 'dns', path: '/dns', icon: Globe, group: 'analysis', enabled: false },
  { id: 'http', path: '/http', icon: ArrowLeftRight, group: 'analysis', enabled: false },
  { id: 'httpHeaders', path: '/http-headers', icon: ListTree, group: 'analysis', enabled: false },
  { id: 'tls', path: '/tls', icon: Lock, group: 'analysis', enabled: false },
  { id: 'connections', path: '/connections', icon: Cable, group: 'analysis', enabled: false },
  { id: 'openPorts', path: '/open-ports', icon: DoorOpen, group: 'analysis', enabled: false },
  { id: 'smb', path: '/smb', icon: FolderTree, group: 'analysis', enabled: false },
  { id: 'pictures', path: '/pictures', icon: Image, group: 'analysis', enabled: false },
  { id: 'credentials', path: '/credentials', icon: KeyRound, group: 'analysis', enabled: false },
  { id: 'servers', path: '/servers', icon: Server, group: 'analysis', enabled: false },
  { id: 'network', path: '/network', icon: Share2, group: 'analysis', enabled: false },
  { id: 'hosts', path: '/hosts', icon: Monitor, group: 'more', enabled: false },
  { id: 'documents', path: '/documents', icon: FileText, group: 'more', enabled: false },
  { id: 'ftp', path: '/ftp', icon: Upload, group: 'more', enabled: false },
  { id: 'telnet', path: '/telnet', icon: SquareTerminal, group: 'more', enabled: false },
  { id: 'ssdp', path: '/ssdp', icon: Radar, group: 'more', enabled: false },
  { id: 'sip', path: '/sip', icon: Phone, group: 'more', enabled: false },
  { id: 'arp', path: '/arp', icon: Network, group: 'more', enabled: false },
  { id: 'ethernet', path: '/ethernet', icon: Router, group: 'more', enabled: false },
  { id: 'wifi', path: '/wifi', icon: Wifi, group: 'more', enabled: false },
];

export const SETTINGS_ITEM: NavItem = {
  id: 'settings',
  path: '/settings',
  icon: Settings,
  group: 'more',
  enabled: true,
};

export const NAV_GROUPS: readonly NavGroup[] = ['session', 'analysis', 'more'];

export function findNavItem(pathname: string): NavItem | undefined {
  return [...NAV_ITEMS, SETTINGS_ITEM].find((i) => pathname === i.path || pathname.startsWith(`${i.path}/`));
}
