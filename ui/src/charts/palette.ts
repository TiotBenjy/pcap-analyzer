// Single source of truth for chart colors (docs/UI_GUIDELINES.md, "Palette des graphiques").
// A category keeps the same color everywhere in the application.

import type { AddressCategory } from '../api/types/AddressCategory';

export type NodeShape = 'circle' | 'square' | 'triangle' | 'diamond';

/** Categorical palette, fixed order, colorblind-friendly. The last entry is reserved for "Other". */
export const CATEGORICAL = [
  '#2563eb',
  '#0d9488',
  '#d97706',
  '#7c3aed',
  '#db2777',
  '#65a30d',
  '#0891b2',
  '#737373',
] as const;

export const OTHER_COLOR = CATEGORICAL[7];

/** Neutral fill of single-series rankings (bars that are not a category of the palette). */
export const NEUTRAL = '#71717a';

/**
 * Fixed assignments for well-known protocol categories, including every series of the Overview
 * traffic chart (`TrafficProtocol`). Eight hues for thirteen series: related protocols share a
 * hue (SMB / NetBIOS, TLS / QUIC, DNS / DHCP, SSH / SNMP); the legend and tooltip name them.
 */
const FIXED: Readonly<Record<string, string>> = {
  http: CATEGORICAL[0],
  tls: CATEGORICAL[1],
  quic: CATEGORICAL[1],
  dns: CATEGORICAL[2],
  dhcp: CATEGORICAL[2],
  // Name services of the DNS view (DNS keeps its hue).
  llmnr: CATEGORICAL[0],
  mdns: CATEGORICAL[1],
  nbns: CATEGORICAL[3],
  smb: CATEGORICAL[3],
  netbios: CATEGORICAL[3],
  udp: CATEGORICAL[4],
  other_udp: CATEGORICAL[4],
  wifi_mgmt: CATEGORICAL[4],
  tcp: CATEGORICAL[5],
  other_tcp: CATEGORICAL[5],
  icmp: CATEGORICAL[6],
  ssh: CATEGORICAL[6],
  snmp: CATEGORICAL[6],
  other: OTHER_COLOR,
};

const ASSIGNABLE = CATEGORICAL.slice(0, 7);

/** Deterministic hash so unknown categories also keep a stable color across views and reloads. */
function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

export function colorFor(category: string): string {
  const key = category.trim().toLowerCase();
  return FIXED[key] ?? ASSIGNABLE[hash(key) % ASSIGNABLE.length] ?? OTHER_COLOR;
}

/** Sequential single-hue blue scale (5 steps), light to dark, for choropleths and heatmaps. */
export const SEQUENTIAL = ['#dbeafe', '#93c5fd', '#3b82f6', '#1d4ed8', '#1e3a8a'] as const;

/** Same blue scale for the dark theme: dark to bright, so that low values do not glare. */
export const SEQUENTIAL_DARK = ['#172554', '#1e3a8a', '#1d4ed8', '#3b82f6', '#93c5fd'] as const;

/**
 * Address categories (`AddressCategory`, backend labels) for network legends: color and node shape
 * are defined once. Labels come from the dictionaries (`addressCategories.<label>`; `private` is
 * shown as "LAN"). CGNAT shares a hue with nothing else; unspecified and reserved addresses
 * (documentation ranges...) use the "Other" grey.
 */
export const ADDRESS_CATEGORIES: Readonly<Record<AddressCategory, { color: string; shape: NodeShape }>> = {
  private: { color: CATEGORICAL[0], shape: 'circle' },
  public: { color: CATEGORICAL[2], shape: 'circle' },
  broadcast: { color: CATEGORICAL[4], shape: 'triangle' },
  multicast: { color: CATEGORICAL[1], shape: 'triangle' },
  link_local: { color: CATEGORICAL[6], shape: 'diamond' },
  loopback: { color: CATEGORICAL[5], shape: 'diamond' },
  cgnat: { color: CATEGORICAL[3], shape: 'circle' },
  unspecified: { color: OTHER_COLOR, shape: 'diamond' },
  reserved: { color: OTHER_COLOR, shape: 'circle' },
};

/** Legend order of the address categories. */
export const ADDRESS_CATEGORY_ORDER: readonly AddressCategory[] = [
  'private',
  'public',
  'broadcast',
  'multicast',
  'link_local',
  'loopback',
  'cgnat',
  'unspecified',
  'reserved',
];

/**
 * The server role is not an address category: it is drawn with its own shape, keeping the color
 * of the address category (a public server stays amber).
 */
export const SERVER_ROLE = { shape: 'square' } as const satisfies { shape: NodeShape };
