// Single source of truth for chart colors (docs/UI_GUIDELINES.md, "Palette des graphiques").
// A category keeps the same color everywhere in the application.

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

/** Fixed assignments for well-known protocol categories. */
const FIXED: Readonly<Record<string, string>> = {
  http: CATEGORICAL[0],
  tls: CATEGORICAL[1],
  dns: CATEGORICAL[2],
  smb: CATEGORICAL[3],
  netbios: CATEGORICAL[3],
  udp: CATEGORICAL[4],
  tcp: CATEGORICAL[5],
  icmp: CATEGORICAL[6],
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

/** Address categories for network legends: color and node shape are defined once. */
export const ADDRESS_CATEGORIES = {
  lan: { color: CATEGORICAL[0], shape: 'circle' },
  server: { color: CATEGORICAL[3], shape: 'square' },
  public: { color: CATEGORICAL[2], shape: 'circle' },
  broadcast: { color: CATEGORICAL[4], shape: 'triangle' },
  multicast: { color: CATEGORICAL[1], shape: 'triangle' },
  linkLocal: { color: CATEGORICAL[6], shape: 'diamond' },
  loopback: { color: OTHER_COLOR, shape: 'diamond' },
} as const;
