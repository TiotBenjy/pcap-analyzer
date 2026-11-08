// Planar helpers for the world map (worldMap.ts): no ECharts, testable on their own.

import type { Geometry, MultiPolygon, Polygon, Position } from 'geojson';

/** Longitude and latitude of a point. */
export type LonLat = [number, number];

/** Signed area and centroid of a ring (shoelace formula, planar: good enough for an anchor). */
function ringCentroid(ring: readonly Position[]): { area: number; at: LonLat } {
  let area = 0;
  let cx = 0;
  let cy = 0;
  for (let i = 0; i < ring.length - 1; i++) {
    const [x0 = 0, y0 = 0] = ring[i] ?? [];
    const [x1 = 0, y1 = 0] = ring[i + 1] ?? [];
    const cross = x0 * y1 - x1 * y0;
    area += cross;
    cx += (x0 + x1) * cross;
    cy += (y0 + y1) * cross;
  }
  if (area === 0) {
    const [x = 0, y = 0] = ring[0] ?? [];
    return { area: 0, at: [x, y] };
  }
  return { area: Math.abs(area / 2), at: [cx / (3 * area), cy / (3 * area)] };
}

/**
 * Rings crossing the antimeridian (Russia, Fiji) would be drawn with lines across the whole map
 * in a planar projection: their points on the minority side are moved onto the 180th meridian
 * (a sliver of land disappears, invisible at this scale).
 */
export function clampRing(ring: readonly Position[]): Position[] {
  const crosses = ring.some((p, i) => i > 0 && Math.abs((p[0] ?? 0) - (ring[i - 1]?.[0] ?? 0)) > 180);
  if (!crosses) return [...ring];
  const east = ring.filter((p) => (p[0] ?? 0) >= 0).length >= ring.length / 2;
  return ring.map(([x = 0, y = 0]) => (east ? [x < 0 ? 180 : x, y] : [x > 0 ? -180 : x, y]));
}

export function clampGeometry(geometry: Geometry | null): Geometry | null {
  if (geometry === null) return null;
  if (geometry.type === 'Polygon') return { ...geometry, coordinates: geometry.coordinates.map(clampRing) };
  if (geometry.type === 'MultiPolygon') {
    return { ...geometry, coordinates: geometry.coordinates.map((poly) => poly.map(clampRing)) };
  }
  return geometry;
}

/** Centroid of the largest polygon of a country. */
export function anchorOf(geometry: Geometry | null): LonLat | null {
  if (geometry === null) return null;
  const polygons: Position[][][] =
    geometry.type === 'Polygon'
      ? [(geometry as Polygon).coordinates]
      : geometry.type === 'MultiPolygon'
        ? (geometry as MultiPolygon).coordinates
        : [];
  let best: { area: number; at: LonLat } | null = null;
  for (const polygon of polygons) {
    const outer = polygon[0];
    if (outer === undefined || outer.length < 3) continue;
    const c = ringCentroid(outer);
    if (best === null || c.area > best.area) best = c;
  }
  return best?.at ?? null;
}
