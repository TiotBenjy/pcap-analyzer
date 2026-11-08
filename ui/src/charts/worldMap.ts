// World map for ECharts (`geo` component, choropleth and points), loaded on demand: the country
// shapes (Natural Earth 1:110m through `world-atlas`, public domain) and the map modules of
// ECharts stay out of the views that do not show a map.

import { MapChart, ScatterChart } from 'echarts/charts';
import { GeoComponent } from 'echarts/components';
import * as echarts from 'echarts/core';
import type { Feature, FeatureCollection, Geometry } from 'geojson';
import { feature } from 'topojson-client';
import type { GeometryCollection, Topology } from 'topojson-specification';
import world from 'world-atlas/countries-110m.json';
import { anchorOf, clampGeometry, type LonLat } from './geo';
import { NUMERIC_TO_ALPHA2 } from './isoCountries';
import { WORLD_MAP_NAME } from './worldMapOption';

/** Name under which the map is registered (`geo.map`). Regions are named by alpha-2 code. */
export const WORLD_MAP = WORLD_MAP_NAME;

export interface WorldMap {
  /** Alpha-2 code -> point inside the main landmass of the country, for proportional symbols. */
  anchors: ReadonlyMap<string, LonLat>;
}

let loaded: WorldMap | null = null;

/** Registers the map modules and the country shapes once; returns the country anchors. */
export function loadWorldMap(): WorldMap {
  if (loaded !== null) return loaded;
  echarts.use([MapChart, ScatterChart, GeoComponent]);
  const topology = world as unknown as Topology<{ countries: GeometryCollection<{ name: string }> }>;
  const all = feature(topology, topology.objects.countries) as FeatureCollection<Geometry, { name: string }>;
  const anchors = new Map<string, LonLat>();
  const features: Feature<Geometry, { name: string }>[] = [];
  for (const f of all.features) {
    const code = f.id === undefined ? undefined : NUMERIC_TO_ALPHA2.get(String(f.id));
    // Antarctica takes a fifth of the height for no server.
    if (code === undefined || code === 'AQ') continue;
    const geometry = clampGeometry(f.geometry);
    if (geometry === null) continue;
    features.push({ ...f, geometry, properties: { name: code } });
    const at = anchorOf(geometry);
    if (at !== null) anchors.set(code, at);
  }
  echarts.registerMap(WORLD_MAP, { type: 'FeatureCollection', features } as never);
  loaded = { anchors };
  return loaded;
}
