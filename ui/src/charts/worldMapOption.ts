import type { EChartsCoreOption } from 'echarts/core';
import { CATEGORICAL, SEQUENTIAL } from './palette';
import type { LonLat } from './geo';

// Option of the world map (components/WorldMap.tsx): light choropleth of values per country
// (ISO 3166-1 alpha-2 codes) and optional points proportional to the values, at an anchor point
// of each country. Pure: testable without ECharts.

/** Name under which `charts/worldMap.ts` registers the shapes (kept equal by a test). */
export const WORLD_MAP_NAME = 'netsift-world';

/** Light choropleth: the three lightest steps of the sequential scale. */
const STEPS = SEQUENTIAL.slice(0, 3);

/**
 * Width / height of the map without Antarctica (360 by about 140 degrees, with the 0.75 aspect
 * scale of ECharts): the chart height follows its width so that the map is not stretched.
 */
const MAP_RATIO = 3.2;
const MAP_HEIGHT_MIN = 110;
const MAP_HEIGHT_MAX = 420;

export function worldMapHeight(width: number): number {
  return Math.round(Math.min(MAP_HEIGHT_MAX, Math.max(MAP_HEIGHT_MIN, width / MAP_RATIO)));
}

/** Step of the light choropleth (logarithmic, 0..2). */
export function stepOf(value: number, max: number): number {
  if (max <= 0 || value <= 0) return 0;
  const ratio = Math.log1p(value) / Math.log1p(max);
  return Math.min(STEPS.length - 1, Math.floor(ratio * STEPS.length));
}

export interface WorldMapData {
  /** Value per alpha-2 country code (only positive values are drawn). */
  values: ReadonlyMap<string, number>;
  /** Points proportional to the values, at the anchors of the countries. */
  points: boolean;
  /** Tooltip HTML of a country (escape what comes from the data). */
  tooltip: (code: string, value: number | undefined) => string;
}

export function worldMapOption(data: WorldMapData, anchors: ReadonlyMap<string, LonLat>): EChartsCoreOption {
  const entries = [...data.values].filter(([, v]) => v > 0);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  return {
    tooltip: {
      trigger: 'item',
      formatter: (p: { name?: string }) =>
        p.name === undefined || p.name === '' ? '' : data.tooltip(p.name, data.values.get(p.name)),
    },
    geo: {
      map: WORLD_MAP_NAME,
      roam: false,
      left: 0,
      right: 0,
      top: 8,
      bottom: 8,
      label: { show: false },
      itemStyle: { areaColor: 'rgba(115, 115, 115, 0.16)', borderColor: 'rgba(115, 115, 115, 0.45)', borderWidth: 0.5 },
      emphasis: { disabled: true },
      select: { disabled: true },
      regions: entries.map(([code, v]) => ({ name: code, itemStyle: { areaColor: STEPS[stepOf(v, max)] } })),
    },
    series: data.points
      ? [
          {
            type: 'scatter',
            coordinateSystem: 'geo',
            data: entries.flatMap(([code, v]) => {
              const at = anchors.get(code);
              return at === undefined ? [] : [{ name: code, value: [at[0], at[1], v] }];
            }),
            symbolSize: (v: number[]) => 4 + 14 * Math.sqrt((v[2] ?? 0) / max),
            // Amber points stand out on the blue choropleth, in both themes.
            itemStyle: { color: CATEGORICAL[2], opacity: 0.9, borderColor: '#ffffff', borderWidth: 1 },
            label: { show: false },
            emphasis: { scale: false },
          },
        ]
      : [],
  };
}
