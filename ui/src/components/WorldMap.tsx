import { useEffect, useMemo, useState } from 'react';
import type { WorldMap as LoadedMap } from '../charts/worldMap';
import { type WorldMapData, worldMapHeight, worldMapOption } from '../charts/worldMapOption';
import { useElementWidth } from '../lib/useElementWidth';
import { Chart } from './Chart';
import { ErrorState } from './ErrorState';
import { Skeleton } from './Skeleton';

interface WorldMapProps extends WorldMapData {
  ariaLabel: string;
  /** Shown when the map module cannot be loaded. */
  errorText?: string;
}

/**
 * World map: light choropleth of a value per country (alpha-2 codes), optional proportional
 * points, tooltip per country. Its height follows its width (no stretched shapes). The shapes
 * and the ECharts map modules are loaded on demand.
 */
export function WorldMap({ values, points, tooltip, ariaLabel, errorText }: WorldMapProps) {
  const [ref, width] = useElementWidth();
  const [map, setMap] = useState<LoadedMap | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let alive = true;
    import('../charts/worldMap')
      .then((m) => {
        if (alive) setMap(m.loadWorldMap());
      })
      .catch(() => {
        if (alive) setFailed(true);
      });
    return () => {
      alive = false;
    };
  }, []);
  const option = useMemo(
    () => (map === null ? null : worldMapOption({ values, points, tooltip }, map.anchors)),
    [map, values, points, tooltip],
  );
  const height = worldMapHeight(width);
  let body;
  if (failed) body = <ErrorState {...(errorText === undefined ? {} : { message: errorText })} />;
  else if (option === null || width === 0) body = <Skeleton height={height} />;
  else body = <Chart option={option} height={height} ariaLabel={ariaLabel} />;
  return <div ref={ref}>{body}</div>;
}
