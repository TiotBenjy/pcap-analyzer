import { describe, expect, it } from 'vitest';
import { keepZoomWindows, LEGEND_SIDE_MIN_WIDTH, normalizeOption, zoomWindows } from './normalize';

describe('normalizeOption', () => {
  it('hides overlapping axis and series labels unless the view says otherwise', () => {
    const out = normalizeOption(
      { xAxis: { type: 'category' }, yAxis: [{ axisLabel: { hideOverlap: false } }], series: [{ type: 'bar' }] },
      800,
    ) as Record<string, unknown>;
    expect(out.xAxis).toEqual([{ type: 'category', axisLabel: { hideOverlap: true } }]);
    expect(out.yAxis).toEqual([{ axisLabel: { hideOverlap: false } }]);
    expect(out.series).toEqual([{ type: 'bar', labelLayout: { hideOverlap: true } }]);
  });

  it('puts the legend below on narrow containers and on the right on wide ones', () => {
    const narrow = normalizeOption({ legend: {} }, 600) as { legend: Record<string, unknown>[] };
    expect(narrow.legend[0]).toMatchObject({ type: 'scroll', orient: 'horizontal', bottom: 0 });
    const wide = normalizeOption({ legend: {} }, LEGEND_SIDE_MIN_WIDTH) as { legend: Record<string, unknown>[] };
    expect(wide.legend[0]).toMatchObject({ type: 'scroll', orient: 'vertical', right: 0 });
  });

  it('applies theme axis colors under the view values', () => {
    const theme = { axisLabel: { color: 'grey' }, splitLine: { lineStyle: { color: 'line' } } };
    const out = normalizeOption(
      { yAxis: { splitLine: { lineStyle: { type: 'dashed' } }, axisLabel: { color: 'red' } } },
      800,
      { axis: theme },
    ) as { yAxis: Record<string, unknown>[] };
    expect(out.yAxis[0]).toEqual({
      axisLabel: { hideOverlap: true, color: 'red' },
      splitLine: { lineStyle: { color: 'line', type: 'dashed' } },
    });
  });

  it('applies theme colors to slider data zooms only, under the view values', () => {
    const slider = { borderColor: 'line', handleStyle: { color: 'surface', borderColor: 'muted' } };
    const out = normalizeOption(
      { dataZoom: [{ type: 'inside' }, { type: 'slider', handleStyle: { borderColor: 'red' } }] },
      800,
      { slider },
    ) as { dataZoom: Record<string, unknown>[] };
    expect(out.dataZoom[0]).toEqual({ type: 'inside' });
    expect(out.dataZoom[1]).toEqual({
      type: 'slider',
      borderColor: 'line',
      handleStyle: { color: 'surface', borderColor: 'red' },
    });
  });

  it('leaves options without axes, series or legend untouched', () => {
    expect(normalizeOption({ title: { text: 'x' } }, 500)).toEqual({ title: { text: 'x' } });
  });

  it('keeps the zoom windows of the applied option when the option is re-applied', () => {
    const applied = { dataZoom: [{ type: 'inside', start: 20, end: 60 }, { type: 'slider', start: 20, end: 60 }] };
    const windows = zoomWindows(applied);
    expect(windows).toEqual([
      { start: 20, end: 60 },
      { start: 20, end: 60 },
    ]);
    const next = { series: [], dataZoom: [{ type: 'inside' }, { type: 'slider', height: 16 }] };
    expect(keepZoomWindows(next, windows)).toEqual({
      series: [],
      dataZoom: [
        { type: 'inside', start: 20, end: 60 },
        { type: 'slider', height: 16, start: 20, end: 60 },
      ],
    });
    // Another layout of zooms, nothing applied yet, or an unknown window: the option as is.
    expect(keepZoomWindows(next, windows.slice(1))).toBe(next);
    expect(zoomWindows(undefined)).toEqual([]);
    expect(keepZoomWindows(next, [null, null])).toEqual(next);
  });
});
