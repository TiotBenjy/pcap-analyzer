import { describe, expect, it } from 'vitest';
import { LEGEND_SIDE_MIN_WIDTH, normalizeOption } from './normalize';

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

  it('leaves options without axes, series or legend untouched', () => {
    expect(normalizeOption({ title: { text: 'x' } }, 500)).toEqual({ title: { text: 'x' } });
  });
});
