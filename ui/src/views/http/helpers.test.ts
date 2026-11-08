import { describe, expect, it } from 'vitest';
import { httpHeaderListQuery, httpListQuery } from '../../api/http';
import { OTHER_COLOR } from '../../charts/palette';
import { BAR_COLOR, barColor, barsOption, donutOption, escapeHtml, statusOption, truncateLabel } from './charts';
import { displayTarget, highlightParts, isSensitiveHeader, statusClass, statusTone } from './format';
import { methodFilters, methodParam } from './state';

const fmt = { count: (n: number) => String(n), label: (k: string) => k };

describe('HTTP formatting', () => {
  it('flags sensitive headers whatever their case', () => {
    for (const name of ['Authorization', 'COOKIE', 'set-cookie', ' Proxy-Authorization ']) {
      expect(isSensitiveHeader(name)).toBe(true);
    }
    expect(isSensitiveHeader('Host')).toBe(false);
  });

  it('splits highlighted occurrences, case-insensitively', () => {
    expect(highlightParts('session=AbC; abc', 'abc')).toEqual([
      { text: 'session=', match: false },
      { text: 'AbC', match: true },
      { text: '; ', match: false },
      { text: 'abc', match: true },
    ]);
    expect(highlightParts('value', '')).toEqual([{ text: 'value', match: false }]);
    expect(highlightParts('', 'x')).toEqual([{ text: '', match: false }]);
  });

  it('classes and tones statuses', () => {
    expect(statusClass(204)).toBe('2xx');
    expect(statusClass(null)).toBe('none');
    expect(statusClass(999)).toBe('other');
    expect(statusTone(503)).toBe('danger');
    expect(statusTone(404)).toBe('warning');
    expect(statusTone(301)).toBe('neutral');
  });

  it('displays targets with their query', () => {
    expect(displayTarget({ path: '/a', query: 'x=1', uri: '/a?x=1' })).toBe('/a?x=1');
    expect(displayTarget({ path: null, query: null, uri: 'host:443' })).toBe('host:443');
  });
});

describe('HTTP charts', () => {
  it('escapes capture text in tooltips', () => {
    const option = barsOption([{ key: '<img src=x onerror=alert(1)>', count: 2 }], () => '#000', fmt) as {
      tooltip: { formatter: (p: unknown) => string };
    };
    const html = option.tooltip.formatter([{ name: '<img src=x onerror=alert(1)>', value: 2, marker: '' }]);
    expect(html).not.toContain('<img');
    expect(html).toContain('&lt;img');
    expect(escapeHtml(`"'&`)).toBe('&quot;&#39;&amp;');
  });

  it('builds the donut, the bars and the status series', () => {
    const donut = donutOption([{ key: 'GET', count: 3 }], { GET: '#111' }, fmt) as { series: { data: unknown[] }[] };
    expect(donut.series[0]?.data).toEqual([{ name: 'GET', value: 3, itemStyle: { color: '#111' } }]);
    const status = statusOption(
      [
        { key: '500', count: 1 },
        { key: '200', count: 4 },
        { key: '201', count: 2 },
      ],
      fmt,
    ) as { xAxis: { data: string[] }; series: { name: string; data: unknown[] }[] };
    expect(status.xAxis.data).toEqual(['200', '201', '500']);
    expect(status.series.map((s) => [s.name, s.data])).toEqual([
      ['2xx', [4, 2, '-']],
      ['5xx', ['-', '-', 1]],
    ]);
    expect(truncateLabel('x'.repeat(30))).toHaveLength(24);
    // Bars: values at the end of the bars, no value axis, one color.
    const bars = barsOption([{ key: 'GET', count: 1234 }, { key: 'other', count: 2 }], barColor, fmt) as {
      xAxis: { show: boolean };
      series: { label: { position: string; formatter: (p: unknown) => string }; data: { itemStyle: { color: string } }[] }[];
    };
    expect(bars.xAxis.show).toBe(false);
    const label = bars.series[0]?.label;
    expect(label?.position).toBe('right');
    expect(label?.formatter({ value: 1234 })).toBe('1234');
    expect(bars.series[0]?.data.map((d) => d.itemStyle.color)).toEqual([BAR_COLOR, OTHER_COLOR]);
  });
});

describe('HTTP list parameters', () => {
  it('sends empty method lists and drops empty texts', () => {
    expect(httpListQuery({ methods: [], q: ' ', host: 'a.test', sort: 'size' })).toBe('?sort=size&method=&host=a.test');
    expect(httpListQuery({ statuses: ['2xx', '404'], cursor: null })).toBe('?status=2xx%2C404');
    expect(httpHeaderListQuery({ name: 'cookie', q: 'abc', limit: 50 })).toBe('?limit=50&name=cookie&q=abc');
    expect(httpListQuery()).toBe('');
  });

  it('turns disabled toggles into the methods parameter', () => {
    expect(methodParam(new Set())).toBeUndefined();
    expect(methodParam(new Set(['GET', 'other']))).toEqual(['POST', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'DELETE', 'CONNECT']);
    const filters = methodFilters([{ key: 'GET', count: 5 }], new Set(['POST']), 'Other');
    expect(filters[0]).toEqual({ id: 'GET', label: 'GET', count: 5, active: true });
    expect(filters[1]).toEqual({ id: 'POST', label: 'POST', count: 0, active: false });
    expect(filters.at(-1)?.label).toBe('Other');
  });
});
