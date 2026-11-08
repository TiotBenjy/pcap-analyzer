import { BarChart, HeatmapChart, LineChart, PieChart } from 'echarts/charts';
import * as components from 'echarts/components';
import * as echarts from 'echarts/core';
import { SVGRenderer } from 'echarts/renderers';
import Graph from 'graphology';
import { beforeAll, describe, expect, it } from 'vitest';

// The desktop app sets `freezePrototype: true` (tauri.conf.json): Tauri runs
// `Object.freeze(Object.prototype)` before any page script. Assigning `toString`, `constructor`,
// `valueOf`... on an object whose nearest such property is the frozen one throws in strict code
// (the "override mistake"). This file checks that the chart libraries load and run under that
// constraint. Vitest isolates test files, so the freeze does not leak into other tests.
//
// The modules are imported before the freeze: Vitest's own module runner does not support a
// frozen prototype. Module evaluation under the freeze is covered in a real browser by
// `./x.sh shots` (which freezes the prototype like Tauri does) for every view using ECharts.
// Not covered: sigma, whose module needs WebGL at load time (absent from jsdom) and which no view
// uses yet; the network graph view will be covered by its shots. Graphology is exercised here.

beforeAll(() => {
  // jsdom has no canvas: ECharts measures text through this hook instead.
  echarts.setPlatformAPI({ measureText: (text = '') => ({ width: text.length * 7 }) });
  Object.freeze(Object.prototype);
});

describe('frozen Object.prototype (Tauri freezePrototype)', () => {
  it('is really frozen in this file', () => {
    expect(Object.isFrozen(Object.prototype)).toBe(true);
    // The override mistake this file guards against (module code is strict).
    const legacyPrototype: { toString: () => string } = {};
    expect(() => {
      legacyPrototype.toString = () => 'legacy';
    }).toThrow(TypeError);
  });

  it('renders the ECharts SVG charts used by the views', () => {
    echarts.use([
      BarChart,
      HeatmapChart,
      LineChart,
      PieChart,
      components.DataZoomComponent,
      components.GridComponent,
      components.LegendComponent,
      components.TitleComponent,
      components.TooltipComponent,
      components.VisualMapComponent,
      SVGRenderer,
    ]);

    const el = document.createElement('div');
    document.body.append(el);
    const chart = echarts.init(el, null, { renderer: 'svg', width: 640, height: 400 });
    chart.setOption({
      animation: false,
      title: { text: 'traffic' },
      tooltip: { trigger: 'axis' },
      legend: { data: ['tcp', 'udp'] },
      dataZoom: [{ type: 'inside' }, { type: 'slider' }],
      xAxis: { type: 'time' },
      yAxis: { type: 'value' },
      series: [
        { name: 'tcp', type: 'line', data: [[0, 1], [1000, 5], [2000, 3]] },
        { name: 'udp', type: 'bar', data: [[0, 2], [1000, 1], [2000, 4]] },
      ],
    });
    expect(el.querySelector('svg path')).not.toBeNull();

    chart.setOption(
      {
        animation: false,
        series: [{ type: 'pie', radius: ['40%', '70%'], data: [{ name: 'a', value: 3 }, { name: 'b', value: 1 }] }],
      },
      { notMerge: true },
    );
    chart.setOption(
      {
        animation: false,
        xAxis: { type: 'category', data: ['00', '01'] },
        yAxis: { type: 'category', data: ['mon', 'tue'] },
        visualMap: { min: 0, max: 10, calculable: true },
        series: [{ type: 'heatmap', data: [[0, 0, 1], [1, 1, 9]] }],
      },
      { notMerge: true },
    );
    chart.resize({ width: 320, height: 240 });
    expect(chart.getDataURL({ type: 'svg' })).toMatch(/^data:image\/svg\+xml/);
    chart.dispose();
    el.remove();
  });

  it('builds and copies graphology graphs', () => {
    const graph = new Graph({ multi: false, type: 'directed' });
    graph.addNode('10.0.0.1', { x: 0, y: 0, size: 4, label: '10.0.0.1' });
    graph.addNode('10.0.0.2', { x: 1, y: 1, size: 2, label: '10.0.0.2' });
    graph.addEdge('10.0.0.1', '10.0.0.2', { size: 1 });
    graph.mergeNodeAttributes('10.0.0.2', { color: '#888' });
    expect(graph.order).toBe(2);
    expect(graph.size).toBe(1);
    expect(String(graph)).toBe('[object Graph]');
    expect(JSON.parse(JSON.stringify(graph))).toHaveProperty('nodes');
    const copy = graph.copy();
    copy.dropNode('10.0.0.1');
    expect(copy.order).toBe(1);

  });
});
