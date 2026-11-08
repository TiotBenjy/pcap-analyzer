import { act, render } from '@testing-library/react';
import { createRef } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import EChartsRenderer, { type ChartHandle } from './EChartsRenderer';

// ECharts does not run in jsdom: a fake instance records what the renderer asks for.
const instance = {
  handlers: new Map<string, (params: unknown) => void>(),
  applied: {} as Record<string, unknown>,
  setOption: vi.fn(),
  getOption: vi.fn(),
  dispatchAction: vi.fn(),
  on: vi.fn(),
  off: vi.fn(),
  resize: vi.fn(),
  dispose: vi.fn(),
};

vi.mock('echarts/core', () => ({
  use: vi.fn(),
  init: () => instance,
}));

const OPTION = {
  series: [{ type: 'line', data: [] }],
  dataZoom: [{ type: 'inside' }, { type: 'slider' }],
};

type Applied = { dataZoom?: Record<string, unknown>[] } | undefined;
const lastApplied = () => instance.setOption.mock.calls.at(-1)?.[0] as Applied;

describe('EChartsRenderer', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    instance.handlers.clear();
    instance.getOption.mockReturnValue(undefined);
    instance.on.mockImplementation((name: string, handler: (params: unknown) => void) => {
      instance.handlers.set(name, handler);
    });
  });

  it('never re-applies the option while the user zooms, and keeps the window on later options', () => {
    const datazoom = vi.fn();
    const events = { datazoom };
    const { rerender } = render(<EChartsRenderer option={OPTION} height={200} ariaLabel="Traffic" onEvents={events} />);
    const calls = instance.setOption.mock.calls.length;
    expect(calls).toBeGreaterThan(0);

    // Dragging the slider: ECharts emits datazoom events, the renderer does nothing else.
    act(() => {
      instance.handlers.get('datazoom')?.({ start: 20, end: 60 });
      instance.handlers.get('datazoom')?.({ start: 25, end: 65 });
    });
    rerender(<EChartsRenderer option={OPTION} height={200} ariaLabel="Traffic" onEvents={events} />);
    expect(datazoom).toHaveBeenCalledTimes(2);
    expect(instance.setOption).toHaveBeenCalledTimes(calls);

    // Another option (metric, selection...): the window the user left is kept.
    instance.getOption.mockReturnValue({ dataZoom: [{ start: 25, end: 65 }, { start: 25, end: 65 }] });
    rerender(<EChartsRenderer option={{ ...OPTION }} height={200} ariaLabel="Traffic" onEvents={events} />);
    expect(lastApplied()?.dataZoom?.map((z) => [z.start, z.end])).toEqual([
      [25, 65],
      [25, 65],
    ]);
  });

  it('themes the zoom slider and exposes chart actions', () => {
    const handle = createRef<ChartHandle>();
    render(<EChartsRenderer option={OPTION} height={200} ariaLabel="Traffic" handleRef={handle} />);
    const slider = lastApplied()?.dataZoom?.[1];
    expect(slider).toHaveProperty('handleStyle');
    expect(slider).toHaveProperty('fillerColor');
    expect(slider).toHaveProperty('dataBackground');
    handle.current?.dispatchAction({ type: 'dataZoom', start: 0, end: 100 });
    expect(instance.dispatchAction).toHaveBeenCalledWith({ type: 'dataZoom', start: 0, end: 100 });
  });
});
