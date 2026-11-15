import { act, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { loadChartRenderer, preloadChartRenderer, useChartRendererReady } from './loadRenderer';

vi.mock('./EChartsRenderer', () => ({ default: () => <div data-testid="renderer" /> }));

function Probe() {
  return <span>{useChartRendererReady() ? 'ready' : 'loading'}</span>;
}

describe('chart renderer loading', () => {
  it('loads the renderer on mount, once, then renders without suspending', async () => {
    const idle = vi.fn((cb: () => void) => {
      cb();
      return 1;
    });
    vi.stubGlobal('requestIdleCallback', idle);
    vi.stubGlobal('cancelIdleCallback', vi.fn());
    try {
      render(<Probe />);
      expect(screen.getByText('loading')).toBeInTheDocument();
      await act(async () => {
        await loadChartRenderer();
      });
      expect(screen.getByText('ready')).toBeInTheDocument();
      // Already loaded: nothing scheduled when a session opens.
      const cancel = preloadChartRenderer();
      expect(idle).not.toHaveBeenCalled();
      cancel();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
