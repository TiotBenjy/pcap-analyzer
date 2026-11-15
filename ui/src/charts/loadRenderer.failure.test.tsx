import { act, render, screen } from '@testing-library/react';
import { Component, type ReactNode } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { loadChartRenderer, useChartRendererReady } from './loadRenderer';

// The chunk of the renderer cannot be loaded (network error, removed build file).
vi.mock('./EChartsRenderer', () => {
  throw new Error('chunk load failed');
});

class Boundary extends Component<{ children: ReactNode }, { error: string | null }> {
  override state = { error: null };
  static getDerivedStateFromError(e: unknown) {
    return { error: e instanceof Error ? e.message : String(e) };
  }
  override render() {
    return this.state.error === null ? this.props.children : <p>failed</p>;
  }
}

function Probe() {
  return <span>{useChartRendererReady(true) ? 'ready' : 'loading'}</span>;
}

describe('chart renderer loading failure', () => {
  it('reaches a chart mounted while the failing load was running', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const running = loadChartRenderer();
    render(
      <Boundary>
        <Probe />
      </Boundary>,
    );
    expect(screen.getByText('loading')).toBeInTheDocument();
    await act(async () => {
      await running;
    });
    expect(screen.getByText('failed')).toBeInTheDocument();
  });
});
