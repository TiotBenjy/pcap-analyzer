import '../i18n';
import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { errorDetails } from '../lib/errorReport';
import { setupUser } from '../test/user';
import { RouteError } from './RouteError';

function failure(): Error {
  const err = new TypeError('Attempted to assign to readonly property.');
  err.stack = 'j_@http://127.0.0.1/assets/echarts.js:35:30753\nmodule code@http://127.0.0.1/assets/echarts.js:35:30552';
  return err;
}

const props = (error: unknown) => ({ error: error as Error, reset: () => undefined, info: { componentStack: '' } });

describe('errorDetails', () => {
  it('holds the error, its stack, the route pattern and the user agent', () => {
    const text = errorDetails(failure(), '#/sessions/01ABCDEF/overview?x=1', 'WebKitGTK');
    expect(text).toContain('TypeError: Attempted to assign to readonly property.');
    expect(text).toContain('j_@http://127.0.0.1/assets/echarts.js:35:30753');
    expect(text).toContain('route: /sessions/:id/overview');
    expect(text).not.toContain('01ABCDEF');
    expect(text).not.toContain('x=1');
    expect(text).toContain('user agent: WebKitGTK');
  });

  it('describes a thrown non-Error value', () => {
    expect(errorDetails('boom', '', 'ua')).toContain('Non-Error thrown: boom');
    expect(errorDetails(Object.create(null), '', 'ua')).toContain('Non-Error thrown: object');
  });
});

describe('RouteError', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('shows a short message, the error, and reload / copy actions', () => {
    render(<RouteError {...props(failure())} />);
    const alert = screen.getByRole('alert');
    expect(alert).toHaveAttribute('data-testid', 'route-error');
    expect(screen.getByRole('heading', { level: 1, name: 'This view could not be displayed' })).toBeInTheDocument();
    expect(screen.getByText('Attempted to assign to readonly property.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reload' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy details' })).toBeInTheDocument();
    expect(screen.queryByText('Something went wrong!')).toBeNull();
  });

  it('copies the message and the stack', async () => {
    const user = setupUser();
    const writeText = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue(undefined);
    render(<RouteError {...props(failure())} />);
    await user.click(screen.getByRole('button', { name: 'Copy details' }));
    expect(writeText).toHaveBeenCalledTimes(1);
    const copied = writeText.mock.calls[0]?.[0] ?? '';
    expect(copied).toContain('TypeError: Attempted to assign to readonly property.');
    expect(copied).toContain('module code@http://127.0.0.1/assets/echarts.js:35:30552');
    expect(await screen.findByText('Details copied')).toBeInTheDocument();
  });

  it('reports a failed copy and keeps the details selectable', async () => {
    const user = setupUser();
    vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValue(new Error('denied'));
    render(<RouteError {...props(failure())} />);
    await user.click(screen.getByRole('button', { name: 'Copy details' }));
    expect(await screen.findByText('Copy failed: select the details below')).toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: 'Error details' })).toHaveValue(
      errorDetails(failure(), window.location.hash, navigator.userAgent),
    );
  });
});
