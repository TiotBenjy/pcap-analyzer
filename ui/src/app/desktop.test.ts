import { afterEach, describe, expect, it, vi } from 'vitest';
import { reportLanguage } from './desktop';

const invoke = vi.fn<(cmd: string, args?: unknown) => Promise<unknown>>();
vi.mock('@tauri-apps/api/core', () => ({ invoke: (cmd: string, args?: unknown) => invoke(cmd, args) }));

function setDesktop(on: boolean) {
  if (on) Object.defineProperty(window, '__TAURI_INTERNALS__', { value: {}, configurable: true });
  else Reflect.deleteProperty(window, '__TAURI_INTERNALS__');
}

describe('reportLanguage', () => {
  afterEach(() => {
    setDesktop(false);
    invoke.mockReset();
  });

  it('does nothing in web mode', async () => {
    await reportLanguage('fr');
    expect(invoke).not.toHaveBeenCalled();
  });

  it('sends the language to the desktop shell', async () => {
    setDesktop(true);
    invoke.mockResolvedValue(null);
    await reportLanguage('fr');
    expect(invoke).toHaveBeenCalledWith('set_ui_language', { lang: 'fr' });
  });

  it('ignores a failing command', async () => {
    setDesktop(true);
    invoke.mockRejectedValue(new Error('command not found'));
    await expect(reportLanguage('en')).resolves.toBeUndefined();
  });
});
