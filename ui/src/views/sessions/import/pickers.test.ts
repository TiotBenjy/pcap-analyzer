import '../../../i18n';
import { afterEach, describe, expect, it, vi } from 'vitest';
import i18n from '../../../i18n';
import { desktopPicker, nativePicker, pickFile, pickFolder, setNativePicker } from './pickers';

const open = vi.fn<(options: unknown) => Promise<string | string[] | null>>();
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: (options: unknown) => open(options) }));

function setDesktop(on: boolean) {
  if (on) Object.defineProperty(window, '__TAURI_INTERNALS__', { value: {}, configurable: true });
  else Reflect.deleteProperty(window, '__TAURI_INTERNALS__');
}

describe('nativePicker', () => {
  afterEach(() => {
    setDesktop(false);
    setNativePicker(undefined);
    open.mockReset();
  });

  it('is null in web mode, so the wizard shows the folder browser', async () => {
    expect(nativePicker()).toBeNull();
    await expect(pickFolder()).rejects.toThrow('no native picker');
  });

  it('uses the dialog plugin in the desktop app', async () => {
    setDesktop(true);
    expect(nativePicker()).toBe(desktopPicker);

    await i18n.changeLanguage('en');
    open.mockResolvedValueOnce('/home/u/captures/run1');
    await expect(pickFolder()).resolves.toBe('/home/u/captures/run1');
    expect(open).toHaveBeenLastCalledWith({ directory: true, multiple: false, title: 'Choose a folder' });

    open.mockResolvedValueOnce('C:\\captures\\office.pcapng');
    await expect(pickFile()).resolves.toBe('C:\\captures\\office.pcapng');
    expect(open).toHaveBeenLastCalledWith({ directory: false, multiple: false, title: 'Choose a file' });
  });

  it('maps a cancelled or unexpected answer to null', async () => {
    setDesktop(true);
    open.mockResolvedValueOnce(null);
    await expect(pickFolder()).resolves.toBeNull();
    open.mockResolvedValueOnce(['/a', '/b']);
    await expect(pickFolder()).resolves.toBeNull();
    open.mockResolvedValueOnce('');
    await expect(pickFile()).resolves.toBeNull();
  });

  it('titles the dialog in the UI language', async () => {
    setDesktop(true);
    await i18n.changeLanguage('fr');
    open.mockResolvedValueOnce(null);
    await pickFolder();
    const options = open.mock.calls[0]?.[0] as { title: string };
    expect(options.title).toBe(i18n.t('views.import.chooseFolder'));
    expect(options.title).not.toBe('Choose a folder');
    await i18n.changeLanguage('en');
  });

  it('propagates dialog errors to the wizard', async () => {
    setDesktop(true);
    open.mockRejectedValueOnce(new Error('dialog unavailable'));
    await expect(pickFolder()).rejects.toThrow('dialog unavailable');
  });

  it('can be overridden by tests', async () => {
    const picker = vi.fn(() => Promise.resolve('/x'));
    setNativePicker(picker);
    await expect(pickFile()).resolves.toBe('/x');
    expect(picker).toHaveBeenCalledWith('file');
    setNativePicker(null);
    expect(nativePicker()).toBeNull();
  });
});
