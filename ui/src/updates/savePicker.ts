import { isDesktop } from '../api/client';
import i18n from '../i18n';

// Destination of a downloaded installer.
//
// - Desktop (Tauri): the system save dialog of `tauri-plugin-dialog` (capability
//   `dialog:allow-save`), opened in the Downloads folder (`core:path:allow-resolve-directory`)
//   with the installer name. Modules imported on demand: the web build never loads them.
// - Web mode: no save dialog (the server refuses downloads there); `nativeSavePicker()` returns
//   null and the UI shows the release page instead.

/** Resolves to the absolute path chosen for `fileName`, or `null` when the user cancels. */
export type SavePicker = (fileName: string) => Promise<string | null>;

let override: SavePicker | null | undefined;

/** `name` inside the Downloads folder, or `name` alone when the folder is unknown. */
async function defaultPath(name: string): Promise<string> {
  try {
    const { downloadDir, sep } = await import('@tauri-apps/api/path');
    const dir = await downloadDir();
    const separator = sep();
    return dir.endsWith(separator) ? `${dir}${name}` : `${dir}${separator}${name}`;
  } catch {
    return name;
  }
}

/** System save dialog of the desktop app. */
export const desktopSavePicker: SavePicker = async (fileName) => {
  const { save } = await import('@tauri-apps/plugin-dialog');
  const picked = await save({ defaultPath: await defaultPath(fileName), title: i18n.t('views.updates.saveTitle') });
  return typeof picked === 'string' && picked !== '' ? picked : null;
};

/** Save dialog of the current platform, `null` in web mode. */
export function nativeSavePicker(): SavePicker | null {
  if (override !== undefined) return override;
  return isDesktop() ? desktopSavePicker : null;
}

/** Tests: replaces the platform picker (`undefined` restores the default). */
export function setNativeSavePicker(picker: SavePicker | null | undefined): void {
  override = picker;
}
