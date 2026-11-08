import { isDesktop } from '../../../api/client';
import type { PickKind } from '../../../app/importTracker';
import i18n from '../../../i18n';

// Path selection for the import wizard.
//
// - Web mode (./x.sh dev, vite preview): no native dialog. `nativePicker()` returns null and the
//   wizard renders the in-app <FolderBrowser>, built on `GET /fs/browse` and limited to the
//   backend's allowed roots.
// - Desktop (Tauri): the system open dialog of `tauri-plugin-dialog` (capability
//   `dialog:allow-open`). The plugin is imported on demand, so the web build never loads it.
//   Any absolute path is accepted by the desktop API (`allow_any_path`).

/** Resolves to an absolute path, or `null` when the user cancels. */
export type NativePicker = (kind: PickKind) => Promise<string | null>;

let override: NativePicker | null | undefined;

/** System open dialog of the desktop app. */
export const desktopPicker: NativePicker = async (kind) => {
  const { open } = await import('@tauri-apps/plugin-dialog');
  const folder = kind === 'folder';
  const picked = await open({
    directory: folder,
    multiple: false,
    title: i18n.t(folder ? 'views.import.chooseFolder' : 'views.import.chooseFile'),
  });
  // `multiple: false` yields a single path; anything else is treated as a cancellation.
  return typeof picked === 'string' && picked !== '' ? picked : null;
};

/** Native dialog picker of the current platform, `null` in web mode. */
export function nativePicker(): NativePicker | null {
  if (override !== undefined) return override;
  return isDesktop() ? desktopPicker : null;
}

/** Tests: replaces the platform picker (`undefined` restores the default). */
export function setNativePicker(picker: NativePicker | null | undefined): void {
  override = picker;
}

function pick(kind: PickKind): Promise<string | null> {
  const picker = nativePicker();
  if (picker === null) return Promise.reject(new Error('no native picker in web mode'));
  return picker(kind);
}

export function pickFolder(): Promise<string | null> {
  return pick('folder');
}

export function pickFile(): Promise<string | null> {
  return pick('file');
}
