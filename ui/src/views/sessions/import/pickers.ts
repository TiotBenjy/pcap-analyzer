import type { PickKind } from '../../../app/importTracker';

// Path selection for the import wizard.
//
// - Web mode (./x.sh dev, vite preview): no native dialog. `nativePicker()` returns null and the
//   wizard renders the in-app <FolderBrowser>, built on `GET /fs/browse` and limited to the
//   backend's allowed roots.
// - Desktop (Tauri): EXTENSION POINT for P2.5. Return a picker backed by the dialog plugin, e.g.
//     if (isDesktop()) return async (kind) => {
//       const { open } = await import('@tauri-apps/plugin-dialog');
//       const r = await open({ directory: kind === 'folder', multiple: false });
//       return typeof r === 'string' ? r : null;
//     };
//   The wizard then shows a "Choose a folder" button that calls `pickFolder()` / `pickFile()`.

/** Resolves to an absolute path, or `null` when the user cancels. */
export type NativePicker = (kind: PickKind) => Promise<string | null>;

let override: NativePicker | null | undefined;

/** Native dialog picker of the current platform, `null` in web mode. */
export function nativePicker(): NativePicker | null {
  if (override !== undefined) return override;
  return null; // P2.5: desktop dialog (see above).
}

/** Tests and P2.5 wiring: replaces the platform picker (`undefined` restores the default). */
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
