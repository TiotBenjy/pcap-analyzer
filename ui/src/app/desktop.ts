import { isDesktop } from '../api/client';

// Calls into the desktop shell (Tauri commands of apps/desktop). No-ops in web mode; the Tauri
// bridge is imported on demand so the web build never loads it.

/** Reports the UI language so the native dialogs (close confirmation) use it. */
export async function reportLanguage(lang: string): Promise<void> {
  if (!isDesktop()) return;
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke('set_ui_language', { lang });
  } catch {
    /* best effort: the dialogs fall back to the system locale */
  }
}
