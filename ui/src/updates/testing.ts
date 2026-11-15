import type { UpdateCheck } from '../api/types/UpdateCheck';
import type { UpdateDownload } from '../api/types/UpdateDownload';
import type { UpdateRelease } from '../api/types/UpdateRelease';
import type { UpdateState } from '../api/types/UpdateState';

// Test data of the update check (Vitest only).

export const DEB = 'NetSift_0.2.0_amd64.deb';
export const APPIMAGE = 'NetSift_0.2.0_amd64.AppImage';
/** Release name of `release.yml` with a title (markup that must stay text). */
const RELEASE_NAME = 'NetSift v0.2.0 — <b>Faster</b> imports';

export function release(extra: Partial<UpdateRelease> = {}): UpdateRelease {
  return {
    version: '0.2.0',
    name: RELEASE_NAME,
    title: '<b>Faster</b> imports',
    notes: '## Fixes\n\n- <b>Faster</b> import\n- Second line',
    notes_truncated: false,
    html_url: 'https://github.com/TiotBenjy/pcap-analyzer/releases/tag/v0.2.0',
    installers: [
      { name: DEB, size: 120_000_000, format: 'deb' },
      { name: APPIMAGE, size: 130_000_000, format: 'appimage' },
    ],
    format_known: true,
    ...extra,
  };
}

export function available(rel: UpdateRelease = release()): UpdateCheck {
  return {
    status: 'available',
    current_version: '0.1.0',
    latest_version: rel.version,
    checked_at_us: 1_700_000_000_000_000,
    release: rel,
  };
}

export const UP_TO_DATE: UpdateCheck = {
  status: 'up_to_date',
  current_version: '0.1.0',
  latest_version: '0.1.0',
  checked_at_us: 1_700_000_000_000_000,
  release: null,
};

export function state(check: UpdateCheck | null, extra: Partial<UpdateState> = {}): UpdateState {
  return { current_version: '0.1.0', checking: false, check, can_download: true, ...extra };
}

export const IDLE: UpdateDownload = {
  phase: 'idle',
  asset: null,
  received_bytes: 0,
  total_bytes: null,
  path: null,
  error: null,
};
