import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { ApiError } from '../api/client';
import type { UpdateDownload } from '../api/types/UpdateDownload';
import type { UpdateInstaller } from '../api/types/UpdateInstaller';
import { describeError } from '../lib/errors';
import { useStartDownload, useUpdateDownload } from './queries';
import { nativeSavePicker } from './savePicker';

// Download of an installer, shared by the banner and Settings > About: the save dialog first
// (nothing is requested when it is cancelled), then the backend downloads and checks the file.

/** Problem types of `POST /updates/download` (`netsift-api/src/updates.rs`). */
const START_PROBLEMS = {
  'urn:netsift:problem:update-download-running': 'views.updates.errors.running',
  'urn:netsift:problem:update-path-invalid': 'views.updates.errors.path',
  'urn:netsift:problem:update-asset-unknown': 'views.updates.errors.asset',
  'urn:netsift:problem:update-not-checked': 'views.updates.errors.asset',
} as const;

function startErrorMessage(t: TFunction, error: unknown): string {
  if (error instanceof ApiError && error.kind in START_PROBLEMS) {
    return t(START_PROBLEMS[error.kind as keyof typeof START_PROBLEMS]);
  }
  return describeError(t, error).message;
}

export interface InstallerDownload {
  /** Downloads are possible here: desktop app (save dialog) and a server that accepts them. */
  available: boolean;
  /** Opens the save dialog, then starts the download; nothing happens when cancelled. */
  start: (installer: UpdateInstaller) => void;
  running: boolean;
  download: UpdateDownload | undefined;
  /** Failure before the download started (dialog, refused request), translated. */
  error: string | null;
}

/** Download of an installer: save dialog first, then the backend downloads and checks it. */
export function useInstallerDownload(canDownload: boolean): InstallerDownload {
  const { t } = useTranslation();
  const picker = nativeSavePicker();
  const available = picker !== null && canDownload;
  const state = useUpdateDownload(available);
  const startMutation = useStartDownload();
  const [pickError, setPickError] = useState<string | null>(null);
  const [picking, setPicking] = useState(false);

  const start = (installer: UpdateInstaller) => {
    if (picker === null) return;
    setPickError(null);
    startMutation.reset();
    setPicking(true);
    picker(installer.name).then(
      (path) => {
        setPicking(false);
        if (path !== null) startMutation.mutate({ asset: installer.name, path });
      },
      (e: unknown) => {
        setPicking(false);
        setPickError(t('views.updates.pickError', { message: e instanceof Error ? e.message : String(e) }));
      },
    );
  };

  let error = pickError;
  if (startMutation.isError) error = startErrorMessage(t, startMutation.error);
  return {
    available,
    start,
    running: picking || startMutation.isPending || state.data?.phase === 'downloading',
    download: state.data,
    error,
  };
}
