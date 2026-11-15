import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useInstallerDownload } from '../updates/download';
import { DownloadStatus, ReleaseNotesDialog, ReleasePageLink } from '../updates/parts';
import { useUpdates } from '../updates/queries';
import { NoticeSlot } from './NoticeSlot';
import type { Notice, NoticeAction, NoticeSlotProps } from './types';

// Newer release found by the startup check or by "Check for updates" (ADR-025): version and
// title of the release (plain text, from its GitHub name), full notes in a dialog, download on
// click (desktop) or the release page (web dev mode). Hidden per version.

export function UpdateNotice(slot: NoticeSlotProps) {
  const { t } = useTranslation();
  const updates = useUpdates();
  const [notesOpen, setNotesOpen] = useState(false);
  const check = updates.data?.check;
  const release = check?.status === 'available' ? check.release : null;
  // No request for the download state while there is nothing to download.
  const dl = useInstallerDownload((updates.data?.can_download ?? false) && release !== null);

  let notice: Notice | null = null;
  if (release !== null) {
    const installer = release.installers[0];
    const actions: NoticeAction[] = [];
    if (dl.available && installer !== undefined) {
      actions.push({
        label: t('views.updates.download'),
        primary: true,
        disabled: dl.running,
        title: dl.running ? t('views.updates.errors.running') : installer.name,
        onClick: () => {
          dl.start(installer);
        },
      });
    }
    actions.push({
      label: t('views.updates.notes'),
      onClick: () => {
        setNotesOpen(true);
      },
    });
    const title = release.title;
    notice = {
      dismissKey: release.version,
      message: t('views.updates.available', { version: release.version }),
      detail: (
        <div className="flex min-w-0 flex-col gap-1">
          {title !== null && (
            <span className="line-clamp-2" title={title} data-testid="update-title">
              {title}
            </span>
          )}
          {dl.available ? <DownloadStatus dl={dl} /> : <ReleasePageLink release={release} />}
        </div>
      ),
      actions,
    };
  }

  return (
    <>
      <NoticeSlot slot={slot} notice={notice} />
      {notesOpen && release !== null && (
        <ReleaseNotesDialog
          release={release}
          onClose={() => {
            setNotesOpen(false);
          }}
        />
      )}
    </>
  );
}
