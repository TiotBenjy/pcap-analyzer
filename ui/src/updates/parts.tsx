import { useTranslation } from 'react-i18next';
import type { UpdateRelease } from '../api/types/UpdateRelease';
import { Dialog } from '../components/Dialog';
import { formatBytes } from '../lib/format';
import type { InstallerDownload } from './download';

// Pieces shared by the update banner and Settings > About. Release notes come from the network:
// always shown as plain text (React text nodes), never as HTML or Markdown.

/** Progress, saved path or failure of the download (nothing while idle). */
export function DownloadStatus({ dl }: { dl: InstallerDownload }) {
  const { t, i18n } = useTranslation();
  if (dl.error !== null) {
    return (
      <p role="alert" className="break-words text-meta text-danger" data-testid="update-download-error">
        {dl.error}
      </p>
    );
  }
  const d = dl.download;
  if (d === undefined || d.phase === 'idle') return null;
  if (d.phase === 'downloading') {
    const total = d.total_bytes;
    return (
      <div className="flex min-w-0 flex-col gap-0.5" data-testid="update-download-progress">
        <span role="status" className="text-meta [overflow-wrap:anywhere]">
          {t('views.updates.downloading', { name: d.asset ?? '' })}
        </span>
        {total !== null && total > 0 && (
          <span className="num text-meta text-muted">
            {t('views.updates.progressOf', {
              received: formatBytes(d.received_bytes, i18n.language),
              total: formatBytes(total, i18n.language),
            })}
          </span>
        )}
      </div>
    );
  }
  if (d.phase === 'done') {
    return (
      <div className="flex min-w-0 flex-col gap-0.5" data-testid="update-download-done">
        <span role="status" className="text-meta text-success [overflow-wrap:anywhere]">
          {t('views.updates.saved', { path: d.path ?? '' })}
        </span>
        <span className="break-words text-meta text-muted">{t('views.updates.manual')}</span>
      </div>
    );
  }
  return (
    <p role="alert" className="break-words text-meta text-danger" data-testid="update-download-error">
      {t(`views.updates.errors.${d.error ?? 'network'}`)}
    </p>
  );
}

/** Web dev mode: the page of the release, as a link (no download from the server there). */
export function ReleasePageLink({ release }: { release: UpdateRelease }) {
  const { t } = useTranslation();
  if (release.html_url === null) return null;
  return (
    <p className="min-w-0 text-meta text-muted" data-testid="update-release-page">
      {t('views.updates.releasePage')}{' '}
      <a
        href={release.html_url}
        target="_blank"
        rel="noreferrer noopener"
        className="text-accent underline-offset-2 [overflow-wrap:anywhere] hover:underline"
      >
        {release.html_url}
      </a>
    </p>
  );
}

/** Full release notes in a dialog, as plain text. */
export function ReleaseNotesDialog({ release, onClose }: { release: UpdateRelease; onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <Dialog open onClose={onClose} size="lg" title={t('views.updates.notesTitle', { version: release.version })}>
      <div className="flex min-w-0 flex-col gap-3" data-testid="update-notes">
        {release.notes === '' ? (
          <p className="text-muted">{t('views.updates.notesEmpty')}</p>
        ) : (
          <pre className="font-sans text-body break-words whitespace-pre-wrap [overflow-wrap:anywhere]">{release.notes}</pre>
        )}
        {release.notes_truncated && <p className="text-meta text-muted">{t('views.updates.notesTruncated')}</p>}
        <ReleasePageLink release={release} />
      </div>
    </Dialog>
  );
}
