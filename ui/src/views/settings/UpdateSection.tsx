import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { PackageFormat } from '../../api/types/PackageFormat';
import type { UpdateRelease } from '../../api/types/UpdateRelease';
import { Button } from '../../components/Button';
import { useInstallerDownload } from '../../updates/download';
import { DownloadStatus, ReleaseNotesDialog, ReleasePageLink } from '../../updates/parts';
import { useCheckUpdates, useUpdates } from '../../updates/queries';

// Settings > About: "Check for updates" (request made by the backend, ADR-025), result inline,
// and for a newer release its title, its notes and the download of the installer (desktop) or
// the release page (web dev mode).

interface UpdateSectionProps {
  readOnly: boolean;
}

export function UpdateSection({ readOnly }: UpdateSectionProps) {
  const { t } = useTranslation();
  const updates = useUpdates();
  const checkMutation = useCheckUpdates();
  const checking = checkMutation.isPending || updates.data?.checking === true;
  const result = updates.data?.check ?? null;

  let status = null;
  if (checking) {
    status = (
      <span role="status" className="text-muted" data-testid="update-status" data-status="checking">
        {t('views.updates.checking')}
      </span>
    );
  } else if (checkMutation.isError) {
    status = (
      <span role="alert" className="break-words text-danger" data-testid="update-status" data-status="failed">
        {t('views.updates.checkFailed')}
      </span>
    );
  } else if (result?.status === 'up_to_date') {
    status = (
      <span className="break-words text-success" data-testid="update-status" data-status="up-to-date">
        {t('views.updates.upToDate', { version: result.current_version })}
      </span>
    );
  } else if (result?.status === 'available' && result.release !== null) {
    status = (
      <span className="break-words font-medium text-accent" data-testid="update-status" data-status="available">
        {t('views.updates.available', { version: result.release.version })}
      </span>
    );
  }

  const release = !checking && result?.status === 'available' ? result.release : null;

  return (
    <div className="flex min-w-0 flex-col gap-2" data-testid="update-section">
      <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-2">
        <Button
          disabled={readOnly || checking}
          title={readOnly ? t('views.updates.readOnly') : undefined}
          onClick={() => {
            checkMutation.mutate();
          }}
        >
          {t('views.updates.check')}
        </Button>
        {status}
      </div>
      {release !== null && release.title !== null && (
        <p className="break-words text-muted [overflow-wrap:anywhere]" data-testid="update-title">
          {release.title}
        </p>
      )}
      {release !== null && <ReleaseActions release={release} canDownload={updates.data?.can_download ?? false} />}
      {readOnly && <p className="break-words text-meta text-muted">{t('views.updates.readOnly')}</p>}
      <p className="break-words text-meta text-muted">{t('views.updates.checkHost')}</p>
    </div>
  );
}

function ReleaseActions({ release, canDownload }: { release: UpdateRelease; canDownload: boolean }) {
  const { t } = useTranslation();
  const dl = useInstallerDownload(canDownload);
  const [notesOpen, setNotesOpen] = useState(false);
  const [format, setFormat] = useState<PackageFormat | null>(null);
  const formatId = useId();
  const installers = release.installers;
  const chosen = installers.find((i) => i.format === format) ?? installers[0];
  // The installed format is unknown (development build, unusual install): let the user choose.
  const choose = dl.available && !release.format_known && installers.length > 1;

  return (
    <div className="flex min-w-0 flex-col gap-2" data-testid="update-release">
      {choose && (
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <label htmlFor={formatId} className="text-meta text-muted">
            {t('views.updates.format')}
          </label>
          <select
            id={formatId}
            value={chosen?.format ?? ''}
            onChange={(e) => {
              setFormat(e.target.value as PackageFormat);
            }}
            className="h-8 max-w-full min-w-0 rounded-md border border-line bg-surface px-2 text-meta"
          >
            {installers.map((i) => (
              <option key={i.name} value={i.format}>
                {t(`views.updates.formats.${i.format}`)}
              </option>
            ))}
          </select>
        </div>
      )}
      <div className="flex min-w-0 flex-wrap gap-2">
        {dl.available && chosen !== undefined && (
          <Button
            variant="primary"
            disabled={dl.running}
            title={dl.running ? t('views.updates.errors.running') : chosen.name}
            onClick={() => {
              dl.start(chosen);
            }}
          >
            {t('views.updates.download')}
          </Button>
        )}
        <Button
          onClick={() => {
            setNotesOpen(true);
          }}
        >
          {t('views.updates.notes')}
        </Button>
      </div>
      {dl.available && installers.length === 0 && (
        <p className="break-words text-meta text-muted">{t('views.updates.noInstaller')}</p>
      )}
      {dl.available ? <DownloadStatus dl={dl} /> : <ReleasePageLink release={release} />}
      {notesOpen && (
        <ReleaseNotesDialog
          release={release}
          onClose={() => {
            setNotesOpen(false);
          }}
        />
      )}
    </div>
  );
}
