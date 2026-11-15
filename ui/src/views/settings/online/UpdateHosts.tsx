import { useTranslation } from 'react-i18next';
import type { OnlineExtensionProps } from './extensions';

/** Hosts of an installer download: GitHub, then its file storage (ADR-027). */
const DOWNLOAD_HOSTS = ['github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'];

/** Under "Check for updates at startup": the hosts of the downloads, which only a click starts. */
export function UpdateHosts(_props: OnlineExtensionProps) {
  const { t } = useTranslation();
  return (
    <p className="break-words text-meta text-muted" data-testid="online-update-hosts">
      {t('views.updates.onlineDownloads')}{' '}
      {DOWNLOAD_HOSTS.map((host, i) => (
        <span key={host}>
          {/* One host per line at most: never split at its hyphen. */}
          <span className="whitespace-nowrap">{host}</span>
          {i < DOWNLOAD_HOSTS.length - 1 ? ', ' : ''}
        </span>
      ))}
    </p>
  );
}
