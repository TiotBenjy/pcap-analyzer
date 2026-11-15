import { useTranslation } from 'react-i18next';
import { KeepTogether } from '../../../components/KeepTogether';
import { DOWNLOAD_HOSTS } from '../../../updates/hosts';
import type { OnlineExtensionProps } from './extensions';

/** Under "Check for updates at startup": the hosts of the downloads, which only a click starts. */
export function UpdateHosts(_props: OnlineExtensionProps) {
  const { t } = useTranslation();
  return (
    <p className="break-words text-meta text-muted" data-testid="online-update-hosts">
      {/* Each host on one line: never split at its hyphen. */}
      <KeepTogether text={t('views.updates.onlineDownloads')} word={DOWNLOAD_HOSTS} />
    </p>
  );
}
