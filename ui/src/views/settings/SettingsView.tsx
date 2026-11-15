import { Fragment, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { license as PROJECT_LICENSE, version as APP_VERSION } from '../../../package.json';
import { useHealth, useServerInfo } from '../../api/queries';
import { Badge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Card } from '../../components/Card';
import { PageHeader } from '../../components/PageHeader';
import { SegmentedControl } from '../../components/SegmentedControl';
import { type LanguagePref, readLanguagePref, setLanguagePref } from '../../i18n';
import { type ThemePref, useTheme } from '../../theme/theme';
import { GeoipSection } from './GeoipSection';
import { ThirdPartyLicensesDialog } from './licenses/ThirdPartyLicenses';
import { OnlineCard } from './online/OnlineCard';
import { UpdateSection } from './UpdateSection';

/** Shown as text only: the application never opens external URLs (no network, opener limited to exports/). */
const REPOSITORY_URL = 'https://github.com/TiotBenjy/pcap-analyzer';

export default function SettingsView() {
  const { t } = useTranslation();
  const { pref, setPref } = useTheme();
  const [lang, setLang] = useState<LanguagePref>(readLanguagePref);

  return (
    <div className="flex flex-col gap-4">
      <PageHeader title={t('nav.items.settings')} subtitle={t('views.settings.subtitle')} />
      <Card title={t('views.settings.appearance')}>
        <div className="flex flex-col gap-4">
          <SegmentedControl<ThemePref>
            label={t('theme.label')}
            value={pref}
            onChange={setPref}
            options={[
              { value: 'system', label: t('theme.system') },
              { value: 'light', label: t('theme.light') },
              { value: 'dark', label: t('theme.dark') },
            ]}
          />
          <SegmentedControl<LanguagePref>
            label={t('language.label')}
            value={lang}
            onChange={(v) => {
              setLang(v);
              setLanguagePref(v);
            }}
            options={[
              { value: 'system', label: t('language.system') },
              { value: 'en', label: t('language.en') },
              { value: 'fr', label: t('language.fr') },
            ]}
          />
        </div>
      </Card>
      <OnlineCard />
      <AboutCard />
    </div>
  );
}

function AboutCard() {
  const { t } = useTranslation();
  const health = useHealth();
  const info = useServerInfo();
  const [licensesOpen, setLicensesOpen] = useState(false);

  let backend;
  if (health.isPending) backend = <span className="text-muted">{t('views.settings.checking')}</span>;
  else if (health.isError) backend = <Badge tone="danger">{t('views.settings.backendDown')}</Badge>;
  else backend = <Badge tone="success">{t('views.settings.backendOk', { version: health.data.version })}</Badge>;

  return (
    <Card title={t('views.settings.about')}>
      <dl className="grid grid-cols-[minmax(0,7rem)_minmax(0,1fr)] items-baseline gap-x-4 gap-y-3">
        <dt className="text-muted">{t('views.settings.version')}</dt>
        <dd className="num min-w-0" data-testid="app-version">
          {APP_VERSION}
        </dd>
        {/* Full width below 640 px, like the GeoIP row: buttons and status need the room. */}
        <dt className="col-span-2 self-start text-muted sm:col-span-1">{t('views.updates.label')}</dt>
        <dd className="col-span-2 min-w-0 sm:col-span-1">
          <UpdateSection readOnly={info.data?.read_only ?? true} />
        </dd>
        <dt className="text-muted">{t('views.settings.license')}</dt>
        <dd className="min-w-0 break-words" data-testid="app-license">
          {PROJECT_LICENSE}
        </dd>
        <dt className="text-muted">{t('views.settings.sourceCode')}</dt>
        <dd className="min-w-0 break-words select-all" data-testid="app-repository">
          {/* Break opportunities after each slash only: the address never splits inside a word. */}
          {REPOSITORY_URL.split('/').map((part, i, parts) => (
            <Fragment key={i}>
              {part}
              {i < parts.length - 1 && (
                <>
                  /<wbr />
                </>
              )}
            </Fragment>
          ))}
        </dd>
        <dt className="text-muted">{t('views.settings.backend')}</dt>
        <dd className="min-w-0" data-testid="backend-status">
          {backend}
        </dd>
        {info.data !== undefined && (
          <>
            <dt className="text-muted">{t('views.settings.mode')}</dt>
            <dd className="min-w-0" data-testid="server-mode">
              {info.data.read_only ? t('views.settings.readOnly') : t('views.settings.readWrite')}
            </dd>
          </>
        )}
        {/* Country database: state, updates and CC BY 4.0 attribution. Full width below 640 px:
            the buttons do not fit the value column of a phone. */}
        <dt className="col-span-2 self-start text-muted sm:col-span-1">{t('views.settings.geoip.label')}</dt>
        <dd className="col-span-2 min-w-0 sm:col-span-1">
          <GeoipSection info={info.data} infoError={info.isError} />
        </dd>
        <dt className="col-span-2 self-start text-muted sm:col-span-1">{t('views.settings.thirdParty.label')}</dt>
        <dd className="col-span-2 flex min-w-0 flex-col items-start gap-2 sm:col-span-1">
          <span className="break-words text-meta text-muted">{t('views.settings.thirdParty.description')}</span>
          <Button
            onClick={() => {
              setLicensesOpen(true);
            }}
          >
            {t('views.settings.thirdParty.open')}
          </Button>
        </dd>
      </dl>
      {licensesOpen && (
        <ThirdPartyLicensesDialog
          onClose={() => {
            setLicensesOpen(false);
          }}
        />
      )}
    </Card>
  );
}
