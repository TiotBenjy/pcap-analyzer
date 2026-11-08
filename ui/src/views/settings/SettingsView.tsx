import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useHealth, useServerInfo } from '../../api/queries';
import { Badge } from '../../components/Badge';
import { Card } from '../../components/Card';
import { PageHeader } from '../../components/PageHeader';
import { SegmentedControl } from '../../components/SegmentedControl';
import { type LanguagePref, readLanguagePref, setLanguagePref } from '../../i18n';
import { type ThemePref, useTheme } from '../../theme/theme';

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
      <AboutCard />
    </div>
  );
}

function AboutCard() {
  const { t } = useTranslation();
  const health = useHealth();
  const info = useServerInfo();

  let backend;
  if (health.isPending) backend = <span className="text-muted">{t('views.settings.checking')}</span>;
  else if (health.isError) backend = <Badge tone="danger">{t('views.settings.backendDown')}</Badge>;
  else backend = <Badge tone="success">{t('views.settings.backendOk', { version: health.data.version })}</Badge>;

  return (
    <Card title={t('views.settings.about')}>
      <dl className="grid grid-cols-[minmax(0,7rem)_minmax(0,1fr)] items-center gap-x-4 gap-y-3">
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
        {/* CC BY 4.0 attribution of the country database. Plain text: the application never
            opens external URLs. Whether the database is installed is not exposed by the API yet. */}
        <dt className="self-start text-muted">{t('views.settings.geoip.label')}</dt>
        <dd className="flex min-w-0 flex-col gap-0.5" data-testid="geoip-attribution">
          <span className="break-words">{t('views.settings.geoip.attribution')}</span>
          <span className="break-all text-muted">{t('views.settings.geoip.source')}</span>
          <span className="break-words text-muted">{t('views.settings.geoip.license')}</span>
          <span className="break-all text-muted">{t('views.settings.geoip.licenseUrl')}</span>
        </dd>
      </dl>
    </Card>
  );
}
