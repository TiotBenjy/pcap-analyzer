import { useTranslation } from 'react-i18next';
import { Card } from '../../components/Card';
import { PageHeader } from '../../components/PageHeader';
import { SegmentedControl } from '../../components/SegmentedControl';
import { type LanguagePref, readLanguagePref, setLanguagePref } from '../../i18n';
import { type ThemePref, useTheme } from '../../theme/theme';
import { useState } from 'react';

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
    </div>
  );
}
