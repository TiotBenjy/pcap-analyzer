import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useServerInfo } from '../../../api/queries';
import { useSettings, useUpdateSettings } from '../../../api/settingsQueries';
import type { OnlineSettings } from '../../../api/types/OnlineSettings';
import { Card } from '../../../components/Card';
import { ErrorNote } from '../../../components/ErrorNote';
import { cn } from '../../../lib/cn';
import { ONLINE_EXTENSIONS, type OnlineExtension } from './extensions';

type OnlineKey = keyof OnlineSettings;

/** The switches, in display order. Labels and hints come from `views.online`. */
const CHECKS = [
  { setting: 'geoip_check', label: 'views.online.geoipCheck', hint: 'views.online.geoipCheckHint' },
  { setting: 'update_check', label: 'views.online.updateCheck', hint: 'views.online.updateCheckHint' },
] as const satisfies readonly { setting: OnlineKey; label: string; hint: string }[];

interface OnlineCardProps {
  /** Tests only: the production registry by default. */
  extensions?: readonly OnlineExtension[];
}

/**
 * Settings > Online: the online checks run at startup (ADR-025), off by default and stored by
 * the server. Each feature adds its own content under its switch (`extensions.ts`).
 */
export function OnlineCard({ extensions = ONLINE_EXTENSIONS }: OnlineCardProps) {
  const { t } = useTranslation();
  const settings = useSettings();
  const info = useServerInfo();
  const update = useUpdateSettings();
  const [changed, setChanged] = useState(false);
  const readOnly = info.data?.read_only ?? false;
  const online = settings.data?.online;

  const toggle = (setting: OnlineKey, value: boolean) => {
    setChanged(true);
    update.mutate({ online: { [setting]: value } });
  };

  return (
    <Card title={t('views.online.title')}>
      <div className="flex min-w-0 flex-col gap-4" data-testid="online-settings">
        <p className="break-words text-muted">{t('views.online.description')}</p>
        {settings.isError && (
          <p role="alert" className="break-words text-danger">
            {t('views.online.loadError')}
          </p>
        )}
        <ul className="flex min-w-0 flex-col gap-4">
          {CHECKS.map(({ setting, label, hint }) => {
            // While a change is saved, the switch shows the requested value.
            const pending = update.isPending ? update.variables.online?.[setting] : undefined;
            const checked = pending ?? online?.[setting] ?? false;
            return (
              <li key={setting} className="flex min-w-0 flex-col gap-2">
                <SwitchRow
                  label={t(label)}
                  hint={t(hint)}
                  checked={checked}
                  disabled={online === undefined || readOnly || update.isPending}
                  disabledReason={readOnly ? t('views.online.readOnly') : undefined}
                  testId={`online-${setting}`}
                  onChange={(value) => {
                    toggle(setting, value);
                  }}
                />
                {extensions
                  .filter((e) => e.setting === setting)
                  .map(({ id, Component }) => (
                    <Component key={id} enabled={online?.[setting] ?? false} readOnly={readOnly} />
                  ))}
              </li>
            );
          })}
        </ul>
        {update.isError && (
          <ErrorNote error={update.error} format={(message) => t('views.online.saveError', { message })} />
        )}
        {readOnly && <p className="break-words text-meta text-muted">{t('views.online.readOnly')}</p>}
        {changed && update.isSuccess && <p className="break-words text-meta text-muted">{t('views.online.nextStart')}</p>}
      </div>
    </Card>
  );
}

interface SwitchRowProps {
  label: string;
  hint: string;
  checked: boolean;
  disabled: boolean;
  disabledReason: string | undefined;
  testId: string;
  onChange: (checked: boolean) => void;
}

/** Label and hint on the left, switch on the right; the label wraps instead of being cut. */
function SwitchRow({ label, hint, checked, disabled, disabledReason, testId, onChange }: SwitchRowProps) {
  const labelId = useId();
  const hintId = useId();
  return (
    <div className="flex min-w-0 items-start justify-between gap-3">
      <div className="flex min-w-0 flex-col gap-0.5">
        <span id={labelId} className="break-words">
          {label}
        </span>
        <span id={hintId} className="break-words text-meta text-muted">
          {hint}
        </span>
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-labelledby={labelId}
        aria-describedby={hintId}
        disabled={disabled}
        title={disabledReason}
        data-testid={testId}
        onClick={() => {
          onChange(!checked);
        }}
        className="inline-flex h-8 w-11 shrink-0 items-center justify-center rounded-md disabled:cursor-not-allowed disabled:opacity-50"
      >
        <span
          aria-hidden
          className={cn('relative h-5 w-9 rounded-full transition-colors', checked ? 'bg-accent' : 'bg-faint/50')}
        >
          <span
            className={cn(
              'absolute top-0.5 size-4 rounded-full bg-white transition-[left]',
              checked ? 'left-[1.125rem]' : 'left-0.5',
            )}
          />
        </span>
      </button>
    </div>
  );
}
