import { useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useDismissNotice, useSettings } from '../api/settingsQueries';
import type { DismissedNotice } from '../api/types/DismissedNotice';
import { MAX_NOTICES, NOTICE_PROVIDERS } from './providers';
import type { NoticeProvider, NoticeSlotProps } from './types';

type Keys = Readonly<Record<string, string>>;

interface NoticeAreaProps {
  /** Tests only: the production registry by default. */
  providers?: readonly NoticeProvider[];
  max?: number;
}

/**
 * Stack of notices under the application header. Providers report the dismiss key of their
 * current notice; the area shows the first `max` of them, in registry order, that are not
 * dismissed for that key. Dismissals are kept in the server settings, and locally for the rest
 * of the session when the server refuses them (read-only).
 */
export function NoticeArea({ providers = NOTICE_PROVIDERS, max = MAX_NOTICES }: NoticeAreaProps) {
  const { t } = useTranslation();
  const [active, setActive] = useState<Keys>({});
  const [hidden, setHidden] = useState<Keys>({});
  const anyActive = Object.keys(active).length > 0;
  // Fetched only once a notice wants to show: none in the usual case.
  const settings = useSettings(anyActive);
  const dismissMutation = useDismissNotice();
  const { mutate } = dismissMutation;

  const slots = useMemo(() => {
    const out = new Map<string, Pick<NoticeSlotProps, 'report' | 'dismiss'>>();
    for (const { id } of providers) {
      out.set(id, {
        report: (key) => {
          setActive((prev) => {
            if ((prev[id] ?? null) === key) return prev;
            if (key !== null) return { ...prev, [id]: key };
            return Object.fromEntries(Object.entries(prev).filter(([other]) => other !== id));
          });
        },
        dismiss: (key) => {
          setHidden((prev) => ({ ...prev, [id]: key }));
          mutate({ id, key });
        },
      });
    }
    return out;
  }, [providers, mutate]);

  const isDismissed = useCallback(
    (id: string, key: string) => {
      if (hidden[id] === key) return true;
      // Defensive: a server or a test double may answer without the list.
      const server: unknown = settings.data?.dismissed_notices;
      return Array.isArray(server) && (server as readonly DismissedNotice[]).some((n) => n.id === id && n.key === key);
    },
    [hidden, settings.data],
  );

  // Until the dismissals are known, nothing shows: a dismissed notice must not flash.
  const ready = !settings.isPending || settings.isError;
  const visible = new Set<string>();
  if (ready) {
    for (const { id } of providers) {
      const key = active[id];
      if (visible.size < max && key !== undefined && !isDismissed(id, key)) visible.add(id);
    }
  }

  return (
    // A landmark only while it shows something; a live region always, so new notices are read.
    <div
      role={visible.size > 0 ? 'region' : undefined}
      aria-label={visible.size > 0 ? t('notices.region') : undefined}
      aria-live="polite"
      className="shrink-0"
      data-testid="notice-area"
    >
      {providers.map(({ id, Component }) => {
        const slot = slots.get(id);
        if (slot === undefined) return null;
        return <Component key={id} id={id} visible={visible.has(id)} report={slot.report} dismiss={slot.dismiss} />;
      })}
    </div>
  );
}
