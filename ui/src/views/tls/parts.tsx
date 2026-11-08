import { Check, Copy } from 'lucide-react';
import { type ReactNode, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { TlsNamedValue } from '../../api/types/TlsNamedValue';
import { Badge } from '../../components/Badge';
import { cn } from '../../lib/cn';
import { CERT_ISSUE_KEYS, hex4, isCertIssue, isWeakness, suiteLabel } from './tlsFormat';

// Small building blocks of the TLS view.

/** Copies `value` to the clipboard; `name` describes it for assistive technologies. */
export function CopyButton({ value, name }: { value: string; name: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => {
      setCopied(false);
    }, 1500);
    return () => {
      clearTimeout(timer);
    };
  }, [copied]);
  const label = copied ? t('views.tls.copy.copied') : t('views.tls.copy.label', { name });
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={(e) => {
        // Inside a clickable row: copying must not select the row.
        e.stopPropagation();
        void navigator.clipboard?.writeText(value).then(() => {
          setCopied(true);
        });
      }}
      className="-my-1 inline-flex size-8 shrink-0 items-center justify-center rounded-md text-faint hover:bg-subtle hover:text-fg"
    >
      {copied ? (
        <Check aria-hidden size={16} strokeWidth={1.75} />
      ) : (
        <Copy aria-hidden size={16} strokeWidth={1.75} />
      )}
    </button>
  );
}

/** Monospace value, truncated with its full text on hover, and a copy button. */
export function MonoValue({ value, name, className }: { value: string; name: string; className?: string }) {
  return (
    <span className={cn('flex min-w-0 items-center gap-1', className)}>
      <span data-testid="truncatable" title={value} className="min-w-0 truncate font-mono text-meta">
        {value}
      </span>
      <CopyButton value={value} name={name} />
    </span>
  );
}

/** Amber dot of a weak suite, with its reason as accessible text. */
export function WeakDot({ weak }: { weak: string }) {
  const { t } = useTranslation();
  const label = isWeakness(weak) ? t(`views.tls.weak.${weak}`) : t('views.tls.weak.other');
  return (
    <span role="img" aria-label={label} title={label} className="inline-block size-2 shrink-0 rounded-full bg-warning" />
  );
}

/** Suite name (without `TLS_`), amber dot when weak. */
export function SuiteName({ name, id, weak }: { name: string | null; id: number | null; weak: string | null }) {
  const label = suiteLabel(name, id);
  return (
    <span className="flex min-w-0 items-center gap-1.5">
      {weak !== null && <WeakDot weak={weak} />}
      <span data-testid="truncatable" title={name ?? label} className="min-w-0 truncate font-mono text-meta">
        {label}
      </span>
    </span>
  );
}

/** Badges of the certificate issues of a session. */
export function IssueBadges({ issues }: { issues: readonly string[] }) {
  const { t } = useTranslation();
  return (
    <>
      {issues.filter(isCertIssue).map((issue) => (
        <Badge key={issue} tone={issue === 'expired' || issue === 'not_yet_valid' ? 'danger' : 'warning'}>
          {t(CERT_ISSUE_KEYS[issue])}
        </Badge>
      ))}
    </>
  );
}

/** Two-column description list that stacks on narrow widths. */
export function Fields({ children }: { children: ReactNode }) {
  return <dl className="grid min-w-0 grid-cols-1 gap-x-4 gap-y-2 sm:grid-cols-[minmax(0,12rem)_minmax(0,1fr)]">{children}</dl>;
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-meta text-muted sm:pt-0.5">{label}</dt>
      <dd className="min-w-0 [overflow-wrap:anywhere]">{children}</dd>
    </>
  );
}

/** Code points as wrapping chips: name when known, hexadecimal value, GREASE marked. */
export function CodeList({ values, empty }: { values: readonly TlsNamedValue[]; empty: string }) {
  const { t } = useTranslation();
  if (values.length === 0) return <span className="text-muted">{empty}</span>;
  return (
    <ul className="flex min-w-0 flex-wrap gap-1">
      {values.map((v, i) => {
        const code = hex4(v.value);
        const name = v.grease ? t('views.tls.detail.grease') : (v.name ?? t('views.tls.detail.unknown'));
        return (
          <li
            key={`${i}-${v.value}`}
            title={`${name} (${code}, ${v.value})`}
            className={cn(
              'inline-flex max-w-full items-center gap-1 rounded-md border border-line px-1.5 py-0.5 font-mono text-meta',
              v.grease && 'text-faint',
            )}
          >
            {v.weak !== null && <WeakDot weak={v.weak} />}
            <span className="min-w-0 truncate">{v.name ?? name}</span>
            <span className="shrink-0 text-faint">{code}</span>
          </li>
        );
      })}
    </ul>
  );
}
