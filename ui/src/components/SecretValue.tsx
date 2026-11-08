import { Check, Copy, Eye, EyeOff } from 'lucide-react';
import { type ReactNode, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { cn } from '../lib/cn';

interface SecretValueProps {
  value: string;
  /** What the value is (`Cookie`, `Authorization`...), for the button labels. */
  label: string;
  /** Rendering of the revealed value (highlighting...); the raw value by default. */
  children?: ReactNode;
  className?: string;
}

/**
 * Sensitive value (credential, cookie, token): masked by default, with buttons to reveal it and
 * to copy it. The masked state shows the length only, never a part of the value.
 */
export function SecretValue({ value, label, children, className }: SecretValueProps) {
  const { t } = useTranslation();
  const [shown, setShown] = useState(false);
  const [copied, setCopied] = useState(false);
  const copy = () => {
    void navigator.clipboard
      .writeText(value)
      .then(() => {
        setCopied(true);
        window.setTimeout(() => {
          setCopied(false);
        }, 1500);
      })
      .catch(() => undefined);
  };
  return (
    <span className={cn('inline-flex max-w-full min-w-0 items-start gap-1', className)}>
      <span className={cn('min-w-0 [overflow-wrap:anywhere]', !shown && 'text-muted italic')}>
        {shown ? (children ?? value) : t('secret.hidden', { count: [...value].length })}
      </span>
      <button
        type="button"
        aria-pressed={shown}
        aria-label={shown ? t('secret.hide', { label }) : t('secret.show', { label })}
        title={shown ? t('secret.hide', { label }) : t('secret.show', { label })}
        onClick={() => {
          setShown((s) => !s);
        }}
        className="inline-flex size-6 shrink-0 items-center justify-center rounded-md text-muted hover:bg-subtle hover:text-fg"
      >
        {shown ? <EyeOff aria-hidden size={14} strokeWidth={1.75} /> : <Eye aria-hidden size={14} strokeWidth={1.75} />}
      </button>
      <button
        type="button"
        aria-label={t('secret.copy', { label })}
        title={copied ? t('secret.copied') : t('secret.copy', { label })}
        onClick={copy}
        className="inline-flex size-6 shrink-0 items-center justify-center rounded-md text-muted hover:bg-subtle hover:text-fg"
      >
        {copied ? <Check aria-hidden size={14} strokeWidth={1.75} /> : <Copy aria-hidden size={14} strokeWidth={1.75} />}
      </button>
    </span>
  );
}
