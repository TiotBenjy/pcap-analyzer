import { Eye, EyeOff } from 'lucide-react';
import { type ReactNode, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { cn } from '../lib/cn';
import { CopyButton } from './CopyButton';

interface SecretValueProps {
  value: string;
  /** What the value is (`Cookie`, `Authorization`...), for the button labels. */
  label: string;
  /** Rendering of the revealed value (highlighting...); the raw value by default. */
  children?: ReactNode;
  className?: string;
  /**
   * Inside a line of text (transcript): the buttons keep their 32 px target but overflow the
   * line instead of making it taller, and the value stays on one line (truncated, full text on
   * hover once shown).
   */
  inline?: boolean;
}

/**
 * Sensitive value (credential, cookie, token): masked by default, with buttons to reveal it and
 * to copy it. The masked state shows the length only, never a part of the value.
 */
export function SecretValue({ value, label, children, className, inline = false }: SecretValueProps) {
  const { t } = useTranslation();
  const [shown, setShown] = useState(false);
  return (
    <span className={cn('inline-flex max-w-full min-w-0 gap-1', inline ? 'h-[1lh] items-center align-top' : 'items-start', className)}>
      <span
        className={cn('min-w-0', inline ? 'truncate' : '[overflow-wrap:anywhere]', !shown && 'text-muted italic')}
        {...(inline && shown ? { title: value } : {})}
      >
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
        className="-my-1 inline-flex size-8 shrink-0 items-center justify-center rounded-md text-faint hover:bg-subtle hover:text-fg"
      >
        {shown ? <EyeOff aria-hidden size={16} strokeWidth={1.75} /> : <Eye aria-hidden size={16} strokeWidth={1.75} />}
      </button>
      <CopyButton value={value} name={label} />
    </span>
  );
}
