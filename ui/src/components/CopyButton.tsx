import { Check, Copy } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { copyText } from '../lib/clipboard';
import { cn } from '../lib/cn';

/** How long the "copied" state stays visible, in ms. */
export const COPIED_MS = 1500;

interface CopyButtonProps {
  /** Text put on the clipboard. */
  value: string;
  /** What the value is (`SHA-256`, `Address`...), for the button label: "Copy SHA-256". */
  name: string;
  className?: string;
}

/**
 * The only copy action of the UI: 16 px icon in a 32 px target, label "Copy <name>", then a
 * check mark and "Copied" for a moment. Inside a clickable row, a click does not select the row.
 */
export function CopyButton({ value, name, className }: CopyButtonProps) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => {
      setCopied(false);
    }, COPIED_MS);
    return () => {
      window.clearTimeout(timer);
    };
  }, [copied]);
  const label = copied ? t('common.copied') : t('common.copy', { name });
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={(e) => {
        e.stopPropagation();
        void copyText(value).then((ok) => {
          if (ok) setCopied(true);
        });
      }}
      className={cn(
        '-my-1 inline-flex size-8 shrink-0 items-center justify-center rounded-md hover:bg-subtle',
        copied ? 'text-success' : 'text-faint hover:text-fg',
        className,
      )}
    >
      {copied ? <Check aria-hidden size={16} strokeWidth={1.75} /> : <Copy aria-hidden size={16} strokeWidth={1.75} />}
    </button>
  );
}
