import { X } from 'lucide-react';
import { type KeyboardEvent, type ReactNode, useEffect, useId, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import { cn } from '../lib/cn';
import { Button } from './Button';

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

// Number of open dialogs: the application root stays inert while at least one is open.
let openCount = 0;

function setRootInert(inert: boolean): void {
  const root = document.getElementById('root');
  if (root !== null) root.inert = inert;
}

interface DialogProps {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  /** Secondary line under the title (step, context). */
  description?: ReactNode;
  children: ReactNode;
  /** Buttons, right-aligned (wrap on narrow widths). */
  footer?: ReactNode;
  /** `sm`: confirmations and short forms; `lg`: wizards (full screen below 640 px). */
  size?: 'sm' | 'lg';
}

/**
 * Accessible modal dialog: `role="dialog"`, labelled by its title, focus moved inside on open
 * (first `[data-autofocus]` element, else the first focusable), Tab cycles inside, Escape and
 * the close button call `onClose`, focus returns to the previously focused element on close.
 * The rest of the application is inert while it is open.
 */
export function Dialog({ open, onClose, title, description, children, footer, size = 'sm' }: DialogProps) {
  const { t } = useTranslation();
  const panelRef = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const descId = useId();

  useEffect(() => {
    if (!open) return undefined;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    openCount += 1;
    setRootInert(true);
    const panel = panelRef.current;
    const target =
      panel?.querySelector<HTMLElement>('[data-autofocus]') ?? panel?.querySelector<HTMLElement>(FOCUSABLE) ?? panel;
    target?.focus();
    return () => {
      openCount -= 1;
      if (openCount === 0) setRootInert(false);
      previous?.focus();
    };
  }, [open]);

  if (!open) return null;

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'Escape') {
      e.stopPropagation();
      onClose();
      return;
    }
    if (e.key !== 'Tab' || panelRef.current === null) return;
    const items = [...panelRef.current.querySelectorAll<HTMLElement>(FOCUSABLE)];
    const first = items[0];
    const last = items.at(-1);
    if (first === undefined || last === undefined) {
      e.preventDefault();
      return;
    }
    const active = document.activeElement;
    if (e.shiftKey && (active === first || active === panelRef.current)) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && active === last) {
      e.preventDefault();
      first.focus();
    }
  };

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center sm:p-4" onKeyDown={onKeyDown}>
      {/* Backdrop: pointer-only dismissal (keyboard users have Escape and the close button). */}
      <div aria-hidden className="absolute inset-0 bg-zinc-950/40" onClick={onClose} />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description === undefined ? undefined : descId}
        tabIndex={-1}
        className={cn(
          'relative flex w-full min-w-0 flex-col border border-line bg-surface text-fg shadow-xs',
          size === 'sm'
            ? 'mx-3 max-h-[calc(100dvh-1.5rem)] max-w-md rounded-lg'
            : 'h-full max-h-dvh sm:h-auto sm:max-h-[calc(100dvh-2rem)] sm:max-w-3xl sm:rounded-lg',
        )}
      >
        <header className="flex shrink-0 items-start gap-2 border-b border-line px-3 py-2.5 sm:px-4">
          <div className="min-w-0 flex-1">
            <h2 id={titleId} className="truncate text-card font-medium">
              {title}
            </h2>
            {description !== undefined && (
              <p id={descId} className="text-meta text-muted">
                {description}
              </p>
            )}
          </div>
          <Button variant="ghost" icon aria-label={t('common.close')} title={t('common.close')} onClick={onClose}>
            <X aria-hidden size={16} strokeWidth={1.75} />
          </Button>
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto p-3 sm:p-4">{children}</div>
        {footer !== undefined && (
          <footer className="flex shrink-0 flex-wrap items-center justify-end gap-2 border-t border-line px-3 py-2.5 sm:px-4">
            {footer}
          </footer>
        )}
      </div>
    </div>,
    document.body,
  );
}
