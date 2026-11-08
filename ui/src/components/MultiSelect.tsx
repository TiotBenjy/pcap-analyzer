import { ChevronDown } from 'lucide-react';
import { useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { cn } from '../lib/cn';
import { Button } from './Button';

export interface MultiSelectOption<T extends string> {
  value: T;
  label: string;
  /** Color swatch (chart series). Identity is never color-only: the label is always shown. */
  color?: string;
  /** Right-aligned secondary text (total, count). */
  detail?: string;
}

interface MultiSelectProps<T extends string> {
  label: string;
  options: readonly MultiSelectOption<T>[];
  selected: ReadonlySet<T>;
  onChange: (selected: Set<T>) => void;
  /** Edge of the button the panel is aligned on: `end` for a control at the right of a header. */
  align?: 'start' | 'end';
}

/**
 * Drop-down list of checkboxes with "All" / "None". The panel opens under the button, aligned on
 * its left edge (place the control first in its toolbar) or, with `align="end"`, on its right edge
 * (a control at the right of a card header), and closes on Escape or outside click.
 */
export function MultiSelect<T extends string>({ label, options, selected, onChange, align = 'start' }: MultiSelectProps<T>) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const panelId = useId();
  const count = options.filter((o) => selected.has(o.value)).length;

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (root.current !== null && !root.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false);
        button.current?.focus();
      }
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const toggle = (value: T, on: boolean) => {
    const next = new Set(selected);
    if (on) next.add(value);
    else next.delete(value);
    onChange(next);
  };

  return (
    <div ref={root} className="relative min-w-0">
      <button
        ref={button}
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => {
          setOpen((o) => !o);
        }}
        className="inline-flex h-8 max-w-full items-center gap-1.5 rounded-md border border-line bg-surface px-3 text-body hover:bg-subtle"
      >
        <span className="truncate">{label}</span>
        <span className="num text-meta text-muted">
          {count}/{options.length}
        </span>
        <ChevronDown aria-hidden size={16} strokeWidth={1.75} className={cn('shrink-0', open && 'rotate-180')} />
      </button>
      {open && (
        <div
          id={panelId}
          role="group"
          aria-label={label}
          className={cn(
            'absolute top-full z-20 mt-1 flex w-72 max-w-[calc(100vw-2rem)] flex-col gap-1 rounded-lg border border-line bg-surface p-2 shadow-xs',
            align === 'end' ? 'right-0' : 'left-0',
          )}
        >
          <div className="flex gap-1 border-b border-line pb-1">
            <Button
              variant="ghost"
              onClick={() => {
                onChange(new Set(options.map((o) => o.value)));
              }}
            >
              {t('common.all')}
            </Button>
            <Button
              variant="ghost"
              onClick={() => {
                onChange(new Set());
              }}
            >
              {t('common.none')}
            </Button>
          </div>
          <ul className="flex max-h-80 flex-col overflow-y-auto">
            {options.map((o) => (
              <li key={o.value}>
                <label className="flex h-8 cursor-pointer items-center gap-2 rounded px-2 hover:bg-subtle has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-accent">
                  <input
                    type="checkbox"
                    checked={selected.has(o.value)}
                    onChange={(e) => {
                      toggle(o.value, e.target.checked);
                    }}
                    className="size-4 shrink-0 accent-[var(--ns-accent)]"
                  />
                  {o.color !== undefined && (
                    <span aria-hidden className="size-2.5 shrink-0 rounded-sm" style={{ backgroundColor: o.color }} />
                  )}
                  <span className="min-w-0 flex-1 truncate">{o.label}</span>
                  {o.detail !== undefined && <span className="num shrink-0 text-meta text-muted">{o.detail}</span>}
                </label>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
