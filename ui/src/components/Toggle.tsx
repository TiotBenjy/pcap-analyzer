import { cn } from '../lib/cn';
import { formatCount } from '../lib/format';

interface ToggleProps {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  /** Optional item count shown next to the label (filter bars). */
  count?: number;
  disabled?: boolean;
}

/** Accessible switch (role="switch") with label and optional counter. */
export function Toggle({ label, checked, onChange, count, disabled = false }: ToggleProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => {
        onChange(!checked);
      }}
      className={cn(
        'inline-flex h-8 max-w-full items-center gap-2 rounded-md border px-2.5 text-body',
        'disabled:pointer-events-none disabled:opacity-50',
        checked ? 'border-accent bg-accent-soft text-fg' : 'border-line bg-surface text-muted hover:bg-subtle',
      )}
    >
      <span
        aria-hidden
        className={cn(
          'relative h-3.5 w-6 shrink-0 rounded-full transition-colors',
          checked ? 'bg-accent' : 'bg-faint/50',
        )}
      >
        <span
          className={cn(
            'absolute top-0.5 size-2.5 rounded-full bg-white transition-[left]',
            checked ? 'left-3' : 'left-0.5',
          )}
        />
      </span>
      <span className="truncate">{label}</span>
      {count !== undefined && <span className="num text-meta text-muted">{formatCount(count)}</span>}
    </button>
  );
}
