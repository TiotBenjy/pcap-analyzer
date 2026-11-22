import { X } from 'lucide-react';

interface FilterChipProps {
  /** Text of the active filter (host, status, MAC address...), truncated with a tooltip. */
  label: string;
  onRemove: () => void;
  /** Accessible label of the remove button ("Clear the host filter"). */
  removeLabel: string;
}

/** Removable chip of an active filter, 32 px high, in a filter bar. */
export function FilterChip({ label, onRemove, removeLabel }: FilterChipProps) {
  return (
    <span className="inline-flex h-8 max-w-full min-w-0 items-center gap-1 rounded-md border border-accent bg-accent-soft pr-1 pl-2.5">
      <span data-testid="truncatable" title={label} className="min-w-0 truncate">
        {label}
      </span>
      <button
        type="button"
        aria-label={removeLabel}
        title={removeLabel}
        onClick={onRemove}
        className="inline-flex size-6 shrink-0 items-center justify-center rounded text-muted hover:bg-subtle hover:text-fg"
      >
        <X aria-hidden size={14} strokeWidth={1.75} />
      </button>
    </span>
  );
}
