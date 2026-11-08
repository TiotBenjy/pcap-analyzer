import { useId } from 'react';
import { cn } from '../lib/cn';

interface SegmentedControlProps<T extends string> {
  label: string;
  value: T;
  options: readonly { value: T; label: string }[];
  onChange: (value: T) => void;
  /** Keeps the label for assistive technologies only (compact toolbars). */
  hideLabel?: boolean;
}

/** Mutually exclusive choice rendered as a radio group (keyboard: Tab + arrows via native radios). */
export function SegmentedControl<T extends string>({
  label,
  value,
  options,
  onChange,
  hideLabel = false,
}: SegmentedControlProps<T>) {
  const name = useId();
  return (
    <fieldset className="flex min-w-0 flex-wrap items-center gap-x-4 gap-y-2">
      <legend className={hideLabel ? 'sr-only' : 'float-left mr-4 w-28 shrink-0 text-muted'}>{label}</legend>
      <div className="inline-flex max-w-full flex-wrap rounded-md border border-line p-0.5">
        {options.map((o) => (
          <label
            key={o.value}
            className={cn(
              'relative inline-flex h-7 cursor-pointer items-center rounded px-3 text-body',
              'has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-accent',
              o.value === value ? 'bg-accent-soft font-medium text-accent' : 'text-muted hover:text-fg',
            )}
          >
            <input
              type="radio"
              name={name}
              value={o.value}
              checked={o.value === value}
              onChange={() => {
                onChange(o.value);
              }}
              className="sr-only"
            />
            {o.label}
          </label>
        ))}
      </div>
    </fieldset>
  );
}
