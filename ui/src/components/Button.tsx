import type { ButtonHTMLAttributes, Ref } from 'react';
import { cn } from '../lib/cn';

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger';

const VARIANTS: Record<Variant, string> = {
  primary: 'bg-accent text-white hover:opacity-90',
  secondary: 'border border-line bg-surface text-fg hover:bg-subtle',
  ghost: 'text-muted hover:bg-subtle hover:text-fg',
  /** Destructive confirmation only (delete). */
  danger: 'bg-danger text-white hover:opacity-90',
};

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  /** Square icon-only button; requires an aria-label. */
  icon?: boolean;
  ref?: Ref<HTMLButtonElement>;
}

export function Button({ variant = 'secondary', icon = false, className, type = 'button', ...rest }: ButtonProps) {
  return (
    <button
      type={type}
      className={cn(
        'inline-flex h-8 shrink-0 items-center justify-center gap-1.5 rounded-md text-body font-medium',
        'disabled:pointer-events-none disabled:opacity-50',
        icon ? 'w-8' : 'px-3',
        VARIANTS[variant],
        className,
      )}
      {...rest}
    />
  );
}
