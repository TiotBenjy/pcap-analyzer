import type { ReactNode } from 'react';
import { cn } from '../lib/cn';

export type BadgeTone = 'neutral' | 'accent' | 'success' | 'warning' | 'danger';

const TONES: Record<BadgeTone, string> = {
  neutral: 'bg-subtle text-muted',
  accent: 'bg-accent-soft text-accent',
  success: 'bg-subtle text-success',
  warning: 'bg-subtle text-warning',
  danger: 'bg-subtle text-danger',
};

interface BadgeProps {
  children: ReactNode;
  tone?: BadgeTone;
  className?: string;
  title?: string;
}

/** Counters only get tabular figures: in text labels they would set hyphens in fixed width. */
function isNumeric(children: ReactNode): boolean {
  return typeof children === 'number' || (typeof children === 'string' && /^[\d\s.,\u00a0\u202f]+$/.test(children));
}

/** Small neutral label or counter. Semantic tones color the text only, never large fills. */
export function Badge({ children, tone = 'neutral', className, title }: BadgeProps) {
  return (
    <span
      title={title}
      className={cn(
        'inline-flex h-5 shrink-0 items-center rounded-md px-1.5 text-meta font-medium whitespace-nowrap',
        isNumeric(children) && 'num',
        TONES[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}
