import { cn } from '../lib/cn';

/** Loading placeholder with the final block size, so layouts do not jump. */
export function Skeleton({ className, height }: { className?: string; height?: number }) {
  return (
    <div
      aria-hidden
      className={cn('animate-pulse rounded-md bg-subtle', className)}
      style={height === undefined ? undefined : { height }}
    />
  );
}
