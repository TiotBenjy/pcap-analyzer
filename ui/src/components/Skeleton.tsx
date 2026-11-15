import { cn } from '../lib/cn';

/** Loading placeholder with the final block size, so layouts do not jump. */
export function Skeleton({ className, height }: { className?: string; height?: number }) {
  return (
    <div
      aria-hidden
      // The visual tests wait for every placeholder to be replaced before a capture.
      data-skeleton
      className={cn('animate-pulse rounded-md bg-subtle', className)}
      style={height === undefined ? undefined : { height }}
    />
  );
}
