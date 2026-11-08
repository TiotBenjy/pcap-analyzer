import { flagUrl } from './flags';

interface FlagProps {
  /** ISO 3166-1 alpha-2 code. */
  country: string;
  className?: string;
}

/** Small decorative flag (the country code is given in text or title by the caller). */
export function Flag({ country, className }: FlagProps) {
  const url = flagUrl(country);
  if (url === null) return null;
  return (
    <img
      src={url}
      alt=""
      aria-hidden
      width={16}
      height={12}
      className={className ?? 'inline-block h-3 w-4 shrink-0 rounded-[2px] object-cover'}
    />
  );
}
