import { useCallback, useSyncExternalStore } from 'react';

/** Live result of a CSS media query (false where `matchMedia` is unavailable). */
export function useMediaQuery(query: string): boolean {
  const subscribe = useCallback(
    (onChange: () => void) => {
      if (typeof window.matchMedia !== 'function') return () => undefined;
      const mq = window.matchMedia(query);
      mq.addEventListener('change', onChange);
      return () => {
        mq.removeEventListener('change', onChange);
      };
    },
    [query],
  );
  const get = () => typeof window.matchMedia === 'function' && window.matchMedia(query).matches;
  return useSyncExternalStore(subscribe, get, get);
}

/** Tailwind `lg` breakpoint. */
export const LG_QUERY = '(min-width: 1024px)';
