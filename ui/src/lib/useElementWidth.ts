import { useEffect, useState } from 'react';

/** Width of an element, followed with a ResizeObserver (0 before layout). Callback ref: the
 * element appears only once there is something to draw. */
export function useElementWidth(): [(el: HTMLDivElement | null) => void, number] {
  const [el, setEl] = useState<HTMLDivElement | null>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    if (el === null) return;
    const ro = new ResizeObserver((entries) => {
      setWidth(Math.round(entries[0]?.contentRect.width ?? 0));
    });
    ro.observe(el);
    return () => {
      ro.disconnect();
    };
  }, [el]);
  return [setEl, width];
}
