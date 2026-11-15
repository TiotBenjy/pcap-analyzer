import { useEffect } from 'react';
import { NoticeBanner } from './NoticeBanner';
import type { Notice, NoticeSlotProps } from './types';

interface NoticeSlotComponentProps {
  slot: NoticeSlotProps;
  /** What to show now, or `null`. */
  notice: Notice | null;
}

/**
 * What a provider renders: reports its notice to the area and shows the banner when the area
 * lets it (not dismissed for this key, within the first `MAX_NOTICES`).
 */
export function NoticeSlot({ slot, notice }: NoticeSlotComponentProps) {
  const { id, report, dismiss, visible } = slot;
  const key = notice?.dismissKey ?? null;
  useEffect(() => {
    report(key);
  }, [report, key]);
  useEffect(
    () => () => {
      report(null);
    },
    [report],
  );
  if (!visible || notice === null) return null;
  return (
    <NoticeBanner
      id={id}
      notice={notice}
      onDismiss={() => {
        dismiss(notice.dismissKey);
      }}
    />
  );
}
