import type { ComponentType, ReactNode } from 'react';

// Notices: discreet banners under the application header (Settings > Online, ADR-025). Each
// feature registers one `NoticeProvider` in `providers.ts`; the area shows at most
// `MAX_NOTICES` of them, in registry order, and remembers dismissals on the server.

export interface NoticeAction {
  label: string;
  onClick: () => void;
  /** Main action of the notice (accent button). At most one per notice. */
  primary?: boolean;
  disabled?: boolean;
  /** Reason shown when disabled. */
  title?: string;
}

export interface Notice {
  /**
   * The notice stays hidden once dismissed, until this key changes: for example the month of the
   * GeoIP database offered, or the version number offered. Letters, digits and `. _ - + :`, at
   * most 64 characters (checked by the server).
   */
  dismissKey: string;
  /** One short, factual sentence. */
  message: string;
  /** Optional text below the message (plain text: never HTML from the network). */
  detail?: ReactNode;
  actions?: readonly NoticeAction[];
}

/** Props given by the notice area to each provider component. */
export interface NoticeSlotProps {
  /** Id of the provider (`NoticeProvider.id`). */
  id: string;
  /** The area lets this notice show (reported, not dismissed, within the first `MAX_NOTICES`). */
  visible: boolean;
  /** Reports the dismiss key of the current notice, or `null` when there is nothing to show. */
  report: (dismissKey: string | null) => void;
  /** Hides the notice until its dismiss key changes. */
  dismiss: (dismissKey: string) => void;
}

export interface NoticeProvider {
  /**
   * Stable id, also the key of the dismissal in the server settings: lowercase letters, digits
   * and `- _ .`, starting with a letter or a digit.
   */
  id: string;
  /** Renders `<NoticeSlot slot={props} notice={...} />`, computing the notice with any hooks. */
  Component: ComponentType<NoticeSlotProps>;
}
