import type { ComponentType } from 'react';
import type { OnlineSettings } from '../../../api/types/OnlineSettings';
import { GeoipCheckStatus } from './GeoipCheckStatus';

// Settings > Online: each online feature may show its own content (state, last result, button)
// under the switch of its setting.

export interface OnlineExtensionProps {
  /** Current value of the setting (false while unknown). */
  enabled: boolean;
  /** The server is read-only: nothing may be changed. */
  readOnly: boolean;
}

export interface OnlineExtension {
  /** Unique id (React key). */
  id: string;
  /** Switch under which the component shows. */
  setting: keyof OnlineSettings;
  Component: ComponentType<OnlineExtensionProps>;
}

/**
 * Registration point: one import and one line per feature, sorted by id. Example extensions live
 * in the tests only.
 */
export const ONLINE_EXTENSIONS: readonly OnlineExtension[] = [
  { id: 'geoip', setting: 'geoip_check', Component: GeoipCheckStatus },
];
