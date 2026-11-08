import type { AddressCategory } from '../../api/types/AddressCategory';

/** Categories behind the "Private" switch: every address that is not public. */
export const PRIVATE_CATEGORIES: readonly AddressCategory[] = [
  'private',
  'link_local',
  'loopback',
  'cgnat',
  'unspecified',
  'reserved',
  'broadcast',
  'multicast',
];
export const PUBLIC_CATEGORIES: readonly AddressCategory[] = ['public'];

/** Categories sent to the API: `undefined` when both switches are on (no filter). */
export function categoriesOf(showPrivate: boolean, showPublic: boolean): readonly AddressCategory[] | undefined {
  if (showPrivate && showPublic) return undefined;
  return [...(showPrivate ? PRIVATE_CATEGORIES : []), ...(showPublic ? PUBLIC_CATEGORIES : [])];
}
