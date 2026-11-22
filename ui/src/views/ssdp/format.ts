import type { SsdpDeviceInfo } from '../../api/types/SsdpDeviceInfo';

/** `MediaRenderer:1` for `urn:schemas-upnp-org:device:MediaRenderer:1`, the text itself otherwise. */
export function shortType(deviceType: string): string {
  const at = deviceType.toLowerCase().indexOf(':device:');
  return at < 0 ? deviceType : deviceType.slice(at + ':device:'.length);
}

/** Stable numeric key of a device row (FNV-1a of its UUID and address), kept across searches. */
export function deviceKey(d: SsdpDeviceInfo): number {
  let h = 0x811c9dc5;
  for (const c of `${d.uuid}|${d.address.ip}`) {
    h ^= c.codePointAt(0) ?? 0;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h;
}
