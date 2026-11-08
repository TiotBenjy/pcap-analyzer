import type { ObjectItem } from '../../api/types/ObjectItem';

const TYPE_LABELS: Record<string, string> = {
  'image/png': 'PNG',
  'image/jpeg': 'JPEG',
  'image/gif': 'GIF',
  'image/webp': 'WebP',
  'image/bmp': 'BMP',
  'image/x-icon': 'ICO',
  'image/svg+xml': 'SVG',
};

/** Short name of a detected image type (`image/png` -> `PNG`). */
export function typeLabel(mime: string): string {
  return TYPE_LABELS[mime] ?? mime.replace(/^image\//, '').toUpperCase();
}

/** Name shown under a tile: last segment of the URL path, else the host, else the digest. */
export function displayName(item: Pick<ObjectItem, 'uri' | 'host' | 'sha256'>): string {
  const path = (item.uri ?? '').split(/[?#]/)[0] ?? '';
  const segment = path.split('/').filter((s) => s !== '').at(-1);
  if (segment !== undefined) {
    try {
      return decodeURIComponent(segment);
    } catch {
      return segment;
    }
  }
  return item.host ?? item.sha256.slice(0, 12);
}

/** `640 x 480`, or `null` when unknown. */
export function dimensions(item: Pick<ObjectItem, 'width' | 'height'>): string | null {
  return item.width === null || item.height === null ? null : `${item.width} \u00d7 ${item.height}`;
}
