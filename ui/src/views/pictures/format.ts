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

/**
 * Text from the capture, safe to display: control characters and bidirectional overrides or
 * isolates (U+202A-U+202E, U+2066-U+2069, which can disguise an extension) removed.
 */
export function cleanText(text: string): string {
  // eslint-disable-next-line no-control-regex -- removing control characters is the point
  return text.replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '');
}

/** Name shown under a tile: last segment of the URL path, else the host, else the file name. */
export function displayName(item: Pick<ObjectItem, 'uri' | 'host' | 'file_name'>): string {
  const path = (item.uri ?? '').split(/[?#]/)[0] ?? '';
  const segment = path.split('/').filter((s) => s !== '').at(-1);
  let name = segment ?? item.host ?? '';
  if (segment !== undefined) {
    try {
      name = decodeURIComponent(segment);
    } catch {
      name = segment;
    }
  }
  const clean = cleanText(name).trim();
  return clean === '' ? item.file_name : clean;
}

/** `640 x 480`, or `null` when unknown. */
export function dimensions(item: Pick<ObjectItem, 'width' | 'height'>): string | null {
  return item.width === null || item.height === null ? null : `${item.width} \u00d7 ${item.height}`;
}
