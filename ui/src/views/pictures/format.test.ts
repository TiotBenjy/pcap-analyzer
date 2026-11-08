import { expect, it } from 'vitest';
import { cleanText, dimensions, displayName, typeLabel } from './format';

const base = { uri: null, host: null, file_name: 'object-0123456789ab.png' };

it('names an image after its URL, safely', () => {
  expect(displayName({ ...base, uri: '/a/b/photo%20one.jpg?x=1#f' })).toBe('photo one.jpg');
  expect(displayName({ ...base, uri: '/', host: 'cdn.test' })).toBe('cdn.test');
  expect(displayName({ ...base, uri: '/%E0%A4%A' })).toBe('%E0%A4%A');
  // A right-to-left override hiding the real extension, and control characters.
  expect(displayName({ ...base, uri: '/invoice‮gnp.exe' })).toBe('invoicegnp.exe');
  expect(displayName({ ...base, uri: '/%0A%1B%E2%80%AE' })).toBe('object-0123456789ab.png');
  expect(cleanText('a⁦b⁩c\u0007')).toBe('abc');
});

it('labels types and dimensions', () => {
  expect(typeLabel('image/png')).toBe('PNG');
  expect(typeLabel('image/x-icon')).toBe('ICO');
  expect(typeLabel('image/avif')).toBe('AVIF');
  expect(dimensions({ width: 640, height: 480 })).toBe('640 × 480');
  expect(dimensions({ width: null, height: 480 })).toBeNull();
});
